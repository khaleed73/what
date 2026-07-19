//! Rebalance Matrix Engine — Monitors balance drift and computes hedged rebalance actions.
//!
//! This module detects when capital distribution across exchanges becomes imbalanced
//! beyond a configurable threshold, and computes the optimal rebalancing action
//! (which exchange to transfer from/to, how much, and the expected cost).

use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU64, AtomicU8, Ordering};
use std::sync::Mutex;
use rust_decimal::prelude::*;
use rust_decimal_macros::dec;

/// System state machine for rebalancing.
pub const STATE_BALANCED: u8 = 0;
pub const STATE_IMBALANCED: u8 = 1;
pub const STATE_REBALANCING: u8 = 2;
pub const STATE_ERROR: u8 = 3;

/// Account inventory snapshot for two exchanges.
#[derive(Debug, Clone)]
pub struct AccountInventory {
    pub stable_balance_x: Decimal, // Exchange X USDT balance
    pub stable_balance_y: Decimal, // Exchange Y USDT balance,
}

impl AccountInventory {
    pub fn total_stable(&self) -> Decimal {
        self.stable_balance_x + self.stable_balance_y
    }

    pub fn ratio_x(&self) -> Decimal {
        let total = self.total_stable();
        if total > Decimal::ZERO {
            self.stable_balance_x / total
        } else {
            Decimal::ZERO
        }
    }

    pub fn ratio_y(&self) -> Decimal {
        let total = self.total_stable();
        if total > Decimal::ZERO {
            Decimal::ONE - (self.stable_balance_x / total)
        } else {
            Decimal::ZERO
        }
    }
}

/// Result of a rebalance computation.
#[derive(Debug, Clone)]
pub struct RebalanceAction {
    /// Amount of stablecoin to transfer from source to destination.
    pub transfer_amount: Decimal,
    /// Source exchange ID.
    pub from_exchange: u16,
    /// Destination exchange ID.
    pub to_exchange: u16,
    /// Estimated transfer fee in USD.
    pub estimated_fee: Decimal,
    /// The imbalance ratio that triggered rebalancing.
    pub current_imbalance_ratio: Decimal,
    /// The target ratio after rebalancing (should be close to 0.5).
    pub target_ratio: Decimal,
}

/// Returns the current Unix epoch in seconds (cheap, no allocation).
fn now_epoch_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Cheap FNV-1a hash over the serialised bytes of two `Decimal` values.
/// No heap allocation — `Decimal::serialize()` returns a fixed `[u8; 16]`.
fn hash_balances(bx: &Decimal, by: &Decimal) -> u64 {
    let bx_b = bx.serialize();
    let by_b = by.serialize();
    let mut h: u64 = 0xcbf29ce484222325; // FNV-1a offset basis
    for &b in &bx_b {
        h ^= b as u64;
        h = h.wrapping_mul(0x100000001b3);
    }
    for &b in &by_b {
        h ^= b as u64;
        h = h.wrapping_mul(0x100000001b3);
    }
    h
}

/// Hash balances **and** exchange IDs — the full input key for compute_hedged_rebalance_execution.
fn hash_compute_input(bx: &Decimal, by: &Decimal, from: u16, to: u16) -> u64 {
    let mut h = hash_balances(bx, by);
    h ^= (from as u64) << 32;
    h ^= to as u64;
    h
}

/// Rebalance Matrix Engine — detects balance drift and computes optimal rebalancing.
pub struct RebalanceMatrixEngine {
    /// Current system state (balanced / imbalanced / rebalancing / error).
    current_system_state: AtomicU8,
    /// Maximum allowed imbalance ratio (e.g., 0.70 means 70/30 split triggers rebalance).
    /// A perfectly balanced split is 0.50/0.50.
    max_allowed_imbalance_ratio: Decimal,
    /// Execution fee as a decimal (e.g., 0.002 = 0.2%).
    execution_fee: Decimal,
    /// Minimum transfer amount to justify the rebalancing cost.
    min_transfer_amount: Decimal,

    // --- Per-tick caches (O(1) fast-path, avoids O(n³) recomputation) ---
    /// FNV-1a hash of the balances that produced the cached audit result.
    last_audit_hash: AtomicU64,
    /// Cached boolean result of the last `audit_balance_drift` call.
    last_audit_result: AtomicBool,
    /// FNV-1a hash of the full input (balances + exchange IDs) for the cached compute result.
    last_compute_hash: AtomicU64,
    /// Cached `RebalanceAction` from the last `compute_hedged_rebalance_execution` call.
    last_compute_result: Mutex<Option<RebalanceAction>>,
    /// Unix-epoch seconds of the last actual recomputation.
    last_compute_time: AtomicI64,
    /// Minimum wall-clock seconds between successive rebalance computations.
    min_rebalance_interval_secs: i64,
}

impl RebalanceMatrixEngine {
    /// Default minimum interval between rebalance computations (seconds).
    pub const DEFAULT_MIN_INTERVAL_SECS: i64 = 5;

    pub fn new(
        imbalance_threshold: Decimal,
        fee: Decimal,
        min_transfer: Decimal,
    ) -> Self {
        Self {
            current_system_state: AtomicU8::new(STATE_BALANCED),
            max_allowed_imbalance_ratio: imbalance_threshold,
            execution_fee: fee,
            min_transfer_amount: min_transfer,
            // Cache fields — initialised to "empty" sentinels.
            last_audit_hash: AtomicU64::new(0),
            last_audit_result: AtomicBool::new(false),
            last_compute_hash: AtomicU64::new(0),
            last_compute_result: Mutex::new(None),
            last_compute_time: AtomicI64::new(0),
            min_rebalance_interval_secs: Self::DEFAULT_MIN_INTERVAL_SECS,
        }
    }

    /// Builder-style setter for the minimum recomputation interval.
    pub fn with_min_interval(mut self, secs: i64) -> Self {
        self.min_rebalance_interval_secs = secs;
        self
    }

    /// Returns the current system state.
    pub fn state(&self) -> u8 {
        self.current_system_state.load(Ordering::Acquire)
    }

    /// Sets the system state.
    pub fn set_state(&self, new_state: u8) {
        self.current_system_state.store(new_state, Ordering::Release);
    }

    /// Audits the balance drift between two exchanges.
    ///
    /// Returns true if the imbalance exceeds the threshold and rebalancing is needed.
    /// Uses a cheap FNV-1a hash of the input balances to skip recomputation when
    /// the inventory has not changed since the last call (O(1) fast-path).
    pub fn audit_balance_drift(&self, inventory: &AccountInventory) -> bool {
        let h = hash_balances(&inventory.stable_balance_x, &inventory.stable_balance_y);
        let prev_hash = self.last_audit_hash.load(Ordering::Acquire);

        // Fast-path: inputs unchanged → return cached result (no division, no state write).
        if h == prev_hash {
            return self.last_audit_result.load(Ordering::Acquire);
        }

        // Slow-path: compute from scratch.
        let ratio_x = inventory.ratio_x();
        let ratio_y = inventory.ratio_y();

        let needs_rebalance = ratio_x > self.max_allowed_imbalance_ratio
            || ratio_y > self.max_allowed_imbalance_ratio;

        if needs_rebalance {
            self.set_state(STATE_IMBALANCED);
        } else {
            self.set_state(STATE_BALANCED);
        }

        self.last_audit_hash.store(h, Ordering::Release);
        self.last_audit_result.store(needs_rebalance, Ordering::Release);

        needs_rebalance
    }

    /// Computes a hedged rebalance execution plan.
    ///
    /// # Algorithm
    /// 1. Determine which exchange is over-weighted (source)
    /// 2. Calculate the transfer amount needed to restore 50/50 balance
    /// 3. Deduct the transfer fee to ensure net transfer achieves the target
    /// 4. Verify the transfer is large enough to justify the fee cost
    ///
    /// # Caching
    /// Two cheap gates prevent redundant work on every price tick:
    /// * **Hash gate** — if the input balances (and exchange IDs) have not changed,
    ///   the cached `RebalanceAction` is returned immediately (O(1)).
    /// * **Time gate** — even when inputs change, a minimum wall-clock interval
    ///   ([`Self::DEFAULT_MIN_INTERVAL_SECS`]) is enforced so the expensive
    ///   division-heavy path runs at most once per interval.
    ///
    /// # Returns
    /// * `Some(RebalanceAction)` - Action to take
    /// * `None` - Rebalancing not needed or not cost-effective
    pub fn compute_hedged_rebalance_execution(
        &self,
        inventory: &AccountInventory,
        from_exchange_id: u16,
        to_exchange_id: u16,
    ) -> Option<RebalanceAction> {
        let h = hash_compute_input(
            &inventory.stable_balance_x,
            &inventory.stable_balance_y,
            from_exchange_id,
            to_exchange_id,
        );
        let now = now_epoch_secs();
        let prev_hash = self.last_compute_hash.load(Ordering::Acquire);
        let last_time = self.last_compute_time.load(Ordering::Acquire);

        // C-18 fix: Check hash gate first, then time gate.
        if h == prev_hash {
            return self.last_compute_result.lock().unwrap_or_else(|e| e.into_inner()).clone();
        }
        if now.saturating_sub(last_time) < self.min_rebalance_interval_secs {
            return self.last_compute_result.lock().unwrap_or_else(|e| e.into_inner()).clone();
        }

        // --- Slow-path: full recomputation ---
        let result = self.do_compute(inventory, from_exchange_id, to_exchange_id);

        // Always update cache — including `None` so identical no-op inputs
        // hit the fast-path on the next tick instead of re-entering here.
        self.last_compute_hash.store(h, Ordering::Release);
        self.last_compute_time.store(now, Ordering::Release);
        {
            let mut cache = self.last_compute_result.lock().unwrap_or_else(|e| e.into_inner());
            *cache = result.clone();
        }

        result
    }

    /// Inner computation — separated so the public method can wrap it with caching.
    fn do_compute(
        &self,
        inventory: &AccountInventory,
        from_exchange_id: u16,
        to_exchange_id: u16,
    ) -> Option<RebalanceAction> {
        let ratio_x = inventory.ratio_x();
        let ratio_y = inventory.ratio_y();

        // Determine source (over-weighted) and destination (under-weighted).
        // NOTE: When ratio_x == ratio_y (perfectly balanced), the else branch
        // is taken, which swaps from_id/to_id relative to the caller's
        // parameters. This is intentional — the caller passes the "preferred"
        // direction, but equal ratios mean either direction is equivalent.
        let (source_balance, dest_balance, from_id, to_id) = if ratio_x > ratio_y {
            (inventory.stable_balance_x, inventory.stable_balance_y, from_exchange_id, to_exchange_id)
        } else {
            (inventory.stable_balance_y, inventory.stable_balance_x, to_exchange_id, from_exchange_id)
        };

        let total = inventory.total_stable();
        if total <= Decimal::ZERO {
            return None;
        }

        // Target: 50/50 split
        let target_each = total / Decimal::TWO;

        // C-9 fix: Correct transfer fee formula — use (1 - fee) not (1 + fee).
        let raw_transfer = (source_balance - target_each) / (Decimal::ONE - self.execution_fee);
        // Round down to be conservative
        let transfer_amount = raw_transfer.floor();

        if transfer_amount <= Decimal::ZERO {
            return None;
        }

        // Check minimum transfer amount
        if transfer_amount < self.min_transfer_amount {
            return None;
        }

        // Verify the transfer won't over-correct.
        // M-19: Use saturating arithmetic to prevent overflow on extreme values.
        let fee = (transfer_amount * self.execution_fee).min(transfer_amount);
        let net_transfer = transfer_amount.saturating_sub(fee);
        let new_source = if transfer_amount >= source_balance {
            Decimal::ZERO
        } else {
            source_balance.saturating_sub(transfer_amount)
        };
        let new_dest = dest_balance.saturating_add(net_transfer);

        if new_source < Decimal::ZERO {
            return None;
        }

        let new_ratio_source = new_source / (new_source + new_dest);
        if (new_ratio_source - Decimal::from(5) / Decimal::from(10)).abs() > dec!(0.05) {
            // If we'd be more than 5% off from 50/50, skip
            return None;
        }

        let current_imbalance = ratio_x.max(ratio_y);

        Some(RebalanceAction {
            transfer_amount,
            from_exchange: from_id,
            to_exchange: to_id,
            estimated_fee: fee,
            current_imbalance_ratio: current_imbalance,
            target_ratio: Decimal::from(5) / Decimal::from(10),
        })
    }

    /// Convenience: check if system is in rebalancing state.
    pub fn is_rebalancing(&self) -> bool {
        self.state() == STATE_REBALANCING
    }

    /// Convenience: check if system is imbalanced.
    pub fn is_imbalanced(&self) -> bool {
        self.state() == STATE_IMBALANCED
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rust_decimal_macros::dec;

    fn make_engine() -> RebalanceMatrixEngine {
        RebalanceMatrixEngine::new(dec!(0.70), dec!(0.002), dec!(5.0))
    }

    #[test]
    fn test_balanced_no_rebalance_needed() {
        let engine = make_engine();
        let inv = AccountInventory {
            stable_balance_x: dec!(5000.0),
            stable_balance_y: dec!(5000.0),
        };
        assert!(!engine.audit_balance_drift(&inv));
        assert_eq!(engine.state(), STATE_BALANCED);
    }

    #[test]
    fn test_imbalanced_triggers_rebalance() {
        let engine = make_engine();
        let inv = AccountInventory {
            stable_balance_x: dec!(8000.0), // 80/20 — exceeds 70% threshold
            stable_balance_y: dec!(2000.0),
        };
        assert!(engine.audit_balance_drift(&inv));
        assert_eq!(engine.state(), STATE_IMBALANCED);
    }

    #[test]
    fn test_compute_rebalance_action() {
        let engine = make_engine();
        let inv = AccountInventory {
            stable_balance_x: dec!(8000.0),
            stable_balance_y: dec!(2000.0),
        };
        let action = engine.compute_hedged_rebalance_execution(&inv, 0, 1);
        assert!(action.is_some());
        let a = action.unwrap();
        assert!(a.transfer_amount > Decimal::ZERO);
        assert_eq!(a.from_exchange, 0); // X is over-weighted
        assert_eq!(a.to_exchange, 1);
        assert!(a.estimated_fee > Decimal::ZERO);
    }

    #[test]
    fn test_rebalance_below_min_transfer() {
        // Set high min transfer
        let engine = RebalanceMatrixEngine::new(dec!(0.70), dec!(0.002), dec!(10000.0));
        let inv = AccountInventory {
            stable_balance_x: dec!(600.0),
            stable_balance_y: dec!(400.0),
        };
        // Only $50 would need to move — below $10000 minimum
        // But also, 60/40 is below 70% threshold, so audit won't trigger
        assert!(!engine.audit_balance_drift(&inv));
    }

    #[test]
    fn test_total_stable() {
        let inv = AccountInventory {
            stable_balance_x: dec!(3000.0),
            stable_balance_y: dec!(7000.0),
        };
        assert_eq!(inv.total_stable(), dec!(10000.0));
    }

    #[test]
    fn test_ratios() {
        let inv = AccountInventory {
            stable_balance_x: dec!(7500.0),
            stable_balance_y: dec!(2500.0),
        };
        assert_eq!(inv.ratio_x(), dec!(0.75));
        assert_eq!(inv.ratio_y(), dec!(0.25));
    }

    #[test]
    fn test_zero_total() {
        let inv = AccountInventory {
            stable_balance_x: Decimal::ZERO,
            stable_balance_y: Decimal::ZERO,
        };
        // C-14 fix: ratio_y returns 0 when total is 0, not 1.
        assert_eq!(inv.ratio_x(), Decimal::ZERO);
        assert_eq!(inv.ratio_y(), Decimal::ZERO);
    }

    #[test]
    fn test_set_state() {
        let engine = make_engine();
        engine.set_state(STATE_REBALANCING);
        assert!(engine.is_rebalancing());
        engine.set_state(STATE_BALANCED);
        assert!(!engine.is_rebalancing());
    }

    #[test]
    fn test_rebalance_action_fee_deduction() {
        let engine = RebalanceMatrixEngine::new(dec!(0.60), dec!(0.01), dec!(1.0)); // 1% fee
        let inv = AccountInventory {
            stable_balance_x: dec!(9000.0), // 90/10
            stable_balance_y: dec!(1000.0),
        };
        let action = engine.compute_hedged_rebalance_execution(&inv, 0, 1).unwrap();
        // Fee should be 1% of transfer
        let expected_fee = action.transfer_amount * dec!(0.01);
        assert!((action.estimated_fee - expected_fee).abs() < dec!(0.01));
    }
}