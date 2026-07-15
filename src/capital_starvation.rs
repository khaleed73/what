//! Capital Starvation Detector
//!
//! The spec requires a "hot-path check: if one exchange balance hits $0,
//! triggers rebalance request". This module monitors per-exchange stablecoin
//! balances and fires rebalance events when capital is depleted.
//!
//! Spec reference: "Capital Starvation Detection — Hot-path check: if one
//! exchange balance hits $0, triggers rebalance request"

use rust_decimal::Decimal;
use std::sync::atomic::{AtomicBool, Ordering};

/// A detected starvation event.
#[derive(Debug, Clone)]
pub struct StarvationEvent {
    /// The exchange ID that has run out of capital.
    pub exchange_id: usize,
    /// The token ID that is depleted.
    pub token_id: usize,
    /// Current balance (likely 0 or near-0).
    pub current_balance: Decimal,
    /// The minimum balance threshold that triggered the event.
    pub min_threshold: Decimal,
}

/// Detects when an exchange runs out of capital for a specific token.
///
/// This is a fast, lock-free check designed for the hot path.
/// It uses a simple Decimal comparison rather than requiring a specific
/// allocator type, making it universally composable.
pub struct CapitalStarvationDetector {
    /// Minimum balance threshold below which starvation is declared.
    min_threshold: Decimal,
    /// Whether starvation has been detected (any exchange).
    is_starved: AtomicBool,
    /// Last detected starvation event.
    last_event: std::sync::Mutex<Option<StarvationEvent>>,
}

impl CapitalStarvationDetector {
    /// Creates a new detector with the given minimum balance threshold.
    ///
    /// When any exchange balance falls below this value, starvation is declared.
    pub fn new(min_threshold: Decimal) -> Self {
        Self {
            min_threshold,
            is_starved: AtomicBool::new(false),
            last_event: std::sync::Mutex::new(None),
        }
    }

    /// Creates a detector with a default $10 minimum threshold.
    pub fn with_defaults() -> Self {
        Self::new(Decimal::TEN)
    }

    /// Hot-path check: evaluates whether a specific balance is starved.
    ///
    /// This is a standalone check that works with any balance source.
    /// Returns `Some(StarvationEvent)` if starvation is detected, `None` otherwise.
    #[inline]
    pub fn check_balance(
        &self,
        exchange_id: usize,
        token_id: usize,
        current_balance: Decimal,
    ) -> Option<StarvationEvent> {
        if current_balance <= self.min_threshold {
            let event = StarvationEvent {
                exchange_id,
                token_id,
                current_balance,
                min_threshold: self.min_threshold,
            };

            self.is_starved.store(true, Ordering::SeqCst);
            *self.last_event.lock().unwrap() = Some(event.clone());

            tracing::warn!(
                exchange_id,
                token_id,
                balance = %current_balance,
                threshold = %self.min_threshold,
                "CAPITAL STARVATION detected — rebalance required"
            );

            return Some(event);
        }

        None
    }

    /// Returns `true` if any exchange is currently starved.
    #[inline(always)]
    pub fn is_starved(&self) -> bool {
        self.is_starved.load(Ordering::SeqCst)
    }

    /// Clears the starvation flag (e.g. after rebalance completes).
    pub fn clear_starvation(&self) {
        self.is_starved.store(false, Ordering::SeqCst);
        *self.last_event.lock().unwrap() = None;
        tracing::info!("Capital starvation cleared");
    }

    /// Returns the last starvation event, if any.
    pub fn last_event(&self) -> Option<StarvationEvent> {
        self.last_event.lock().unwrap().clone()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use rust_decimal_macros::dec;

    // We can't easily test with LocalCapitalAllocator in unit tests
    // since it requires specific construction. Instead we test the
    // starvation logic directly.

    #[test]
    fn test_new_detector() {
        let det = CapitalStarvationDetector::with_defaults();
        assert!(!det.is_starved());
        assert!(det.last_event().is_none());
    }

    #[test]
    fn test_clear_starvation() {
        let det = CapitalStarvationDetector::with_defaults();
        // Trigger starvation first.
        let _ = det.check_balance(0, 0, Decimal::ZERO);
        assert!(det.is_starved());
        det.clear_starvation();
        assert!(!det.is_starved());
    }

    #[test]
    fn test_custom_threshold() {
        let det = CapitalStarvationDetector::new(dec!(0.01)); // $0.01 threshold
        assert!(!det.is_starved());
    }
}