//! Capital Starvation Detector
//!
//! The spec requires a "hot-path check: if one exchange balance hits $0,
//! triggers rebalance request". This module monitors per-exchange stablecoin
//! balances and fires rebalance events when capital is depleted.
//!
//! Spec reference: "Capital Starvation Detection — Hot-path check: if one
//! exchange balance hits $0, triggers rebalance request"

use rust_decimal::Decimal;
use std::sync::Arc;

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
/// Tracks starvation on a per-exchange basis using a `HashSet` so that
/// a single exchange recovering does not mask starvation on other exchanges.
pub struct CapitalStarvationDetector {
    /// Minimum balance threshold below which starvation is declared.
    min_threshold: Decimal,
    /// Set of exchange IDs currently in a starved state.
    starved_exchanges: std::sync::Mutex<std::collections::HashSet<usize>>,
    /// Last detected starvation event.
    last_event: std::sync::Mutex<Option<StarvationEvent>>,
    /// Optional callback invoked when starvation is *newly* detected for an
    /// exchange (i.e. on transition from non-starved → starved).
    /// Receives the exchange ID as a `usize` to prevent truncation.
    starvation_callback: Option<Arc<dyn Fn(usize) + Send + Sync>>,
}

impl CapitalStarvationDetector {
    /// Creates a new starvation detector.
    ///
    /// The `threshold` parameter represents the minimum USDT balance on any
    /// exchange before a starvation condition is triggered. This should be
    /// set to at least the minimum order size of the configured exchanges
    /// to avoid false positives when an exchange legitimately has low
    /// capital for its assigned pairs.
    pub fn new(min_threshold: Decimal) -> Self {
        Self {
            min_threshold,
            starved_exchanges: std::sync::Mutex::new(std::collections::HashSet::new()),
            last_event: std::sync::Mutex::new(None),
            starvation_callback: None,
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

            // H-5: Track per-exchange starvation state.
            let was_starved = {
                let mut starved_guard = self.starved_exchanges.lock().unwrap_or_else(|e| e.into_inner());
                let already = starved_guard.contains(&exchange_id);
                starved_guard.insert(exchange_id);
                already
            };

            {
                let mut guard = self.last_event.lock().unwrap_or_else(|e| e.into_inner());
                *guard = Some(event.clone());
            } // Lock dropped before callback invocation.

            tracing::warn!(
                exchange_id,
                token_id,
                balance = %current_balance,
                threshold = %self.min_threshold,
                "CAPITAL STARVATION detected \u{2014} rebalance required"
            );

            // M-8: Only fire callback on state transition (non-starved → starved).
            if !was_starved {
                if let Some(ref cb) = self.starvation_callback {
                    cb(exchange_id);
                }
            }

            return Some(event);
        }

        None
    }

    /// Returns `true` if any exchange is currently starved.
    #[inline]
    pub fn is_starved(&self) -> bool {
        let guard = self.starved_exchanges.lock().unwrap_or_else(|e| e.into_inner());
        !guard.is_empty()
    }

    /// Clears starvation for a specific exchange, but only if the verified
    /// balance exceeds the minimum threshold (M-9). Returns `true` if the
    /// exchange was successfully cleared, `false` if the balance is still
    /// insufficient.
    pub fn clear_starvation(&self, exchange_id: usize, verified_balance: Decimal) -> bool {
        if verified_balance <= self.min_threshold {
            return false;
        }
        let mut guard = self.starved_exchanges.lock().unwrap_or_else(|e| e.into_inner());
        guard.remove(&exchange_id);
        if guard.is_empty() {
            *self.last_event.lock().unwrap_or_else(|e| e.into_inner()) = None;
            tracing::info!("Capital starvation cleared for exchange {}", exchange_id);
        } else {
            tracing::info!(
                "Capital starvation cleared for exchange {} ({} exchanges still starved)",
                exchange_id,
                guard.len()
            );
        }
        true
    }

    /// Returns the last starvation event, if any.
    pub fn last_event(&self) -> Option<StarvationEvent> {
        self.last_event.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }

    /// Registers a callback that is invoked whenever starvation is *newly*
    /// detected for an exchange. The callback receives the exchange ID as `usize`.
    /// This allows the caller to wire starvation detection to the rebalancer.
    pub fn set_starvation_callback(&mut self, callback: Arc<dyn Fn(usize) + Send + Sync>) {
        self.starvation_callback = Some(callback);
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
        det.clear_starvation(0, dec!(100.0));
        assert!(!det.is_starved());
    }

    #[test]
    fn test_custom_threshold() {
        let det = CapitalStarvationDetector::new(dec!(0.01)); // $0.01 threshold
        assert!(!det.is_starved());
    }
}