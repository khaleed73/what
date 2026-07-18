//! Size Slicer / Anti-Market Impaction Engine
//!
//! The spec requires breaking large orders into sub-slices (e.g. $1,000
//! chunks) to avoid moving thin order books. This module implements the
//! `SizeSlicer` that splits a single large order into multiple smaller
//! orders with configurable maximum slice notional.
//!
//! Spec reference: "Size Slicing / Anti-Market Impaction Engine — Breaks
//! large orders into sub-slices (e.g., $1,000 chunks) to avoid moving
//! thin order books"

use rust_decimal::prelude::ToPrimitive;
use rust_decimal::Decimal;
use rust_decimal_macros::dec;

/// Default maximum notional per slice in USD.
const DEFAULT_MAX_SLICE_USD: Decimal = dec!(1000.0);

/// Default minimum notional per slice (below this, don't slice further).
const DEFAULT_MIN_SLICE_USD: Decimal = dec!(5.0);

/// A single order slice.
#[derive(Debug, Clone, PartialEq)]
pub struct OrderSlice {
    /// Slice index (0-based).
    pub index: usize,
    /// Quantity for this slice.
    pub quantity: Decimal,
    /// Price per unit.
    pub price: Decimal,
    /// Notional value (quantity * price).
    pub notional: Decimal,
    /// Total number of slices.
    pub total_slices: usize,
}

/// Splits large orders into smaller chunks to prevent market impact.
///
/// # Algorithm
/// 1. Compute total notional = `quantity * price`
/// 2. If notional <= `max_slice_usd`, return single slice
/// 3. Otherwise, divide into ceiling(notional / max_slice_usd) slices
/// 4. Distribute remainder across first N slices using integer division
pub struct SizeSlicer {
    /// Maximum notional per slice.
    max_slice_usd: Decimal,
    /// Minimum notional per slice (won't create slices smaller than this).
    min_slice_usd: Decimal,
}

impl SizeSlicer {
    /// Creates a slicer with default settings ($1000 max, $5 min).
    pub fn new() -> Self {
        Self {
            max_slice_usd: DEFAULT_MAX_SLICE_USD,
            min_slice_usd: DEFAULT_MIN_SLICE_USD,
        }
    }

    /// Creates a slicer with custom settings.
    pub fn with_limits(max_slice_usd: Decimal, min_slice_usd: Decimal) -> Self {
        Self {
            max_slice_usd,
            min_slice_usd,
        }
    }

    /// Splits an order into slices.
    ///
    /// # Arguments
    /// * `quantity` — Total order quantity
    /// * `price` — Price per unit
    ///
    /// # Returns
    /// A vector of `OrderSlice` structs. If the order is small enough,
    /// returns a single slice.
    #[inline]
    pub fn slice_order(&self, quantity: Decimal, price: Decimal) -> Vec<OrderSlice> {
        if quantity <= Decimal::ZERO || price <= Decimal::ZERO {
            return vec![];
        }

        if self.max_slice_usd == Decimal::ZERO {
            return Vec::new();
        }

        let total_notional = quantity * price;

        // Small order — no slicing needed.
        if total_notional <= self.max_slice_usd {
            return vec![OrderSlice {
                index: 0,
                quantity,
                price,
                notional: total_notional,
                total_slices: 1,
            }];
        }

        // Calculate number of slices.
        let num_slices_f = total_notional / self.max_slice_usd;
        let num_slices = match num_slices_f.ceil().to_u64() {
            Some(n) => n as usize,
            None => {
                tracing::warn!(
                    total_notional = %total_notional,
                    max_slice = %self.max_slice_usd,
                    "size_slicer: num_slices overflow, falling back to 1"
                );
                1usize
            }
        };
        let num_slices = num_slices.max(1);

        // Per-slice quantity (evenly distributed).
        let base_qty = quantity / Decimal::from(num_slices);
        let remainder_units = (quantity - base_qty * Decimal::from(num_slices)).to_u64().unwrap_or(0) as usize;

        let mut slices = Vec::with_capacity(num_slices);
        let mut allocated = Decimal::ZERO;
        let mut merged_qty = Decimal::ZERO;

        for i in 0..num_slices {
            // Distribute one unit of remainder across first N slices.
            let extra = if i < remainder_units {
                Decimal::ONE
            } else {
                Decimal::ZERO
            };

            let slice_qty = base_qty + extra + merged_qty;
            merged_qty = Decimal::ZERO; // merged qty applied to this slice

            // Don't create slices below minimum notional (except the last one).
            let slice_notional = slice_qty * price;
            if slice_notional < self.min_slice_usd && i < num_slices - 1 {
                // Merge into next slice — accumulate the quantity rather than losing it.
                merged_qty = slice_qty;
                continue;
            }

            slices.push(OrderSlice {
                index: slices.len(), // Re-index after potential merges
                quantity: slice_qty,
                price,
                notional: slice_notional,
                total_slices: 0, // Will be set after the loop
            });

            allocated += slice_qty;
        }

        // If all slices were merged below min, just create one slice.
        if slices.is_empty() {
            slices.push(OrderSlice {
                index: 0,
                quantity,
                price,
                notional: total_notional,
                total_slices: 1,
            });
        } else {
            // Fix total_slices to reflect actual count after merges.
            let actual_count = slices.len();
            for s in slices.iter_mut() {
                s.total_slices = actual_count;
            }
        }

        slices
    }

    /// Returns the max slice notional.
    pub fn max_slice_usd(&self) -> Decimal {
        self.max_slice_usd
    }

    /// Returns the min slice notional.
    pub fn min_slice_usd(&self) -> Decimal {
        self.min_slice_usd
    }
}

impl Default for SizeSlicer {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use rust_decimal_macros::dec;

    #[test]
    fn test_small_order_no_slice() {
        let slicer = SizeSlicer::new();
        let slices = slicer.slice_order(dec!(0.5), dec!(100)); // $50 total
        assert_eq!(slices.len(), 1);
        assert_eq!(slices[0].quantity, dec!(0.5));
        assert_eq!(slices[0].notional, dec!(50));
    }

    #[test]
    fn test_large_order_sliced() {
        let slicer = SizeSlicer::new();
        // $5000 total at $100/unit → 5 slices of $1000 each
        let slices = slicer.slice_order(dec!(50), dec!(100));
        assert!(slices.len() >= 5);
        assert!(slices.iter().all(|s| s.notional <= dec!(1000.1)));
    }

    #[test]
    fn test_exact_boundary() {
        let slicer = SizeSlicer::new();
        let slices = slicer.slice_order(dec!(10), dec!(100)); // Exactly $1000
        assert_eq!(slices.len(), 1);
    }

    #[test]
    fn test_just_over_boundary() {
        let slicer = SizeSlicer::new();
        let slices = slicer.slice_order(dec!(10.01), dec!(100)); // $1001
        assert!(slices.len() >= 2);
    }

    #[test]
    fn test_zero_quantity() {
        let slicer = SizeSlicer::new();
        let slices = slicer.slice_order(dec!(0), dec!(100));
        assert!(slices.is_empty());
    }

    #[test]
    fn test_custom_max_slice() {
        let slicer = SizeSlicer::with_limits(dec!(2500), dec!(5));
        let slices = slicer.slice_order(dec!(100), dec!(100)); // $10000 → 4 slices
        assert_eq!(slices.len(), 4);
    }

    #[test]
    fn test_slices_sum_to_original() {
        let slicer = SizeSlicer::new();
        let orig_qty = dec!(33.33);
        let price = dec!(150);
        let slices = slicer.slice_order(orig_qty, price);
        let total: Decimal = slices.iter().map(|s| s.quantity).sum();
        assert!((total - orig_qty).abs() < dec!(0.001));
    }
}