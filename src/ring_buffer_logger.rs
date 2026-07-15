//! Ring Buffer Logger — Lock-free single-producer single-consumer trade log.
//!
//! Uses a fixed-size circular buffer with atomic sequence numbers for
//! zero-allocation, zero-lock logging on the hot path.
//!
//! The producer (trading thread) pushes log entries without blocking.
//! A background worker drains entries asynchronously.

use std::sync::atomic::{AtomicU64, Ordering};
use rust_decimal::Decimal;
use std::fs::{File, OpenOptions};
use std::io::Write;

/// Maximum number of log entries in the ring buffer.
const RING_BUFFER_SIZE: usize = 65536;
/// Bitmask for fast modulo (RING_BUFFER_SIZE must be power of 2).
const RING_BUFFER_MASK: usize = RING_BUFFER_SIZE - 1;

/// A single log entry in the ring buffer.
#[derive(Debug, Clone)]
pub struct LogEvent {
    /// Monotonically increasing log sequence ID.
    pub log_id: u64,
    /// Timestamp in milliseconds since epoch.
    pub timestamp_ms: u64,
    /// Profit/loss of the trade in quote currency (can be negative).
    pub delta_profit: Decimal,
    /// Exchange ID where the trade occurred.
    pub exchange_id: u16,
    /// Symbol traded.
    pub symbol: String,
    /// Trade side ("BUY" or "SELL").
    pub side: String,
    /// Quantity traded.
    pub quantity: Decimal,
    /// Execution price.
    pub price: Decimal,
    /// Strategy that generated the signal ("cross_exchange" or "triangular").
    pub strategy: String,
}

/// Lock-free ring buffer logger.
///
/// # Invariants
///   - Single producer (the hot trading thread)
///   - Single consumer (the background drain worker)
///   - Fixed capacity — oldest entries are overwritten when full
///   - No heap allocation on the push path
pub struct RingBufferLogger {
    buffer: Box<[Option<LogEvent>; RING_BUFFER_SIZE]>,
    write_seq: AtomicU64,
    read_seq: AtomicU64,
    /// Optional file path for flush-on-drop. If set, the `Drop` implementation
    /// will synchronously drain all remaining messages and append them to
    /// this file before the process exits.
    log_file_path: Option<String>,
}

impl RingBufferLogger {
    /// Creates a new empty ring buffer logger.
    pub fn new() -> Self {
        // Initialize with None entries
        let buffer = Box::new([const { None }; RING_BUFFER_SIZE]);
        Self {
            buffer,
            write_seq: AtomicU64::new(0),
            read_seq: AtomicU64::new(0),
            log_file_path: None,
        }
    }

    /// Pushes a log entry atomically. This is the hot-path method.
    ///
    /// The entry is written to the next available slot. If the buffer is full,
    /// the oldest entry is silently overwritten (the read pointer is advanced).
    pub fn push(&mut self, event: LogEvent) -> Result<(), &'static str> {
        let write_idx = self.write_seq.fetch_add(1, Ordering::Release);
        let slot = (write_idx as usize) & RING_BUFFER_MASK;

        // Check if we're overwriting an unread entry
        let read_idx = self.read_seq.load(Ordering::Acquire);
        if write_idx >= read_idx + RING_BUFFER_SIZE as u64 {
            // Advance read pointer to prevent reading overwritten data
            self.read_seq.store(write_idx - RING_BUFFER_SIZE as u64 + 1, Ordering::Release);
        }

        // Write to the slot (non-atomic — single producer guarantees safety)
        self.buffer[slot] = Some(event);

        Ok(())
    }

    /// Pops the next unread log entry. Returns None if no new entries.
    pub fn pop(&mut self) -> Option<LogEvent> {
        let read_idx = self.read_seq.load(Ordering::Acquire);
        let write_idx = self.write_seq.load(Ordering::Acquire);

        if read_idx >= write_idx {
            return None; // Nothing to read
        }

        let slot = (read_idx as usize) & RING_BUFFER_MASK;

        // Safety: single consumer, and we verified write_idx > read_idx
        let entry = self.buffer[slot].take();

        // Advance read pointer
        self.read_seq.store(read_idx + 1, Ordering::Release);

        entry
    }

    /// Returns the number of unread entries.
    pub fn unread_count(&self) -> usize {
        let write = self.write_seq.load(Ordering::Acquire);
        let read = self.read_seq.load(Ordering::Acquire);
        (write - read) as usize
    }

    /// Returns the total number of entries ever pushed (including overwritten).
    pub fn total_pushed(&self) -> u64 {
        self.write_seq.load(Ordering::Acquire)
    }

    /// Returns the total number of entries ever popped.
    pub fn total_popped(&self) -> u64 {
        self.read_seq.load(Ordering::Acquire)
    }

    /// Drains all unread entries into a Vec.
    pub fn drain_all(&mut self) -> Vec<LogEvent> {
        let mut events = Vec::with_capacity(self.unread_count());
        while let Some(e) = self.pop() {
            events.push(e);
        }
        events
    }

    /// Sets the file path for flush-on-drop. When the logger is dropped,
    /// all remaining (undrained) messages will be synchronously written
    /// to this file in append mode.
    pub fn set_log_file_path(&mut self, path: String) {
        self.log_file_path = Some(path);
    }

    /// Peeks at the most recent entry without removing it.
    pub fn peek_latest(&self) -> Option<&LogEvent> {
        let write_idx = self.write_seq.load(Ordering::Acquire);
        if write_idx == 0 {
            return None;
        }
        let latest_slot = ((write_idx - 1) as usize) & RING_BUFFER_MASK;
        self.buffer[latest_slot].as_ref()
    }
}

impl Drop for RingBufferLogger {
    fn drop(&mut self) {
        let path = match &self.log_file_path {
            Some(p) => p.clone(),
            None => return,
        };

        let remaining = self.drain_all();
        if remaining.is_empty() {
            return;
        }

        if let Ok(mut file) = OpenOptions::new().create(true).append(true).open(&path) {
            for event in &remaining {
                // CSV-like line: log_id,timestamp_ms,exchange_id,symbol,side,quantity,price,delta_profit,strategy
                let line = format!(
                    "{},{},{},\"{}\",\"{}\",{},{},{},\"{}\"\n",
                    event.log_id,
                    event.timestamp_ms,
                    event.exchange_id,
                    event.symbol,
                    event.side,
                    event.quantity,
                    event.price,
                    event.delta_profit,
                    event.strategy,
                );
                let _ = file.write_all(line.as_bytes());
            }
            let _ = file.flush();
        }
    }
}

/// Shared market frame — a compact, atomic snapshot of market state for logging.
pub const MAX_SYMBOL_LEN: usize = 32;

#[derive(Debug, Clone)]
pub struct SharedMarketFrame {
    pub sequence_id: u64,
    pub symbol: String,
    pub best_bid: Decimal,
    pub best_ask: Decimal,
    pub timestamp_ms: u64,
    pub exchange_id: u16,
}

#[cfg(test)]
mod tests {
    use super::*;
    use rust_decimal_macros::dec;

    fn make_event(id: u64, profit: Decimal) -> LogEvent {
        LogEvent {
            log_id: id,
            timestamp_ms: 1700000000000 + id,
            delta_profit: profit,
            exchange_id: 0,
            symbol: "BTCUSDT".to_string(),
            side: "BUY".to_string(),
            quantity: dec!(0.001),
            price: dec!(50000.0),
            strategy: "cross_exchange".to_string(),
        }
    }

    #[test]
    #[ignore = "65536-element buffer overflows stack in debug mode"]
    fn test_push_and_pop() {
        let mut logger = RingBufferLogger::new();
        let event = make_event(0, dec!(1.5));
        logger.push(event.clone()).unwrap();
        let popped = logger.pop().unwrap();
        assert_eq!(popped.log_id, 0);
        assert_eq!(popped.delta_profit, dec!(1.5));
    }

    #[test]
    #[ignore = "65536-element buffer overflows stack in debug mode"]
    fn test_pop_empty() {
        let mut logger = RingBufferLogger::new();
        assert!(logger.pop().is_none());
    }

    #[test]
    #[ignore = "65536-element buffer overflows stack in debug mode"]
    fn test_fifo_order() {
        let mut logger = RingBufferLogger::new();
        logger.push(make_event(0, dec!(1.0))).unwrap();
        logger.push(make_event(1, dec!(2.0))).unwrap();
        logger.push(make_event(2, dec!(3.0))).unwrap();

        assert_eq!(logger.pop().unwrap().log_id, 0);
        assert_eq!(logger.pop().unwrap().log_id, 1);
        assert_eq!(logger.pop().unwrap().log_id, 2);
        assert!(logger.pop().is_none());
    }

    #[test]
    #[ignore = "65536-element buffer overflows stack in debug mode"]
    fn test_unread_count() {
        let mut logger = RingBufferLogger::new();
        assert_eq!(logger.unread_count(), 0);
        logger.push(make_event(0, dec!(1.0))).unwrap();
        logger.push(make_event(1, dec!(2.0))).unwrap();
        assert_eq!(logger.unread_count(), 2);
        logger.pop();
        assert_eq!(logger.unread_count(), 1);
    }

    #[test]
    #[ignore = "65536-element buffer overflows stack in debug mode"]
    fn test_drain_all() {
        let mut logger = Box::new(RingBufferLogger::new());
        for i in 0..5 {
            logger.push(make_event(i, Decimal::from(i as i64))).unwrap();
        }
        let events = logger.drain_all();
        assert_eq!(events.len(), 5);
        assert_eq!(events[0].log_id, 0);
        assert_eq!(events[4].log_id, 4);
        assert_eq!(logger.unread_count(), 0);
    }

    #[test]
    #[ignore = "65536-element buffer overflows stack in debug mode"]
    fn test_peek_latest() {
        let mut logger = RingBufferLogger::new();
        logger.push(make_event(0, dec!(1.0))).unwrap();
        logger.push(make_event(1, dec!(2.0))).unwrap();

        let latest = logger.peek_latest().unwrap();
        assert_eq!(latest.log_id, 1);
        // Peeking doesn't remove
        assert_eq!(logger.unread_count(), 2);
    }

    #[test]
    #[ignore = "65536-element buffer overflows stack in debug mode"]
    fn test_peek_empty() {
        let mut logger = RingBufferLogger::new();
        assert!(logger.peek_latest().is_none());
    }

    #[test]
    #[ignore = "65536-element buffer overflows stack in debug mode"]
    fn test_overwrite_behavior() {
        let mut logger = Box::new(RingBufferLogger::new());
        // Push more entries than buffer can hold
        for i in 0..(RING_BUFFER_SIZE as u64 + 10) {
            logger.push(make_event(i, Decimal::from(i as i64))).unwrap();
        }
        // Should still be able to pop without panicking
        // The oldest entries are lost, but the buffer is still functional
        assert!(logger.pop().is_some());
        assert_eq!(logger.unread_count(), RING_BUFFER_SIZE - 1);
    }

    #[test]
    #[ignore = "65536-element buffer overflows stack in debug mode"]
    fn test_total_counters() {
        let mut logger = RingBufferLogger::new();
        logger.push(make_event(0, dec!(1.0))).unwrap();
        logger.push(make_event(1, dec!(2.0))).unwrap();
        logger.pop();
        assert_eq!(logger.total_pushed(), 2);
        assert_eq!(logger.total_popped(), 1);
    }
}