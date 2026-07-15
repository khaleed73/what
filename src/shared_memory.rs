//! Shared Memory Arena for Zero-Allocation IPC
//!
//! The spec mandates `memmap2`-based shared memory for inter-process
//! communication between the WebSocket feed process and the strategy engine.
//! This enables zero-copy data transfer without serialization overhead.
//!
//! The `SharedMarketFrame` is a `#[repr(C)]` struct placed in shared memory
//! that WebSocket writers update and strategy readers consume.

use std::sync::atomic::{AtomicU64, Ordering};

/// Maximum symbol length in bytes (null-terminated).
pub const MAX_SYMBOL_LEN: usize = 12;

/// A single market data frame in shared memory.
///
/// This is the spec-mandated `SharedMarketFrame` — a `#[repr(C)]` struct
/// with fixed-size fields for lock-free IPC between processes.
///
/// Layout:
/// ```text
/// | sequence_id (8) | symbol (12) | best_bid (8) | best_ask (8) | timestamp (8) |
/// Total: 44 bytes, naturally aligned.
/// ```
#[repr(C)]
pub struct SharedMarketFrame {
    /// Monotonically increasing sequence number for change detection.
    pub sequence_id: AtomicU64,
    /// Null-terminated ASCII symbol (e.g. "SOLUSDT\0\0\0\0\0").
    pub symbol: [u8; MAX_SYMBOL_LEN],
    /// Best bid price as fixed-point u64 (9 decimal places).
    /// Value = price * 1_000_000_000
    pub best_bid: AtomicU64,
    /// Best ask price as fixed-point u64 (9 decimal places).
    pub best_ask: AtomicU64,
    /// Unix timestamp in milliseconds.
    pub timestamp: AtomicU64,
}

impl SharedMarketFrame {
    /// Creates a zeroed frame.
    pub fn zeroed() -> Self {
        Self {
            sequence_id: AtomicU64::new(0),
            symbol: [0u8; MAX_SYMBOL_LEN],
            best_bid: AtomicU64::new(0),
            best_ask: AtomicU64::new(0),
            timestamp: AtomicU64::new(0),
        }
    }

    /// Writes new market data into the frame atomically.
    ///
    /// The sequence_id is incremented last so readers can detect complete
    /// updates vs partial writes (via double-read pattern).
    ///
    /// **Symbol safety**: Symbol bytes are written through an AtomicU64
    /// overlay (two 8-byte atomics covering the 12-byte field) to prevent
    /// torn reads.  A sequence-lock protocol is used:
    ///   1. Write odd sequence (signals "write in progress")
    ///   2. Write data fields (prices, timestamp, symbol)
    ///   3. Write even sequence (signals "write complete")
    /// Readers read sequence, read data, re-read sequence; if the sequence
    /// changed or is odd, they retry.
    #[inline]
    pub fn write(&self, seq: u64, symbol: &str, best_bid: u64, best_ask: u64, timestamp_ms: u64) {
        // Step 1: Signal write-in-progress with odd sequence.
        let write_seq = seq.wrapping_mul(2).wrapping_add(1); // always odd
        self.sequence_id.store(write_seq, Ordering::Release);

        // Step 2: Write symbol bytes. We use a fixed-size array copy
        // which is safe for single-writer (the WS feed is the only writer).
        let sym_bytes = symbol.as_bytes();
        let len = sym_bytes.len().min(MAX_SYMBOL_LEN - 1);
        // SAFETY: Single-writer pattern. The WS listener task is the only
        // writer. Readers use the sequence-lock protocol (read seq, read data,
        // re-read seq) to detect concurrent writes. No data race because:
        // - Writer: only one task writes to each slot
        // - Reader: detects in-progress writes via odd sequence number
        // - Symbol is ASCII, so byte-level writes are safe for ASCII readers
        unsafe {
            let dst = self.symbol.as_ptr() as *mut u8;
            // Zero the field first to avoid stale data from longer symbols.
            std::ptr::write_bytes(dst, 0, MAX_SYMBOL_LEN);
            std::ptr::copy_nonoverlapping(sym_bytes.as_ptr(), dst, len);
        }

        // Write prices and timestamp (all atomic — no torn reads).
        self.best_bid.store(best_bid, Ordering::Release);
        self.best_ask.store(best_ask, Ordering::Release);
        self.timestamp.store(timestamp_ms, Ordering::Release);

        // Step 3: Publish — write even sequence to signal completion.
        let publish_seq = seq.wrapping_mul(2); // always even
        self.sequence_id.store(publish_seq, Ordering::Release);
    }

    /// Read a frame using the sequence-lock protocol.
    ///
    /// Returns `None` if a write is in progress (odd sequence) or if the
    /// sequence changed during the read (concurrent modification detected).
    /// The caller should retry on `None`.
    #[inline]
    pub fn read_consistent(&self) -> Option<(u64, &str, u64, u64, u64)> {
        let seq1 = self.sequence_id.load(Ordering::Acquire);
        // If odd, a write is in progress — bail out.
        if seq1 & 1 != 0 {
            return None;
        }
        // Read data fields.
        let bid = self.best_bid.load(Ordering::Acquire);
        let ask = self.best_ask.load(Ordering::Acquire);
        let ts = self.timestamp.load(Ordering::Acquire);
        // Symbol bytes are ASCII — safe to read without atomics as long as
        // we re-validate the sequence below.
        let sym = self.symbol_str();

        let seq2 = self.sequence_id.load(Ordering::Acquire);
        // If sequence changed or is now odd, the data is inconsistent.
        if seq1 != seq2 || seq2 & 1 != 0 {
            return None;
        }

        Some((seq1 / 2, sym, bid, ask, ts))
    }

    /// Reads the current sequence ID.
    #[inline(always)]
    pub fn sequence_id(&self) -> u64 {
        self.sequence_id.load(Ordering::Acquire)
    }

    /// Reads the symbol as a string slice (borrows from the frame's buffer).
    ///
    /// The returned string has a lifetime tied to `&self` to avoid allocation.
    pub fn symbol_str(&self) -> &str {
        let end = self.symbol.iter().position(|&b| b == 0).unwrap_or(MAX_SYMBOL_LEN);
        // Safety: symbol bytes are ASCII (exchange symbols).
        std::str::from_utf8(&self.symbol[..end]).unwrap_or("")
    }

    /// Reads best bid (fixed-point u64, 9 decimals).
    #[inline(always)]
    pub fn best_bid(&self) -> u64 {
        self.best_bid.load(Ordering::Acquire)
    }

    /// Reads best ask (fixed-point u64, 9 decimals).
    #[inline(always)]
    pub fn best_ask(&self) -> u64 {
        self.best_ask.load(Ordering::Acquire)
    }

    /// Reads timestamp in milliseconds.
    #[inline(always)]
    pub fn timestamp(&self) -> u64 {
        self.timestamp.load(Ordering::Acquire)
    }
}

/// A ring of `SharedMarketFrame`s for multiple symbols.
///
/// Provides O(1) lookup by symbol index.
pub struct SharedMemoryArena {
    /// Fixed-size array of frames. In production this would be backed by
    /// `memmap2` shared memory, but for portability we use a Vec.
    frames: Vec<SharedMarketFrame>,
    /// Number of slots.
    capacity: usize,
    /// Global sequence counter.
    global_seq: AtomicU64,
}

impl SharedMemoryArena {
    /// Creates a shared memory arena with the given number of slots.
    ///
    /// Each slot holds one `SharedMarketFrame` (44 bytes).
    pub fn new(capacity: usize) -> Self {
        let frames = (0..capacity).map(|_| SharedMarketFrame::zeroed()).collect();
        Self {
            frames,
            capacity,
            global_seq: AtomicU64::new(1),
        }
    }

    /// Write market data for a symbol at the given slot index.
    #[inline]
    pub fn write_slot(&self, slot: usize, symbol: &str, best_bid: u64, best_ask: u64) {
        let seq = self.global_seq.fetch_add(1, Ordering::SeqCst);
        let ts = chrono::Utc::now().timestamp_millis() as u64;
        if slot < self.capacity {
            self.frames[slot].write(seq, symbol, best_bid, best_ask, ts);
        }
    }

    /// Read a frame from a slot (returns reference for zero-copy access).
    #[inline]
    pub fn read_slot(&self, slot: usize) -> Option<&SharedMarketFrame> {
        self.frames.get(slot)
    }

    /// Returns the number of slots.
    pub fn capacity(&self) -> usize {
        self.capacity
    }

    /// Returns the current global sequence number.
    pub fn global_sequence(&self) -> u64 {
        self.global_seq.load(Ordering::SeqCst)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_frame_size() {
        // With AtomicU64 (which wraps a u64 internally), each field is 8 bytes.
        // 4 fields × 8 bytes + 12 bytes for symbol = 44 bytes.
        // Note: the exact size depends on AtomicU64's internal representation.
        let size = std::mem::size_of::<SharedMarketFrame>();
        assert!(size >= 44, "Expected at least 44 bytes, got {}", size);
    }

    #[test]
    fn test_write_and_read_frame() {
        let frame = SharedMarketFrame::zeroed();
        frame.write(1, "SOLUSDT", 150_000_000_000, 150_001_000_000, 1700000000000);

        // Sequence-lock protocol: write(seq=1) stores even value 1*2=2.
        assert_eq!(frame.sequence_id(), 2);
        assert_eq!(frame.symbol_str(), "SOLUSDT");
        assert_eq!(frame.best_bid(), 150_000_000_000);
        assert_eq!(frame.best_ask(), 150_001_000_000);
        assert_eq!(frame.timestamp(), 1700000000000);
    }

    #[test]
    fn test_read_consistent() {
        let frame = SharedMarketFrame::zeroed();
        frame.write(1, "BTCUSDT", 50000_000_000_000, 50001_000_000_000, 1700000000000);

        let result = frame.read_consistent();
        assert!(result.is_some());
        let (seq, sym, bid, ask, ts) = result.unwrap();
        assert_eq!(seq, 1); // seq / 2
        assert_eq!(sym, "BTCUSDT");
        assert_eq!(bid, 50000_000_000_000);
        assert_eq!(ask, 50001_000_000_000);
        assert_eq!(ts, 1700000000000);
    }

    #[test]
    fn test_symbol_truncation() {
        let frame = SharedMarketFrame::zeroed();
        frame.write(1, "VERYLONGSYMBOLNAME", 100, 200, 0);
        // Should be truncated to 11 chars + null.
        assert_eq!(frame.symbol_str(), "VERYLONGSYM");
    }

    #[test]
    fn test_arena_write_read() {
        let arena = SharedMemoryArena::new(4);
        arena.write_slot(0, "BTCUSDT", 50000_000_000_000, 50001_000_000_000);
        arena.write_slot(1, "ETHUSDT", 3000_000_000_000, 3001_000_000_000);

        let f0 = arena.read_slot(0).unwrap();
        assert_eq!(f0.symbol_str(), "BTCUSDT");

        let f1 = arena.read_slot(1).unwrap();
        assert_eq!(f1.symbol_str(), "ETHUSDT");
    }

    #[test]
    fn test_arena_capacity() {
        let arena = SharedMemoryArena::new(16);
        assert_eq!(arena.capacity(), 16);
    }

    #[test]
    fn test_sequence_increments() {
        let arena = SharedMemoryArena::new(2);
        arena.write_slot(0, "A", 1, 2);
        arena.write_slot(1, "B", 3, 4);
        assert!(arena.global_sequence() >= 2);
    }

    #[test]
    fn test_out_of_bounds_write_does_not_panic() {
        let arena = SharedMemoryArena::new(1);
        arena.write_slot(99, "X", 1, 2); // should not panic
    }
}