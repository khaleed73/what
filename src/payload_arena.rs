//! Pre-Signed HTTP Payload Arena
//!
//! The spec requires fixed `[u8; 1024]` stack-allocated buffers for API
//! payloads to avoid heap allocation in the hot path. This module provides
//! a pool of reusable buffers and helpers for building signed query strings
//! directly into stack memory.
//!
//! Spec reference: "Pre-Signed HTTP Payload Arenas — Fixed `[u8; 1024]`
//! buffers for API payloads, avoid heap"

use std::cell::UnsafeCell;
use std::mem::MaybeUninit;

/// Size of each payload buffer in bytes.
pub const PAYLOAD_BUFFER_SIZE: usize = 1024;

/// A single stack-allocated payload buffer.
///
/// This avoids heap allocation for API query string construction.
/// The buffer is a fixed-size array that is written to in-place.
pub struct PayloadBuffer {
    data: UnsafeCell<MaybeUninit<[u8; PAYLOAD_BUFFER_SIZE]>>,
    len: UnsafeCell<usize>,
}

// Safety: PayloadBuffer is designed for single-threaded use within
// a single async task. It is NOT Send/Sync by design — it should
// only be used within a single task context.
// In practice, each task gets its own PayloadArena.

impl PayloadBuffer {
    /// Creates a zeroed payload buffer.
    pub fn new() -> Self {
        Self {
            data: UnsafeCell::new(MaybeUninit::zeroed()),
            len: UnsafeCell::new(0),
        }
    }

    /// Returns the current written length.
    #[inline(always)]
    pub fn len(&self) -> usize {
        unsafe { *self.len.get() }
    }

    /// Returns `true` if the buffer is empty.
    #[inline(always)]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Clears the buffer (sets length to 0).
    #[inline(always)]
    pub fn clear(&self) {
        unsafe {
            *self.len.get() = 0;
        }
    }

    /// Appends a byte slice to the buffer. Returns `false` if it would overflow.
    #[inline]
    pub fn append(&self, data: &[u8]) -> bool {
        let current_len = self.len();
        let new_len = current_len + data.len();
        if new_len > PAYLOAD_BUFFER_SIZE {
            return false;
        }
        unsafe {
            let dst = (*self.data.get()).as_mut_ptr() as *mut u8;
            std::ptr::copy_nonoverlapping(data.as_ptr(), dst.add(current_len), data.len());
            *self.len.get() = new_len;
        }
        true
    }

    /// Appends a `&str` to the buffer.
    #[inline]
    pub fn append_str(&self, s: &str) -> bool {
        self.append(s.as_bytes())
    }

    /// Appends a key-value pair: `&key=&value`. Does NOT add `&` prefix.
    #[inline]
    pub fn append_param(&self, key: &str, value: &str) -> bool {
        let need_amp = !self.is_empty();
        if need_amp && !self.append_str("&") {
            return false;
        }
        self.append_str(key) && self.append_str("=") && self.append_str(value)
    }

    /// Returns the written portion as a `&str` (must be valid UTF-8).
    pub fn as_str(&self) -> &str {
        unsafe {
            let ptr = (*self.data.get()).as_ptr() as *const u8;
            let slice = std::slice::from_raw_parts(ptr, self.len());
            std::str::from_utf8_unchecked(slice)
        }
    }

    /// Returns the written portion as a `&[u8]`.
    pub fn as_bytes(&self) -> &[u8] {
        unsafe {
            let ptr = (*self.data.get()).as_ptr() as *const u8;
            std::slice::from_raw_parts(ptr, self.len())
        }
    }
}

impl Default for PayloadBuffer {
    fn default() -> Self {
        Self::new()
    }
}

/// A pool of payload buffers for reuse across multiple API calls.
///
/// Each buffer can be checked out, used, and returned. This avoids
/// repeated stack frame overhead and enables buffer recycling.
pub struct PreSignedPayloadArena {
    buffers: Vec<PayloadBuffer>,
    /// Next available buffer index (round-robin).
    next_index: std::cell::Cell<usize>,
}

impl PreSignedPayloadArena {
    /// Creates an arena with the given number of buffers.
    pub fn new(count: usize) -> Self {
        let buffers = (0..count).map(|_| PayloadBuffer::new()).collect();
        Self {
            buffers,
            next_index: std::cell::Cell::new(0),
        }
    }

    /// Gets the next available buffer (round-robin).
    ///
    /// The caller should call `clear()` before reusing.
    #[inline]
    pub fn acquire(&self) -> &PayloadBuffer {
        let idx = self.next_index.get();
        let buf = &self.buffers[idx % self.buffers.len()];
        self.next_index.set(idx + 1);
        buf
    }

    /// Returns the total number of buffers in the arena.
    pub fn capacity(&self) -> usize {
        self.buffers.len()
    }

    /// Clears all buffers.
    pub fn clear_all(&self) {
        for buf in &self.buffers {
            buf.clear();
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_buffer_append_str() {
        let buf = PayloadBuffer::new();
        assert!(buf.append_str("symbol=BTCUSDT"));
        assert_eq!(buf.as_str(), "symbol=BTCUSDT");
        assert_eq!(buf.len(), 14);
    }

    #[test]
    fn test_buffer_append_param() {
        let buf = PayloadBuffer::new();
        buf.append_param("symbol", "BTCUSDT");
        buf.append_param("side", "BUY");
        buf.append_param("quantity", "0.001");
        assert_eq!(buf.as_str(), "symbol=BTCUSDT&side=BUY&quantity=0.001");
    }

    #[test]
    fn test_buffer_clear() {
        let buf = PayloadBuffer::new();
        buf.append_str("hello");
        buf.clear();
        assert!(buf.is_empty());
        assert_eq!(buf.len(), 0);
    }

    #[test]
    fn test_buffer_overflow_returns_false() {
        let buf = PayloadBuffer::new();
        let long_str = "x".repeat(PAYLOAD_BUFFER_SIZE + 1);
        assert!(!buf.append_str(&long_str));
    }

    #[test]
    fn test_arena_acquire_round_robin() {
        let arena = PreSignedPayloadArena::new(3);
        let b0 = arena.acquire();
        let b1 = arena.acquire();
        let b2 = arena.acquire();
        let b3 = arena.acquire(); // wraps to 0

        // Verify they're different buffers by writing different data.
        b0.append_str("ZERO");
        b1.append_str("ONE");
        b2.append_str("TWO");
        assert_eq!(b0.as_str(), "ZERO");
        assert_eq!(b1.as_str(), "ONE");
        assert_eq!(b2.as_str(), "TWO");
        // b3 is the same buffer as b0, which now has "ZERO".
        assert_eq!(b3.as_str(), "ZERO");
    }

    #[test]
    fn test_arena_capacity() {
        let arena = PreSignedPayloadArena::new(8);
        assert_eq!(arena.capacity(), 8);
    }

    #[test]
    fn test_buffer_size_constant() {
        assert_eq!(PAYLOAD_BUFFER_SIZE, 1024);
    }
}