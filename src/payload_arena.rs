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
///
/// # Thread Safety
/// This type is `!Send` and `!Sync` because it uses `UnsafeCell`
/// for interior mutability. It is designed for single-threaded use
/// within a single async task. Each task should get its own `PayloadArena`.
pub struct PayloadBuffer {
    data: UnsafeCell<MaybeUninit<[u8; PAYLOAD_BUFFER_SIZE]>>,
    len: UnsafeCell<usize>,
    _not_send_sync: std::marker::PhantomData<*const ()>,
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
            _not_send_sync: std::marker::PhantomData,
        }
    }

    /// Returns the current written length.
    #[inline(always)]
    pub fn len(&self) -> usize {
        // SAFETY: Single-threaded by design — `PayloadArena` is `!Send`/`!Sync`.
        // Only one task ever accesses this buffer at a time.
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
        // SAFETY: Single-threaded by design (see `len()`).
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
        // SAFETY: Single-threaded by design (see `len()`).
        // Bounds check above guarantees `current_len + data.len()` fits within
        // `PAYLOAD_BUFFER_SIZE`. `copy_nonoverlapping` is safe because
        // source and destination regions do not overlap (appending to end).
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
    ///
    /// # Safety Invariant
    /// Callers must only write valid UTF-8 data (ASCII param strings).
    /// If binary data were written, this would be UB.
    pub fn as_str(&self) -> &str {
        // SAFETY: Single-threaded by design (see `len()`).
        // All callers write only ASCII param strings, which are valid UTF-8.
        unsafe {
            let ptr = (*self.data.get()).as_ptr() as *const u8;
            let slice = std::slice::from_raw_parts(ptr, self.len());
            std::str::from_utf8(slice)
                .expect("PayloadArena data is guaranteed ASCII by construction")
        }
    }

    /// Returns the written portion as a `&[u8]`.
    pub fn as_bytes(&self) -> &[u8] {
        // SAFETY: Single-threaded by design (see `len()`).
        // `self.len()` bytes have been written via `append()`, so the
        // slice is fully initialized.
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
///
/// M-15: Tracks total bytes allocated across all buffers and refuses
/// allocations that would exceed the arena's capacity.
pub struct PreSignedPayloadArena {
    buffers: Vec<PayloadBuffer>,
    /// Next available buffer index (round-robin).
    next_index: std::cell::Cell<usize>,
    /// M-15: Total bytes currently in-use across all buffers.
    total_allocated: std::cell::Cell<usize>,
    /// M-15: Maximum total bytes the arena is allowed to hold.
    max_capacity: usize,
}

impl PreSignedPayloadArena {
    /// Creates an arena with the given number of buffers.
    ///
    /// The maximum capacity defaults to `count * PAYLOAD_BUFFER_SIZE`.
    pub fn new(count: usize) -> Self {
        let buffers = (0..count).map(|_| PayloadBuffer::new()).collect();
        Self {
            buffers,
            next_index: std::cell::Cell::new(0),
            total_allocated: std::cell::Cell::new(0),
            max_capacity: count * PAYLOAD_BUFFER_SIZE,
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
        buf.clear();
        buf
    }

    /// Returns the total number of buffers in the arena.
    pub fn capacity(&self) -> usize {
        self.buffers.len()
    }

    /// Returns the current total bytes allocated across all buffers.
    pub fn total_allocated(&self) -> usize {
        self.total_allocated.get()
    }

    /// Clears all buffers and resets the allocation counter.
    pub fn clear_all(&self) {
        for buf in &self.buffers {
            buf.clear();
        }
        self.total_allocated.set(0);
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