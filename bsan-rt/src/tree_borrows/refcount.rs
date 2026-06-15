use core::sync::atomic::{fence, AtomicUsize, Ordering};

/// A thread-safe reference count with correct atomic ordering semantics.
// TODO: remove `allow(dead_code)` once the `__bsan_rc_inc`/`__bsan_rc_dec`
// endpoints (lib.rs) actually drive this type. Until then it is unused in
// non-test builds, which `-Dwarnings` would otherwise reject.
#[allow(dead_code)]
#[derive(Debug)]
pub struct RefCount {
    count: AtomicUsize,
}

#[allow(dead_code)]
impl RefCount {
    /// Creates a new `RefCount` initialized to 1.
    pub fn new() -> Self {
        Self { count: AtomicUsize::new(1) }
    }

    /// Increments the reference count.
    ///
    /// The caller must already hold a live reference. Resurrecting a
    /// reference count from zero is undefined behavior in this design.
    ///
    /// Panics if the count would overflow `usize::MAX / 2`. In practice this is
    /// unreachable, but the check prevents silent wraparound to zero.
    pub fn increment(&self) {
        let prev = self.count.fetch_add(1, Ordering::Relaxed);
        debug_assert!(prev <= usize::MAX / 2, "RefCount overflow");
    }

    /// Decrements the reference count. Returns `true` if the count reached
    /// zero, indicating the caller is responsible for cleanup. Otherwise,
    /// returns `false` if the count is non-zero.
    pub fn decrement(&self) -> bool {
        let prev = self.count.fetch_sub(1, Ordering::Release);
        debug_assert!(prev > 0, "RefCount decremented below zero");
        if prev == 1 {
            // Pair with every prior Release decrement.
            fence(Ordering::Acquire);
            true
        } else {
            false
        }
    }

    /// Returns the current reference count at the time this function is called.
    pub fn get(&self) -> usize {
        self.count.load(Ordering::Relaxed)
    }

    /// Creates a new `RefCount` with the given initial value.
    ///
    /// Test-only: the runtime always starts a count at 1 via [`RefCount::new`].
    #[cfg(test)]
    fn with_count(n: usize) -> Self {
        Self { count: AtomicUsize::new(n) }
    }

    /// Returns `true` if the reference count is exactly 1 at the time this function is called.
    ///
    /// Test-only: the zero transition is reported by [`RefCount::decrement`] instead.
    #[cfg(test)]
    fn is_unique(&self) -> bool {
        self.count.load(Ordering::Acquire) == 1
    }
}

#[cfg(test)]
mod tests {
    use core::cell::UnsafeCell;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use std::thread;

    use super::*;

    // ---- single-threaded API sanity checks ----

    #[test]
    fn new_starts_at_one() {
        let rc = RefCount::new();
        assert_eq!(rc.get(), 1);
        assert!(rc.is_unique());
    }

    #[test]
    fn with_count_sets_initial_value() {
        let rc = RefCount::with_count(5);
        assert_eq!(rc.get(), 5);
        assert!(!rc.is_unique());
    }

    #[test]
    fn increment_raises_count() {
        let rc = RefCount::new();
        rc.increment();
        assert_eq!(rc.get(), 2);
        rc.increment();
        assert_eq!(rc.get(), 3);
        assert!(!rc.is_unique());
    }

    #[test]
    fn decrement_returns_false_while_nonzero() {
        let rc = RefCount::with_count(3);
        assert!(!rc.decrement());
        assert_eq!(rc.get(), 2);
        assert!(!rc.decrement());
        assert_eq!(rc.get(), 1);
        assert!(rc.is_unique());
    }

    #[test]
    fn decrement_returns_true_at_zero() {
        let rc = RefCount::new();
        assert!(rc.decrement());
        assert_eq!(rc.get(), 0);
    }

    #[test]
    fn inc_dec_roundtrip() {
        let rc = RefCount::new();
        rc.increment(); // 2
        rc.increment(); // 3
        assert!(!rc.decrement()); // 2
        assert!(!rc.decrement()); // 1
        assert!(rc.decrement()); // 0
    }

    const THREADS: usize = if cfg!(miri) { 4 } else { 16 };
    const ITERS: usize = if cfg!(miri) { 25 } else { 10_000 };

    /// Every thread performs a balanced run of increments followed by the same
    /// number of decrements. Because we start at 1 and never decrement the
    /// initial reference, the count stays `>= 1` throughout: no decrement
    /// should ever report the zero transition, and the count must return
    /// exactly to 1 once all threads join.
    #[test]
    fn concurrent_balanced_inc_dec() {
        let rc = Arc::new(RefCount::with_count(1));

        let handles: Vec<_> = (0..THREADS)
            .map(|_| {
                let rc = Arc::clone(&rc);
                thread::spawn(move || {
                    for _ in 0..ITERS {
                        rc.increment();
                    }
                    for _ in 0..ITERS {
                        assert!(!rc.decrement(), "count must never reach zero here");
                    }
                })
            })
            .collect();

        for h in handles {
            h.join().unwrap();
        }
        assert_eq!(rc.get(), 1);
    }

    /// With an initial count equal to the number of threads and each thread
    /// decrementing exactly once, the zero transition must be observed by
    /// exactly one thread.
    #[test]
    fn exactly_one_zero_transition() {
        let rc = Arc::new(RefCount::with_count(THREADS));
        let zero_observers = Arc::new(AtomicUsize::new(0));

        let handles: Vec<_> = (0..THREADS)
            .map(|_| {
                let rc = Arc::clone(&rc);
                let zero_observers = Arc::clone(&zero_observers);
                thread::spawn(move || {
                    if rc.decrement() {
                        zero_observers.fetch_add(1, Ordering::Relaxed);
                    }
                })
            })
            .collect();

        for h in handles {
            h.join().unwrap();
        }
        assert_eq!(zero_observers.load(Ordering::Relaxed), 1);
        assert_eq!(rc.get(), 0);
    }

    /// Mirrors `Arc`'s drop protocol and is the test that actually exercises
    /// the ordering: each thread writes to its own disjoint slot, then releases
    /// its reference. The single thread that observes the count reach zero then
    /// reads *all* slots. Correct `Release`/`Acquire` ordering makes every prior
    /// write happen-before that read; if the orderings were weakened (e.g. a
    /// `Relaxed` decrement), Miri's data-race detector would flag the read.
    #[test]
    fn release_acquire_publishes_writes() {
        // One `UnsafeCell` per thread: writers touch disjoint cells through a
        // raw pointer (never a `&mut` to the whole buffer), so threads only ever
        // share `&Slots`. The sole zero-observer reads every cell.
        struct Slots(Vec<UnsafeCell<u64>>);
        unsafe impl Sync for Slots {}

        let rounds = if cfg!(miri) { 5 } else { 200 };
        for _ in 0..rounds {
            let n = THREADS;
            let slots = Arc::new(Slots((0..n).map(|_| UnsafeCell::new(0u64)).collect()));
            let rc = Arc::new(RefCount::with_count(n));

            let handles: Vec<_> = (0..n)
                .map(|i| {
                    let slots = Arc::clone(&slots);
                    let rc = Arc::clone(&rc);
                    thread::spawn(move || {
                        // Each thread owns cell `i`; writes are non-overlapping.
                        unsafe {
                            *slots.0[i].get() = (i as u64) + 1;
                        }
                        // Release this reference. The last one out reads everything.
                        if rc.decrement() {
                            for (j, cell) in slots.0.iter().enumerate() {
                                let v = unsafe { *cell.get() };
                                assert_eq!(v, (j as u64) + 1, "write from thread {j} not visible");
                            }
                        }
                    })
                })
                .collect();

            for h in handles {
                h.join().unwrap();
            }
        }
    }
}
