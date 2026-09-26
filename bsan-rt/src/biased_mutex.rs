use core::marker::PhantomData;
use core::ops::{Deref, DerefMut};
use core::sync::atomic::{AtomicBool, Ordering, fence};

use spin::mutex::{SpinMutex, SpinMutexGuard};
use spin::relax::{RelaxStrategy, Spin};

// Implements the biased, asymmetric mutex 
// from "Simple and Fast Biased Locks".
// https://ieeexplore.ieee.org/document/7851509
pub(crate) struct BiasedMutex<T, R = Spin> {
    lock: SpinMutex<T, R>,
    owner: usize,
    req: AtomicBool,
    grant: AtomicBool,
}

impl<T: Default, R> Default for BiasedMutex<T, R> {
    fn default() -> Self {
        Self {
            lock: SpinMutex::default(),
            owner: 0,
            req: AtomicBool::new(false),
            grant: AtomicBool::new(false),
        }
    }
}

impl<T, R: RelaxStrategy> BiasedMutex<T, R> {
    fn lock(&self, id: usize) -> BiasedGuard<'_, T, R> {
        let kind = if id == self.owner {
            while self.grant.load(Ordering::Relaxed) {
                R::relax();
            }
            GuardKind::Owner(PhantomData)
        } else {
            // Slow path: serialize with other non-owners, then request access.
            let guard = self.lock.lock();
            self.req.store(true, Ordering::Relaxed);
            while !self.grant.load(Ordering::Relaxed) {
                R::relax();
            }
            GuardKind::Remote(guard)
        };
        BiasedGuard { mutex: self, kind }
    }
}

enum GuardKind<'a, T, R> {
    Owner(PhantomData<*mut T>),
    Remote(SpinMutexGuard<'a, T, R>),
}

pub(crate) struct BiasedGuard<'a, T, R = Spin> {
    mutex: &'a BiasedMutex<T, R>,
    kind: GuardKind<'a, T, R>,
}

impl<T, R> Drop for BiasedGuard<'_, T, R> {
    fn drop(&mut self) {
        let mutex = self.mutex;
        match self.kind {
            GuardKind::Owner(_) => {
                if mutex.req.load(Ordering::Relaxed) {
                    mutex.req.store(false, Ordering::Relaxed);
                    fence(Ordering::SeqCst);
                    mutex.grant.store(true, Ordering::Relaxed);
                    fence(Ordering::SeqCst);
                }
            }
            GuardKind::Remote(_) => {
                fence(Ordering::SeqCst);
                mutex.grant.store(false, Ordering::Relaxed);
            }
        }
    }
}

impl<T, R> Deref for BiasedGuard<'_, T, R> {
    type Target = T;

    fn deref(&self) -> &T {
        match &self.kind {
            GuardKind::Owner(_) => unsafe { &*self.mutex.lock.as_mut_ptr() },
            GuardKind::Remote(guard) => guard,
        }
    }
}

impl<T, R> DerefMut for BiasedGuard<'_, T, R> {
    fn deref_mut(&mut self) -> &mut T {
        match &mut self.kind {
            GuardKind::Owner(_) => unsafe { &mut *self.mutex.lock.as_mut_ptr() },
            GuardKind::Remote(guard) => guard,
        }
    }
}
