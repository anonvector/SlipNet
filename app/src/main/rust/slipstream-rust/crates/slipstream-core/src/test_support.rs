use std::sync::atomic::{AtomicUsize, Ordering};

pub struct FailureCounter {
    remaining: AtomicUsize,
}

impl FailureCounter {
    pub const fn new() -> Self {
        Self {
            remaining: AtomicUsize::new(0),
        }
    }

    pub fn set(&self, count: usize) {
        self.remaining.store(count, Ordering::SeqCst);
    }

    pub fn take(&self) -> bool {
        let mut current = self.remaining.load(Ordering::SeqCst);
        while current > 0 {
            match self.remaining.compare_exchange(
                current,
                current - 1,
                Ordering::SeqCst,
                Ordering::SeqCst,
            ) {
                Ok(_) => return true,
                Err(next) => current = next,
            }
        }
        false
    }
}

impl Default for FailureCounter {
    fn default() -> Self {
        Self::new()
    }
}

pub struct ResetOnDrop<F: FnOnce()>(Option<F>);

impl<F: FnOnce()> ResetOnDrop<F> {
    pub fn new(reset: F) -> Self {
        Self(Some(reset))
    }
}

impl<F: FnOnce()> Drop for ResetOnDrop<F> {
    fn drop(&mut self) {
        if let Some(reset) = self.0.take() {
            reset();
        }
    }
}
