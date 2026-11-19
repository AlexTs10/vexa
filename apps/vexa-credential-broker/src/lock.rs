//! A re-entrant lock: the broker's one lock may be taken again by the thread
//! that holds it, as Python's threading.RLock.

use std::sync::{Condvar, Mutex};
use std::thread::{self, ThreadId};

#[derive(Default)]
pub struct ReentrantLock {
    state: Mutex<(Option<ThreadId>, usize)>,
    free: Condvar,
}

pub struct Guard<'a> {
    lock: &'a ReentrantLock,
}

impl ReentrantLock {
    pub fn lock(&self) -> Guard<'_> {
        let me = thread::current().id();
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        loop {
            match state.0 {
                None => {
                    *state = (Some(me), 1);
                    break;
                }
                Some(owner) if owner == me => {
                    state.1 += 1;
                    break;
                }
                Some(_) => state = self.free.wait(state).unwrap_or_else(|e| e.into_inner()),
            }
        }
        Guard { lock: self }
    }
}

impl Drop for Guard<'_> {
    fn drop(&mut self) {
        let mut state = self.lock.state.lock().unwrap_or_else(|e| e.into_inner());
        state.1 -= 1;
        if state.1 == 0 {
            state.0 = None;
            self.lock.free.notify_one();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[test]
    fn the_holder_may_take_it_again_and_others_wait() {
        let lock = Arc::new(ReentrantLock::default());
        let outer = lock.lock();
        let inner = lock.lock();
        drop(inner);
        let other = {
            let lock = lock.clone();
            thread::spawn(move || {
                let _g = lock.lock();
                1
            })
        };
        thread::sleep(std::time::Duration::from_millis(50));
        assert!(!other.is_finished());
        drop(outer);
        assert_eq!(other.join().unwrap(), 1);
    }
}
