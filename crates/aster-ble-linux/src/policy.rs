use std::{sync::Arc, time::Duration};
use tokio::sync::watch;

#[derive(Clone, Debug)]
pub(crate) struct LifecycleCancellation {
    cancelled: Arc<watch::Sender<bool>>,
}

impl Default for LifecycleCancellation {
    fn default() -> Self {
        let (cancelled, _) = watch::channel(false);
        Self {
            cancelled: Arc::new(cancelled),
        }
    }
}

impl LifecycleCancellation {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    pub(crate) fn cancel(&self) {
        self.cancelled.send_if_modified(|cancelled| {
            if *cancelled {
                false
            } else {
                *cancelled = true;
                true
            }
        });
    }

    pub(crate) fn is_cancelled(&self) -> bool {
        *self.cancelled.borrow()
    }

    pub(crate) fn observer(&self) -> LifecycleCancellationObserver {
        LifecycleCancellationObserver {
            cancelled: self.cancelled.subscribe(),
        }
    }

    pub(crate) async fn cancelled(&self) {
        let mut cancelled = self.cancelled.subscribe();
        while !*cancelled.borrow_and_update() {
            if cancelled.changed().await.is_err() {
                return;
            }
        }
    }
}

/// Non-authoritative observation of one lifecycle cancellation generation.
#[derive(Clone, Debug)]
pub(crate) struct LifecycleCancellationObserver {
    cancelled: watch::Receiver<bool>,
}

impl LifecycleCancellationObserver {
    pub(crate) fn is_cancelled(&self) -> bool {
        *self.cancelled.borrow()
    }

    pub(crate) async fn cancelled(&self) {
        let mut cancelled = self.cancelled.clone();
        while !*cancelled.borrow_and_update() {
            if cancelled.changed().await.is_err() {
                return;
            }
        }
    }
}

#[derive(Clone, Debug)]
pub(crate) struct CappedBackoff {
    initial: Duration,
    maximum: Duration,
    next: Duration,
}

impl CappedBackoff {
    pub(crate) fn new(initial: Duration, maximum: Duration) -> Self {
        let initial = initial.min(maximum);
        Self {
            initial,
            maximum,
            next: initial,
        }
    }

    pub(crate) fn next_delay(&mut self) -> Duration {
        let delay = self.next;
        self.next = if self.next >= self.maximum.saturating_sub(self.next) {
            self.maximum
        } else {
            self.next.saturating_add(self.next)
        };
        delay
    }

    pub(crate) fn reset(&mut self) {
        self.next = self.initial;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn capped_backoff_never_overflows() {
        let maximum = Duration::MAX;
        let mut backoff = CappedBackoff::new(maximum - Duration::from_nanos(1), maximum);

        assert_eq!(backoff.next_delay(), maximum - Duration::from_nanos(1));
        assert_eq!(backoff.next_delay(), maximum);
        assert_eq!(backoff.next_delay(), maximum);
        backoff.reset();
        assert_eq!(backoff.next_delay(), maximum - Duration::from_nanos(1));
    }

    #[tokio::test]
    async fn lifecycle_cancellation_is_idempotent() {
        let cancellation = LifecycleCancellation::new();
        let observer = cancellation.clone();

        cancellation.cancel();
        cancellation.cancel();

        observer.cancelled().await;
        assert!(observer.is_cancelled());
    }

    #[test]
    fn lifecycle_cancellation_default_starts_active() {
        assert!(!LifecycleCancellation::default().is_cancelled());
    }
}
