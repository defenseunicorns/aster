//! Test-only deadlines driven by newly observed expected durable versions.
use std::{future::Future, time::Duration};
use tokio::time::{Instant, sleep, timeout_at};

struct Progress<const N: usize> {
    started: Instant,
    advanced: Instant,
    seen: [bool; N],
}

impl<const N: usize> Progress<N> {
    fn new(now: Instant) -> Self {
        Self {
            started: now,
            advanced: now,
            seen: [false; N],
        }
    }

    fn record(&mut self, milestones: [bool; N], now: Instant) {
        for (seen, present) in self.seen.iter_mut().zip(milestones) {
            if present && !*seen {
                *seen = true;
                self.advanced = now;
            }
        }
    }

    fn deadline(&self, stall: Duration, cap: Duration) -> Instant {
        (self.started + cap).min(self.advanced + stall)
    }

    fn diagnostic(&self, label: &str, cap: Duration, detail: &str) -> String {
        let now = Instant::now();
        let reason = if now >= self.started + cap {
            "absolute deadline exceeded"
        } else {
            "durable progress stalled"
        };
        format!(
            "{label}: {reason}; elapsed={:?}; idle={:?}; expected_versions_seen={:?}; last_probe={detail}",
            now - self.started,
            now - self.advanced,
            self.seen
        )
    }
}

// Only first observation of a named expected version advances the timer.
// Completion is a separate exact predicate; duplicate/oscillating projections
// and successful contacts never replenish the deadline. A hung query is bounded.
pub(super) async fn wait<const N: usize, T, F, Fut>(
    label: &str,
    stall: Duration,
    cap: Duration,
    mut probe: F,
) -> T
where
    F: FnMut() -> Fut,
    Fut: Future<Output = ([bool; N], Option<T>, String)>,
{
    let mut progress = Progress::new(Instant::now());
    let mut detail = "no completed query".to_owned();
    loop {
        let deadline = progress.deadline(stall, cap);
        assert!(
            Instant::now() < deadline,
            "{}",
            progress.diagnostic(label, cap, &detail)
        );
        let result = timeout_at(deadline, probe()).await;
        assert!(
            Instant::now() < deadline,
            "{}",
            progress.diagnostic(label, cap, &detail)
        );
        let (milestones, complete, latest) =
            result.unwrap_or_else(|_| panic!("{}", progress.diagnostic(label, cap, &detail)));
        progress.record(milestones, Instant::now());
        detail = latest;
        if let Some(value) = complete {
            return value;
        }
        sleep(
            Duration::from_millis(20).min(
                progress
                    .deadline(stall, cap)
                    .saturating_duration_since(Instant::now()),
            ),
        )
        .await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn only_new_expected_versions_extend_stall_and_never_absolute_cap() {
        let start = Instant::now();
        let mut p = Progress::<3>::new(start);
        let stall = Duration::from_secs(10);
        let cap = Duration::from_secs(25);
        p.record([true, false, false], start + Duration::from_secs(8));
        p.record([false, false, false], start + Duration::from_secs(12));
        p.record([true, false, false], start + Duration::from_secs(17));
        assert_eq!(p.deadline(stall, cap), start + Duration::from_secs(18));
        p.record([true, true, false], start + Duration::from_secs(17));
        assert_eq!(p.deadline(stall, cap), start + cap);
        p.record([true, true, true], start + Duration::from_secs(24));
        assert_eq!(p.deadline(stall, cap), start + cap);
    }

    #[tokio::test]
    #[should_panic(expected = "durable progress stalled")]
    async fn hung_query_cannot_hide_a_stall() {
        wait::<1, (), _, _>(
            "hung",
            Duration::from_millis(20),
            Duration::from_secs(10),
            || std::future::pending(),
        )
        .await;
    }

    #[tokio::test]
    #[should_panic(expected = "absolute deadline exceeded")]
    async fn hung_query_cannot_hide_the_absolute_cap() {
        wait::<1, (), _, _>(
            "hung",
            Duration::from_secs(10),
            Duration::from_millis(20),
            || std::future::pending(),
        )
        .await;
    }
}
