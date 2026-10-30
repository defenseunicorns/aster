use std::{
    io::{self, Write},
    time::{Duration, Instant},
};

const PERIODIC_INTERVAL: Duration = Duration::from_millis(250);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProgressMode {
    Auto,
    Always,
    Never,
}

impl ProgressMode {
    pub fn parse(value: &str) -> Result<Self, &'static str> {
        match value {
            "auto" => Ok(Self::Auto),
            "always" => Ok(Self::Always),
            "never" => Ok(Self::Never),
            _ => Err("progress must be auto, always, or never"),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProgressKind {
    Publish,
    Read,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProgressEvent {
    Initial,
    Periodic,
    Checkpoint,
    Terminal,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ProgressSnapshot {
    pub sent: u64,
    pub accepted: u64,
    pub durable: u64,
    pub written: u64,
    pub total: u64,
}

pub trait ProgressSink {
    fn report(&mut self, event: ProgressEvent, snapshot: ProgressSnapshot) -> io::Result<()>;
}

#[cfg(test)]
pub struct NoProgress;

#[cfg(test)]
impl ProgressSink for NoProgress {
    fn report(&mut self, _event: ProgressEvent, _snapshot: ProgressSnapshot) -> io::Result<()> {
        Ok(())
    }
}

pub trait Clock {
    fn now(&self) -> Duration;
}

pub struct SystemClock(Instant);

impl SystemClock {
    pub fn start() -> Self {
        Self(Instant::now())
    }
}

impl Clock for SystemClock {
    fn now(&self) -> Duration {
        self.0.elapsed()
    }
}

pub struct ProgressReporter<W, C = SystemClock> {
    writer: W,
    enabled: bool,
    terminal: bool,
    kind: ProgressKind,
    clock: C,
    previous: Option<ProgressSnapshot>,
    last_emitted: Option<(Duration, u64)>,
}

impl<W: Write, C: Clock> ProgressReporter<W, C> {
    pub fn new(
        writer: W,
        mode: ProgressMode,
        terminal: bool,
        kind: ProgressKind,
        clock: C,
    ) -> Self {
        Self {
            writer,
            enabled: mode == ProgressMode::Always || (mode == ProgressMode::Auto && terminal),
            terminal,
            kind,
            clock,
            previous: None,
            last_emitted: None,
        }
    }

    pub fn report(&mut self, event: ProgressEvent, snapshot: ProgressSnapshot) -> io::Result<()> {
        self.validate(snapshot)?;
        self.previous = Some(snapshot);
        if !self.enabled {
            return Ok(());
        }
        let now = self.clock.now();
        if event == ProgressEvent::Periodic
            && self
                .last_emitted
                .is_some_and(|(last, _)| now.saturating_sub(last) < PERIODIC_INTERVAL)
        {
            return Ok(());
        }
        let current = match self.kind {
            ProgressKind::Publish => snapshot.sent,
            ProgressKind::Read => snapshot.written,
        };
        let rate = self.last_emitted.map_or(0.0, |(last_time, last_bytes)| {
            let seconds = now.saturating_sub(last_time).as_secs_f64();
            if seconds == 0.0 {
                0.0
            } else {
                current.saturating_sub(last_bytes) as f64 / seconds
            }
        });
        let percentage = if snapshot.total == 0 {
            100.0
        } else {
            current as f64 * 100.0 / snapshot.total as f64
        };
        let line = match self.kind {
            ProgressKind::Publish => format!(
                "Blob publish: sent={} accepted={} durable={} total={} {percentage:.1}% elapsed={:.1}s rate={rate:.0} B/s",
                count(snapshot.sent),
                count(snapshot.accepted),
                count(snapshot.durable),
                count(snapshot.total),
                now.as_secs_f64(),
            ),
            ProgressKind::Read => format!(
                "Blob read: written={} total={} {percentage:.1}% elapsed={:.1}s rate={rate:.0} B/s",
                count(snapshot.written),
                count(snapshot.total),
                now.as_secs_f64(),
            ),
        };
        if self.terminal {
            self.writer.write_all(b"\r")?;
            self.writer.write_all(line.as_bytes())?;
            if event == ProgressEvent::Terminal {
                self.writer.write_all(b"\n")?;
            }
        } else {
            self.writer.write_all(line.as_bytes())?;
            self.writer.write_all(b"\n")?;
        }
        self.writer.flush()?;
        self.last_emitted = Some((now, current));
        Ok(())
    }

    #[cfg(test)]
    pub fn into_inner(self) -> W {
        self.writer
    }

    fn validate(&self, snapshot: ProgressSnapshot) -> io::Result<()> {
        if (snapshot.total == 0 && self.kind == ProgressKind::Publish)
            || snapshot.sent > snapshot.total
            || snapshot.accepted > snapshot.sent
            || snapshot.durable > snapshot.accepted
            || snapshot.written > snapshot.total
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid progress counters",
            ));
        }
        if self.previous.is_some_and(|previous| {
            previous.total != snapshot.total
                || previous.sent > snapshot.sent
                || previous.accepted > snapshot.accepted
                || previous.durable > snapshot.durable
                || previous.written > snapshot.written
        }) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "progress counters regressed",
            ));
        }
        Ok(())
    }
}

impl<W: Write, C: Clock> ProgressSink for ProgressReporter<W, C> {
    fn report(&mut self, event: ProgressEvent, snapshot: ProgressSnapshot) -> io::Result<()> {
        ProgressReporter::report(self, event, snapshot)
    }
}

fn count(value: u64) -> String {
    let digits = value.to_string();
    let mut output = String::with_capacity(digits.len() + digits.len() / 3);
    for (index, digit) in digits.bytes().enumerate() {
        if index > 0 && (digits.len() - index).is_multiple_of(3) {
            output.push(',');
        }
        output.push(char::from(digit));
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{cell::Cell, rc::Rc, time::Duration};

    #[derive(Clone)]
    struct FakeClock(Rc<Cell<Duration>>);

    impl FakeClock {
        fn new() -> Self {
            Self(Rc::new(Cell::new(Duration::ZERO)))
        }

        fn advance(&self, duration: Duration) {
            self.0.set(self.0.get() + duration);
        }
    }

    impl Clock for FakeClock {
        fn now(&self) -> Duration {
            self.0.get()
        }
    }

    fn snapshot(current: u64) -> ProgressSnapshot {
        ProgressSnapshot {
            sent: current,
            accepted: current,
            durable: current,
            written: current,
            total: 1_000,
        }
    }

    #[test]
    fn progress_auto_requires_tty() {
        let mut hidden = ProgressReporter::new(
            Vec::new(),
            ProgressMode::Auto,
            false,
            ProgressKind::Publish,
            FakeClock::new(),
        );
        hidden.report(ProgressEvent::Initial, snapshot(0)).unwrap();
        assert!(hidden.into_inner().is_empty());

        let mut visible = ProgressReporter::new(
            Vec::new(),
            ProgressMode::Auto,
            true,
            ProgressKind::Publish,
            FakeClock::new(),
        );
        visible.report(ProgressEvent::Initial, snapshot(0)).unwrap();
        assert!(!visible.into_inner().is_empty());
    }

    #[test]
    fn progress_always_is_newline_delimited_off_tty() {
        let mut reporter = ProgressReporter::new(
            Vec::new(),
            ProgressMode::Always,
            false,
            ProgressKind::Read,
            FakeClock::new(),
        );
        reporter
            .report(ProgressEvent::Initial, snapshot(0))
            .unwrap();
        reporter
            .report(ProgressEvent::Terminal, snapshot(1_000))
            .unwrap();
        let output = String::from_utf8(reporter.into_inner()).unwrap();
        assert!(!output.contains('\r'));
        assert_eq!(output.lines().count(), 2);
        assert!(output.ends_with('\n'));
    }

    #[test]
    fn progress_never_writes_nothing() {
        let mut reporter = ProgressReporter::new(
            Vec::new(),
            ProgressMode::Never,
            true,
            ProgressKind::Publish,
            FakeClock::new(),
        );
        for event in [
            ProgressEvent::Initial,
            ProgressEvent::Periodic,
            ProgressEvent::Checkpoint,
            ProgressEvent::Terminal,
        ] {
            reporter.report(event, snapshot(0)).unwrap();
        }
        assert!(reporter.into_inner().is_empty());
    }

    #[test]
    fn empty_read_progress_reports_finite_completion() {
        let mut reporter = ProgressReporter::new(
            Vec::new(),
            ProgressMode::Always,
            false,
            ProgressKind::Read,
            FakeClock::new(),
        );
        for event in [ProgressEvent::Initial, ProgressEvent::Terminal] {
            reporter.report(event, ProgressSnapshot::default()).unwrap();
        }
        let output = String::from_utf8(reporter.into_inner()).unwrap();
        assert_eq!(output.lines().count(), 2);
        assert!(
            output
                .lines()
                .all(|line| line.contains("written=0 total=0 100.0%"))
        );
    }

    #[test]
    fn empty_read_progress_still_rejects_nonzero_counters() {
        for snapshot in [
            ProgressSnapshot {
                written: 1,
                ..Default::default()
            },
            ProgressSnapshot {
                sent: 1,
                ..Default::default()
            },
            ProgressSnapshot {
                accepted: 1,
                ..Default::default()
            },
            ProgressSnapshot {
                durable: 1,
                ..Default::default()
            },
        ] {
            let mut reporter = ProgressReporter::new(
                Vec::new(),
                ProgressMode::Never,
                false,
                ProgressKind::Read,
                FakeClock::new(),
            );
            assert_eq!(
                reporter
                    .report(ProgressEvent::Initial, snapshot)
                    .unwrap_err()
                    .kind(),
                io::ErrorKind::InvalidData
            );
        }
    }

    #[test]
    fn progress_is_rate_limited_to_four_periodic_updates_per_second() {
        let clock = FakeClock::new();
        let mut reporter = ProgressReporter::new(
            Vec::new(),
            ProgressMode::Always,
            false,
            ProgressKind::Publish,
            clock.clone(),
        );
        reporter
            .report(ProgressEvent::Initial, snapshot(0))
            .unwrap();
        clock.advance(Duration::from_millis(100));
        reporter
            .report(ProgressEvent::Periodic, snapshot(100))
            .unwrap();
        clock.advance(Duration::from_millis(150));
        reporter
            .report(ProgressEvent::Periodic, snapshot(250))
            .unwrap();
        clock.advance(Duration::from_millis(100));
        reporter
            .report(ProgressEvent::Periodic, snapshot(350))
            .unwrap();
        assert_eq!(
            String::from_utf8(reporter.into_inner())
                .unwrap()
                .lines()
                .count(),
            2
        );
    }

    #[test]
    fn progress_emits_initial_checkpoint_and_terminal_records() {
        let mut reporter = ProgressReporter::new(
            Vec::new(),
            ProgressMode::Always,
            false,
            ProgressKind::Publish,
            FakeClock::new(),
        );
        reporter
            .report(ProgressEvent::Initial, snapshot(0))
            .unwrap();
        reporter
            .report(ProgressEvent::Checkpoint, snapshot(500))
            .unwrap();
        reporter
            .report(ProgressEvent::Terminal, snapshot(1_000))
            .unwrap();
        let output = String::from_utf8(reporter.into_inner()).unwrap();
        assert_eq!(output.lines().count(), 3);
        assert!(output.contains("sent=1,000"));
        assert!(output.contains("durable=1,000"));
        assert!(output.contains("100.0%"));
    }

    #[test]
    fn progress_propagates_output_failure() {
        struct Broken;
        impl Write for Broken {
            fn write(&mut self, _bytes: &[u8]) -> io::Result<usize> {
                Err(io::Error::new(io::ErrorKind::BrokenPipe, "fixture"))
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }

        let mut reporter = ProgressReporter::new(
            Broken,
            ProgressMode::Always,
            false,
            ProgressKind::Read,
            FakeClock::new(),
        );
        assert_eq!(
            reporter
                .report(ProgressEvent::Initial, snapshot(0))
                .unwrap_err()
                .kind(),
            io::ErrorKind::BrokenPipe
        );
    }

    #[test]
    fn json_stdout_remains_single_terminal_object_with_progress() {
        let stdout = crate::output::publish_blob(
            &crate::api::PublishBlobReceipt {
                publication_id: vec![3; 32],
                id: vec![1; 32],
                publisher: vec![2; 32],
                publisher_counter: 3,
                priority: crate::api::Priority::Routine.into(),
                total_len: 1_000,
                acceptance_marker: 4,
                inserted: true,
                ..Default::default()
            },
            "operation-key",
            true,
        )
        .unwrap();
        let mut reporter = ProgressReporter::new(
            Vec::new(),
            ProgressMode::Always,
            false,
            ProgressKind::Publish,
            FakeClock::new(),
        );
        reporter
            .report(ProgressEvent::Terminal, snapshot(1_000))
            .unwrap();
        let stderr = String::from_utf8(reporter.into_inner()).unwrap();

        let value: serde_json::Value = serde_json::from_str(&stdout).unwrap();
        assert!(value.is_object());
        assert_eq!(stdout.matches("\"publicationId\"").count(), 1);
        assert!(!stdout.contains("Blob publish:"));
        assert!(stderr.contains("Blob publish:"));
    }
}
