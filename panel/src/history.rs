//! The dashboard's history: connected sessions and throughput, sampled from
//! occtl every PANEL_SAMPLE_SECONDS and kept for PANEL_HISTORY_HOURS.
//! Throughput comes from each session's byte counters, compared with the
//! previous sample by session ID.

use std::collections::{HashMap, VecDeque};

use serde::{Deserialize, Serialize};

use crate::occtl::Session;

/// One point of the history.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Sample {
    /// Unix seconds.
    pub time: u64,
    pub sessions: u64,
    /// Bytes per second the server sent to clients since the previous
    /// sample; none for the first sample, which only sets the baseline.
    pub to_clients: Option<u64>,
    /// Bytes per second the server received from clients.
    pub from_clients: Option<u64>,
}

/// The samples of the last `capacity` intervals.
pub struct History {
    /// Seconds between samples.
    interval: u64,
    capacity: usize,
    samples: VecDeque<Sample>,
    /// Each session's counters (sent, received) at the previous sample.
    previous: HashMap<u64, (u64, u64)>,
    previous_time: Option<u64>,
}

impl History {
    /// A history holding `hours` of samples taken every `interval` seconds.
    pub fn new(hours: u64, interval: u64) -> Result<History, String> {
        let capacity = usize::try_from(hours * 3600 / interval.max(1))
            .map_err(|error| format!("{hours} hours of samples do not fit in memory: {error}"))?;
        Ok(History {
            interval,
            capacity,
            samples: VecDeque::new(),
            previous: HashMap::new(),
            previous_time: None,
        })
    }

    /// Seconds between samples.
    pub fn interval(&self) -> u64 {
        self.interval
    }

    pub fn samples(&self) -> Vec<Sample> {
        self.samples.iter().cloned().collect()
    }

    /// Fills the history with `samples` as if they had been taken, for the
    /// development server's charts.
    #[cfg(debug_assertions)]
    pub fn backfill(&mut self, samples: Vec<Sample>) {
        self.samples.extend(samples);
        while self.samples.len() > self.capacity {
            self.samples.pop_front();
        }
    }

    /// Adds the sample for `sessions` at `now`. A session seen before counts
    /// the growth of its counters; one that connected since the previous
    /// sample counts its whole counters; one already connected when sampling
    /// began counts nothing until the next sample.
    pub fn record(&mut self, now: u64, sessions: &[Session]) -> Result<(), String> {
        let mut sent_total = 0u64;
        let mut received_total = 0u64;
        let mut current = HashMap::new();
        for session in sessions {
            let (Some(sent), Some(received)) = (session.sent, session.received) else {
                continue;
            };
            current.insert(session.id, (sent, received));
            let (sent_before, received_before) = match self.previous.get(&session.id) {
                Some(before) => *before,
                None if self
                    .previous_time
                    .is_some_and(|time| session.connected_at >= time) =>
                {
                    (0, 0)
                }
                None => (sent, received),
            };
            sent_total = sent_total.saturating_add(sent.saturating_sub(sent_before));
            received_total =
                received_total.saturating_add(received.saturating_sub(received_before));
        }
        let elapsed = self
            .previous_time
            .map(|time| now.saturating_sub(time))
            .filter(|elapsed| *elapsed > 0);
        self.samples.push_back(Sample {
            time: now,
            sessions: u64::try_from(sessions.len())
                .map_err(|error| format!("the session count does not fit: {error}"))?,
            to_clients: elapsed.map(|seconds| sent_total / seconds),
            from_clients: elapsed.map(|seconds| received_total / seconds),
        });
        while self.samples.len() > self.capacity {
            self.samples.pop_front();
        }
        self.previous = current;
        self.previous_time = Some(now);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::occtl::Fake;

    fn sessions(sent: &[(u64, u64, u64)]) -> Vec<Session> {
        let template = Fake::sample(0).sessions.remove(0);
        sent.iter()
            .map(|&(id, sent, connected_at)| Session {
                id,
                sent: Some(sent),
                received: Some(sent / 10),
                connected_at,
                ..template.clone()
            })
            .collect()
    }

    #[test]
    fn the_first_sample_sets_the_baseline() {
        let mut history = History::new(24, 10).unwrap();
        history
            .record(1000, &sessions(&[(1, 5_000_000, 0)]))
            .unwrap();
        let first = &history.samples()[0];
        assert_eq!(
            (first.sessions, first.to_clients, first.from_clients),
            (1, None, None)
        );
    }

    #[test]
    fn throughput_is_counter_growth_per_second() {
        let mut history = History::new(24, 10).unwrap();
        history
            .record(1000, &sessions(&[(1, 5_000_000, 0)]))
            .unwrap();
        history
            .record(1010, &sessions(&[(1, 5_100_000, 0), (2, 20_000, 1005)]))
            .unwrap();
        let second = &history.samples()[1];
        assert_eq!(second.sessions, 2);
        assert_eq!(second.to_clients, Some((100_000 + 20_000) / 10));
        assert_eq!(second.from_clients, Some((10_000 + 2_000) / 10));
    }

    #[test]
    fn a_session_seen_late_counts_from_the_next_sample() {
        let mut history = History::new(24, 10).unwrap();
        history.record(1000, &sessions(&[])).unwrap();
        history
            .record(1010, &sessions(&[(7, 9_000_000, 500)]))
            .unwrap();
        assert_eq!(history.samples()[1].to_clients, Some(0));
    }

    #[test]
    fn only_the_last_hours_are_kept() {
        let mut history = History::new(1, 1800).unwrap();
        for step in 0..5 {
            history.record(1000 + step * 1800, &sessions(&[])).unwrap();
        }
        let times: Vec<u64> = history.samples().iter().map(|sample| sample.time).collect();
        assert_eq!(times, [1000 + 3 * 1800, 1000 + 4 * 1800]);
    }
}
