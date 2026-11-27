//! The audit log: one JSON line per sign-in, refusal and change, appended to
//! audit.log in the panel's data directory and copied to standard output.
//!
//! A line is synced to disk before the request it records is answered, and a
//! line that cannot be written fails that request.

use std::fs::File;
use std::io::Write;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::{clock, files};

/// Whether an audited request was carried out.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Outcome {
    Allowed,
    Denied,
}

/// One line of the audit log.
#[derive(Debug, Serialize)]
struct Entry<'a> {
    /// RFC 3339 UTC.
    time: String,
    /// The admin who acted, or the name someone tried to sign in as.
    actor: &'a str,
    /// The address the request came from.
    from: &'a str,
    /// What was attempted, as `area.verb`.
    action: &'a str,
    result: Outcome,
    /// What it applied to and how it went, in words.
    detail: &'a str,
}

/// One line of the audit log as it is read back.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Record {
    pub time: String,
    pub actor: String,
    pub from: String,
    pub action: String,
    pub result: Outcome,
    pub detail: String,
}

/// A page of the audit log, newest first, and the position to ask for the
/// next older page with, if there is one.
pub type Page = (Vec<Record>, Option<usize>);

/// The open audit log.
pub struct Audit {
    file: File,
    path: PathBuf,
}

impl Audit {
    /// Opens `path` for appending, creating it readable by root only.
    pub fn open(path: &Path) -> Result<Audit, String> {
        Ok(Audit {
            file: files::open_private_append(path)?,
            path: path.to_owned(),
        })
    }

    /// Up to `count` lines and `budget` bytes of them, newest first, from
    /// those before line `before`, or from the newest when it is none. The
    /// newest of them comes back whatever its size, so paging always moves.
    pub fn page(&self, before: Option<usize>, count: usize, budget: usize) -> Result<Page, String> {
        let text = std::fs::read_to_string(&self.path)
            .map_err(|error| format!("{}: {error}", self.path.display()))?;
        let lines: Vec<&str> = text.lines().filter(|line| !line.is_empty()).collect();
        let end = match before {
            Some(before) => before.min(lines.len()),
            None => lines.len(),
        };
        let mut start = end;
        let mut bytes = 0;
        while start > 0 && end - start < count {
            let size = lines[start - 1].len();
            if start < end && bytes + size > budget {
                break;
            }
            bytes += size;
            start -= 1;
        }
        let records = lines[start..end]
            .iter()
            .rev()
            .map(|line| {
                serde_json::from_str(line)
                    .map_err(|error| format!("an audit line could not be read: {error}"))
            })
            .collect::<Result<Vec<Record>, String>>()?;
        Ok((records, (start > 0).then_some(start)))
    }

    /// Appends one line, syncs it to disk and copies it to standard output.
    pub fn record(
        &mut self,
        now: u64,
        actor: &str,
        from: &str,
        action: &str,
        result: Outcome,
        detail: &str,
    ) -> Result<(), String> {
        let entry = Entry {
            time: clock::rfc3339(now),
            actor,
            from,
            action,
            result,
            detail,
        };
        let line = serde_json::to_string(&entry)
            .map_err(|error| format!("an audit line could not be encoded: {error}"))?;
        self.file
            .write_all(format!("{line}\n").as_bytes())
            .and_then(|()| self.file.sync_data())
            .map_err(|error| format!("the audit log could not be written: {error}"))?;
        writeln!(std::io::stdout(), "audit: {line}").map_err(|error| {
            format!("an audit line could not be copied to standard output: {error}")
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testdir::TestDir;

    #[test]
    fn pages_come_back_newest_first() {
        let dir = TestDir::new();
        let mut audit = Audit::open(&dir.path().join("audit.log")).unwrap();
        for second in 0..5 {
            audit
                .record(
                    second,
                    "alex",
                    "local",
                    "test.step",
                    Outcome::Allowed,
                    "a step",
                )
                .unwrap();
        }
        let (first, older) = audit.page(None, 2, usize::MAX).unwrap();
        let times: Vec<&str> = first.iter().map(|record| record.time.as_str()).collect();
        assert_eq!(times, ["1970-01-01T00:00:04Z", "1970-01-01T00:00:03Z"]);
        assert_eq!(older, Some(3));
        let (second, older) = audit.page(older, 2, usize::MAX).unwrap();
        assert_eq!(second[0].time, "1970-01-01T00:00:02Z");
        let (last, end) = audit.page(older, 2, usize::MAX).unwrap();
        assert_eq!((last.len(), end), (1, None));
        assert_eq!(last[0].result, Outcome::Allowed);
    }

    #[test]
    fn pages_stop_at_the_byte_budget_but_always_move() {
        let dir = TestDir::new();
        let mut audit = Audit::open(&dir.path().join("audit.log")).unwrap();
        let long = "x".repeat(4000);
        audit
            .record(0, "alex", "local", "test.step", Outcome::Allowed, "short")
            .unwrap();
        audit
            .record(1, &long, "local", "login", Outcome::Denied, "long name")
            .unwrap();
        audit
            .record(2, "alex", "local", "test.step", Outcome::Allowed, "short")
            .unwrap();
        let (first, older) = audit.page(None, 100, 1000).unwrap();
        assert_eq!((first.len(), older), (1, Some(2)));
        let (second, older) = audit.page(older, 100, 1000).unwrap();
        assert_eq!((second[0].actor.len(), older), (4000, Some(1)));
        let (last, end) = audit.page(older, 100, 1000).unwrap();
        assert_eq!((last.len(), end), (1, None));
    }

    #[test]
    fn lines_are_appended_as_json() {
        let dir = TestDir::new();
        let path = dir.path().join("audit.log");
        let mut audit = Audit::open(&path).unwrap();
        audit
            .record(
                0,
                "alex",
                "192.168.1.20",
                "login",
                Outcome::Allowed,
                "password only",
            )
            .unwrap();
        audit
            .record(
                60,
                "mallory\n{\"forged\":true}",
                "203.0.113.9",
                "login",
                Outcome::Denied,
                "no admin of that name",
            )
            .unwrap();
        let text = std::fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), 2, "{text}");
        let first: serde_json::Value = serde_json::from_str(lines[0]).unwrap();
        assert_eq!(first["time"], "1970-01-01T00:00:00Z");
        assert_eq!(first["actor"], "alex");
        assert_eq!(first["result"], "allowed");
        let second: serde_json::Value = serde_json::from_str(lines[1]).unwrap();
        assert_eq!(second["actor"], "mallory\n{\"forged\":true}");
        assert_eq!(second["result"], "denied");
    }
}
