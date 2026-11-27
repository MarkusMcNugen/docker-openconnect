//! Running the tools the helper drives, occtl and ocpasswd: never through a
//! shell, with the input written and both outputs read as they come so no
//! pipe fills, and stopped when they run past a time limit.

use std::io::{Read, Write};
use std::process::{Child, ChildStderr, ChildStdout, Command, ExitStatus, Stdio};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

/// How long one command may take before it counts as failed.
const TIMEOUT: Duration = Duration::from_secs(10);

/// How often a running command is checked for having finished.
const POLL: Duration = Duration::from_millis(20);

/// What a command printed, and how it ended.
pub struct Ran {
    pub status: ExitStatus,
    pub stdout: String,
    pub stderr: String,
}

impl Ran {
    /// A description of a failed command for an error message: `what`, the
    /// exit status, and everything it printed.
    pub fn failed(&self, what: &str) -> String {
        format!(
            "{what} ({}): {} {}",
            self.status,
            self.stdout.trim(),
            self.stderr.trim()
        )
    }
}

/// Runs `program` with `args`, writes `input` to its standard input and
/// closes it, and waits for it to end, stopping it after TIMEOUT.
pub fn run(program: &str, args: &[&str], input: &[u8]) -> Result<Ran, String> {
    let mut child = Command::new(program)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| format!("{program} could not start: {error}"))?;
    let stdout = read_in_background(program, child.stdout.take(), "standard output")?;
    let stderr = read_in_background(program, child.stderr.take(), "standard error")?;
    let written = match child.stdin.take() {
        Some(mut stdin) => stdin
            .write_all(input)
            .map_err(|error| format!("{program}'s standard input could not be written: {error}")),
        None => Err(format!("{program} has no standard input")),
    };
    let status = wait(program, &mut child)?;
    written?;
    Ok(Ran {
        status,
        stdout: joined(stdout)?,
        stderr: joined(stderr)?,
    })
}

fn wait(program: &str, child: &mut Child) -> Result<ExitStatus, String> {
    let deadline = Instant::now() + TIMEOUT;
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return Ok(status),
            Ok(None) if Instant::now() < deadline => thread::sleep(POLL),
            Ok(None) => {
                let outcome = match child.kill().and_then(|()| child.wait()) {
                    Ok(status) => format!("and was stopped ({status})"),
                    Err(error) => format!("and could not be stopped: {error}"),
                };
                return Err(format!(
                    "{program} did not finish within {} seconds {outcome}",
                    TIMEOUT.as_secs()
                ));
            }
            Err(error) => return Err(format!("{program} could not be waited for: {error}")),
        }
    }
}

trait Pipe: Read + Send + 'static {}
impl Pipe for ChildStdout {}
impl Pipe for ChildStderr {}

fn read_in_background(
    program: &str,
    pipe: Option<impl Pipe>,
    name: &'static str,
) -> Result<JoinHandle<Result<String, String>>, String> {
    let mut pipe = pipe.ok_or_else(|| format!("{program} has no {name}"))?;
    let owner = program.to_owned();
    thread::Builder::new()
        .name(format!("{program} {name}"))
        .spawn(move || {
            let mut text = String::new();
            pipe.read_to_string(&mut text)
                .map_err(|error| format!("{owner}'s {name} could not be read: {error}"))?;
            Ok(text)
        })
        .map_err(|error| format!("a thread to read {program}'s {name} could not start: {error}"))
}

fn joined(reader: JoinHandle<Result<String, String>>) -> Result<String, String> {
    reader
        .join()
        .map_err(|panic| format!("a thread reading a command's output failed: {panic:?}"))?
}
