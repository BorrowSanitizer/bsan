use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Instant;

use ui_test::status_emitter::{RevisionStyle, StatusEmitter, Summary, TestStatus};

type FailedOutput = (PathBuf, Vec<u8>);

#[derive(Default)]
pub struct FixResult {
    pub failed: usize,
    pub aborted: usize,
    pub results: Vec<FailedOutput>,
}

pub struct FixEmitter {
    inner: Box<dyn StatusEmitter>,
    failed: Arc<AtomicUsize>,
    aborted: Arc<AtomicUsize>,
    last_progress: Arc<AtomicU64>,
    start: Instant,
}

struct FixStatus {
    inner: Box<dyn TestStatus>,
    aborted: Arc<AtomicUsize>,
    last_progress: Arc<AtomicU64>,
    start: Instant,
}

impl FixEmitter {
    pub fn new(
        inner: Box<dyn StatusEmitter>,
        failed: Arc<AtomicUsize>,
        aborted: Arc<AtomicUsize>,
        last_progress: Arc<AtomicU64>,
        start: Instant,
    ) -> Self {
        Self { inner, failed, aborted, last_progress, start }
    }
}

impl StatusEmitter for FixEmitter {
    fn register_test(&self, name: PathBuf) -> Box<dyn TestStatus> {
        let status = self.inner.register_test(name);
        Box::new(FixStatus {
            inner: status,
            aborted: Arc::clone(&self.aborted),
            last_progress: Arc::clone(&self.last_progress),
            start: self.start,
        })
    }

    fn finalize(
        &self,
        failed: usize,
        succeeded: usize,
        ignored: usize,
        filtered: usize,
        aborted: bool,
    ) -> Box<dyn Summary> {
        self.failed.store(failed, Ordering::SeqCst);
        let _ = self.inner.finalize(failed, succeeded, ignored, filtered, aborted);
        Box::new(())
    }
}

impl TestStatus for FixStatus {
    fn for_revision(&self, revision: &str, style: RevisionStyle) -> Box<dyn TestStatus> {
        Box::new(FixStatus {
            inner: self.inner.for_revision(revision, style),
            aborted: Arc::clone(&self.aborted),
            last_progress: Arc::clone(&self.last_progress),
            start: self.start,
        })
    }

    fn for_path(&self, path: &Path) -> Box<dyn TestStatus> {
        Box::new(FixStatus {
            inner: self.inner.for_path(path),
            aborted: Arc::clone(&self.aborted),
            last_progress: Arc::clone(&self.last_progress),
            start: self.start,
        })
    }

    fn failed_test<'a>(
        &'a self,
        cmd: &'a str,
        stderr: &'a [u8],
        stdout: &'a [u8],
    ) -> Box<dyn std::fmt::Debug + 'a> {
        self.inner.failed_test(cmd, stderr, stdout)
    }

    fn done(&self, result: &ui_test::test_result::TestResult, aborted: bool) {
        if aborted {
            self.aborted.fetch_add(1, Ordering::SeqCst);
        }
        self.last_progress.store(self.start.elapsed().as_secs(), Ordering::SeqCst);
        self.inner.done(result, aborted);
    }

    fn path(&self) -> &Path {
        self.inner.path()
    }

    fn revision(&self) -> &str {
        self.inner.revision()
    }
}

pub fn kill_descendants(root_pid: i32) {
    let entries = match std::fs::read_dir("/proc") {
        Ok(entries) => entries,
        Err(_) => return,
    };

    for entry in entries.flatten() {
        let pid: i32 = match entry.file_name().to_string_lossy().parse() {
            Ok(pid) => pid,
            Err(_) => continue,
        };
        let stat = match std::fs::read_to_string(entry.path().join("stat")) {
            Ok(stat) => stat,
            Err(_) => continue,
        };
        let rest = match stat.rsplit_once(")") {
            Some((_, rest)) => rest.trim(),
            None => continue,
        };
        let mut parts = rest.split_whitespace();
        let _state = parts.next();
        let ppid: i32 = match parts.next().and_then(|val| val.parse().ok()) {
            Some(ppid) => ppid,
            None => continue,
        };
        if ppid == root_pid && pid != root_pid {
            unsafe {
                libc::kill(pid, libc::SIGKILL);
            }
        }
    }
}
