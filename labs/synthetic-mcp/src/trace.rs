//! Thread-safe JSON-RPC method-name capture.
//!
//! Traces store method names only. Arguments, headers, and credential-like
//! values must never be recorded.

use std::sync::{Arc, Mutex, OnceLock};

/// In-memory log of received JSON-RPC method names.
#[derive(Clone, Debug, Default)]
pub struct MethodTrace {
    methods: Arc<Mutex<Vec<String>>>,
}

impl MethodTrace {
    /// Empty trace.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a JSON-RPC method name. Values that look like secrets are dropped.
    pub fn record(&self, method: &str) {
        if method.is_empty() || looks_like_secret(method) {
            return;
        }
        lock_methods(&self.methods).push(method.to_owned());
        if Arc::ptr_eq(&self.methods, &global_trace().methods) {
            persist_trace_file(&self.snapshot());
        }
    }

    /// Snapshot of recorded method names, in receive order.
    #[must_use]
    pub fn snapshot(&self) -> Vec<String> {
        lock_methods(&self.methods).clone()
    }

    /// Forget previously recorded names.
    pub fn clear(&self) {
        lock_methods(&self.methods).clear();
    }
}

fn lock_methods(methods: &Mutex<Vec<String>>) -> std::sync::MutexGuard<'_, Vec<String>> {
    match methods.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

fn looks_like_secret(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    lower.contains("sk_live_")
        || lower.contains("bearer ")
        || lower.contains("api_key")
        || lower.contains("-----begin")
}

static GLOBAL_TRACE: OnceLock<MethodTrace> = OnceLock::new();

pub(crate) fn global_trace() -> &'static MethodTrace {
    GLOBAL_TRACE.get_or_init(MethodTrace::new)
}

/// Process-wide dump of recorded method names for tests and helpers.
#[must_use]
pub fn method_trace() -> Vec<String> {
    global_trace().snapshot()
}

/// Clear the process-wide method trace.
pub fn reset_method_trace() {
    global_trace().clear();
    persist_trace_file(&[]);
}

/// Environment variable naming a file that receives recorded method names.
pub const TRACE_PATH_ENV: &str = "SYNTHETIC_MCP_TRACE_PATH";

/// Write the process-wide snapshot to [`TRACE_PATH_ENV`] when that variable is set.
pub fn flush_trace_file() {
    persist_trace_file(&global_trace().snapshot());
}

fn persist_trace_file(methods: &[String]) {
    let Ok(path) = std::env::var(TRACE_PATH_ENV) else {
        return;
    };
    if path.trim().is_empty() {
        return;
    }
    write_trace_file(&path, methods);
}

fn write_trace_file(path: &str, methods: &[String]) {
    let body = match serde_json::to_string(methods) {
        Ok(json) => json,
        Err(_) => methods.join("\n"),
    };
    let target = std::path::Path::new(path);
    if let Some(parent) = target.parent() {
        let _ = std::fs::create_dir_all(parent);
    }

    // Write a sibling file and rename it over the target, so a reader never
    // sees a half-written dump. Truncating the target in place left a window
    // in which it existed but was empty, and the discovery adapter kills this
    // process on drop: a kill inside that window used to leave a permanently
    // empty dump that no amount of reader retrying could recover.
    let Some(scratch) = scratch_path(target) else {
        return;
    };
    if write_all_synced(&scratch, body.as_bytes()).is_err()
        || std::fs::rename(&scratch, target).is_err()
    {
        let _ = std::fs::remove_file(&scratch);
    }
}

/// A sibling of `target`, unique per process and per write.
fn scratch_path(target: &std::path::Path) -> Option<std::path::PathBuf> {
    use std::sync::atomic::{AtomicU64, Ordering};
    static WRITES: AtomicU64 = AtomicU64::new(0);

    let name = target.file_name()?.to_string_lossy().into_owned();
    let mut scratch = target.to_path_buf();
    scratch.set_file_name(format!(
        "{name}.tmp-{}-{}",
        std::process::id(),
        WRITES.fetch_add(1, Ordering::Relaxed)
    ));
    Some(scratch)
}

fn write_all_synced(path: &std::path::Path, body: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    let mut file = std::fs::File::create(path)?;
    file.write_all(body)?;
    file.sync_all()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secrets_are_not_recorded() {
        let trace = MethodTrace::new();
        trace.record("tools/list");
        trace.record("sk_live_PLANTED_SECRET_VALUE_9f3a");
        trace.record("Bearer sk_live_PLANTED_SECRET_VALUE_9f3a");
        let names = trace.snapshot();
        assert_eq!(names, ["tools/list"]);
        assert!(!names.iter().any(|name| name.contains("sk_live_")));
    }

    #[test]
    fn non_loopback_http_bind_is_refused() {
        let err = crate::parse_loopback_bind("0.0.0.0:0").expect_err("non-loopback");
        assert!(err.contains("loopback"));
        crate::parse_loopback_bind("127.0.0.1:0").expect("loopback");
    }

    #[test]
    fn trace_file_contains_method_names_only() {
        let path = std::env::temp_dir().join(format!(
            "synthetic-mcp-trace-unit-{}.json",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("time")
                .as_nanos()
        ));
        write_trace_file(
            path.to_str().expect("utf8 path"),
            &["tools/list".to_owned(), "server/discover".to_owned()],
        );
        let dumped = std::fs::read_to_string(&path).expect("trace file");
        let methods: Vec<String> = serde_json::from_str(&dumped).expect("json array");
        assert_eq!(methods, ["tools/list", "server/discover"]);
        assert!(!dumped.contains("sk_live_"));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn a_reader_never_observes_a_partial_trace_file() {
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::sync::Arc;

        let path = std::env::temp_dir().join(format!(
            "synthetic-mcp-trace-atomic-{}.json",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("time")
                .as_nanos()
        ));
        let target = path.to_str().expect("utf8 path").to_owned();
        let methods: Vec<String> = (0..64).map(|i| format!("tools/list-{i}")).collect();
        write_trace_file(&target, &methods);

        // Rewriting the dump used to truncate it in place, so a reader could
        // successfully read a file that was momentarily empty. Replacing it by
        // rename means every successful read sees one complete snapshot.
        let done = Arc::new(AtomicBool::new(false));
        let writer = std::thread::spawn({
            let target = target.clone();
            let methods = methods.clone();
            let done = Arc::clone(&done);
            move || {
                for _ in 0..300 {
                    write_trace_file(&target, &methods);
                }
                done.store(true, Ordering::Release);
            }
        });

        let mut reads = 0_u32;
        while !done.load(Ordering::Acquire) || reads < 1 {
            // A transient open failure is allowed; a successful read is not
            // allowed to return an empty or truncated dump.
            if let Ok(raw) = std::fs::read_to_string(&path) {
                assert!(
                    !raw.trim().is_empty(),
                    "reader observed an empty trace file at {}",
                    path.display()
                );
                let seen: Vec<String> =
                    serde_json::from_str(&raw).expect("every successful read is complete json");
                assert_eq!(seen, methods, "reader observed a partial dump");
                reads += 1;
            }
        }
        writer.join().expect("writer thread");
        assert!(reads > 0, "the reader never managed a read");

        let _ = std::fs::remove_file(&path);
    }
}
