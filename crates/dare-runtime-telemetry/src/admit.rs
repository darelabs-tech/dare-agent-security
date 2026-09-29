//! File admission (BLUEPRINT §6.1): not a symbolic link, a regular file,
//! within the size bound (read through a hard `take`, so a file that grows
//! after `stat` is still bounded), within the run's total, valid JSON, and no
//! deeper than 64 levels.
use std::{fs, io::Read, path::Path};

use serde_json::Value;

use crate::{
    error::{Input, Refusal, Result},
    limits::{MAX_JSON_DEPTH, MAX_TOTAL_BYTES},
};

pub fn depth(value: &Value) -> usize {
    match value {
        Value::Array(items) => 1 + items.iter().map(depth).max().unwrap_or(0),
        Value::Object(map) => 1 + map.values().map(depth).max().unwrap_or(0),
        _ => 0,
    }
}

/// Reads the bytes of `path`, at most `max_bytes`.
pub fn read_bytes(path: &Path, input: Input, max_bytes: u64) -> Result<Vec<u8>> {
    let meta = fs::symlink_metadata(path).map_err(|_| Refusal::Unreadable { input })?;
    if meta.file_type().is_symlink() {
        return Err(Refusal::Symlink { input }.into());
    }
    if !meta.is_file() {
        return Err(Refusal::Unreadable { input }.into());
    }
    let handle = fs::File::open(path).map_err(|_| Refusal::Unreadable { input })?;
    let mut bytes = Vec::new();
    handle
        .take(max_bytes + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| Refusal::Unreadable { input })?;
    if bytes.len() as u64 > max_bytes {
        return Err(Refusal::TooLarge { input }.into());
    }
    Ok(bytes)
}

/// Parses admitted bytes as JSON of bounded depth.
pub fn parse_admitted(bytes: &[u8], input: Input) -> Result<Value> {
    let value: Value = serde_json::from_slice(bytes).map_err(|_| match input {
        Input::Trace(_) => Refusal::InvalidTrace {
            input,
            reason: "json",
        },
        Input::Policy => Refusal::InvalidPolicy { reason: "json" },
    })?;
    if depth(&value) > MAX_JSON_DEPTH {
        return Err(Refusal::TooDeep { input }.into());
    }
    Ok(value)
}

/// Keeps the running total of trace bytes within `MAX_TOTAL_BYTES`.
#[derive(Debug, Default)]
pub struct TotalBudget(u64);

impl TotalBudget {
    pub fn charge(&mut self, bytes: usize) -> Result<()> {
        self.0 = self.0.saturating_add(bytes as u64);
        if self.0 > MAX_TOTAL_BYTES {
            return Err(Refusal::TotalTooLarge.into());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::TelemetryError;

    fn refusal<T: std::fmt::Debug>(result: Result<T>) -> Refusal {
        match result {
            Err(TelemetryError::Refused(r)) => r,
            other => panic!("expected a refusal, got {other:?}"),
        }
    }

    const T0: Input = Input::Trace(0);

    #[test]
    fn a_valid_file_is_admitted() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("t.json");
        fs::write(&path, br#"{"resourceSpans":[]}"#).unwrap();
        let bytes = read_bytes(&path, T0, 100).unwrap();
        assert!(parse_admitted(&bytes, T0).unwrap()["resourceSpans"].is_array());
    }

    #[test]
    fn admission_refuses_links_size_depth_and_garbage() {
        let dir = tempfile::tempdir().unwrap();
        let real = dir.path().join("real.json");
        fs::write(&real, b"{}").unwrap();
        #[cfg(unix)]
        {
            let link = dir.path().join("link.json");
            std::os::unix::fs::symlink(&real, &link).unwrap();
            assert_eq!(
                refusal(read_bytes(&link, T0, 100)),
                Refusal::Symlink { input: T0 }
            );
        }
        let big = dir.path().join("big.json");
        fs::write(&big, vec![b' '; 101]).unwrap();
        assert_eq!(
            refusal(read_bytes(&big, T0, 100)),
            Refusal::TooLarge { input: T0 }
        );
        fs::write(&big, vec![b' '; 100]).unwrap();
        assert!(read_bytes(&big, T0, 100).is_ok(), "exactly at the limit");
        let deep = format!("{}{}", "[".repeat(65), "]".repeat(65));
        assert_eq!(
            refusal(parse_admitted(deep.as_bytes(), T0)),
            Refusal::TooDeep { input: T0 }
        );
        let ok_deep = format!("{}{}", "[".repeat(64), "]".repeat(64));
        assert!(parse_admitted(ok_deep.as_bytes(), T0).is_ok());
        assert_eq!(
            refusal(parse_admitted(&[0xff, 0xfe], T0)),
            Refusal::InvalidTrace {
                input: T0,
                reason: "json"
            }
        );
        assert_eq!(
            refusal(parse_admitted(b"{", Input::Policy)),
            Refusal::InvalidPolicy { reason: "json" }
        );
        assert_eq!(
            refusal(read_bytes(&dir.path().join("missing.json"), T0, 100)),
            Refusal::Unreadable { input: T0 }
        );
        assert_eq!(
            refusal(read_bytes(dir.path(), T0, 100)),
            Refusal::Unreadable { input: T0 }
        );
    }

    #[test]
    fn the_total_budget_refuses_one_byte_over() {
        let mut total = TotalBudget::default();
        total.charge((MAX_TOTAL_BYTES - 1) as usize).unwrap();
        total.charge(1).unwrap();
        assert_eq!(refusal(total.charge(1)), Refusal::TotalTooLarge);
    }
}
