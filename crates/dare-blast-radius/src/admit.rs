//! File admission (BLUEPRINT AD-04): not a symbolic link, a regular file,
//! within the size bound (read through a hard `take`, so a file that grows
//! after `stat` is still bounded), valid JSON, and no deeper than 64 levels.
use std::{fs, io::Read, path::Path};

use serde_json::Value;

use crate::{
    error::{Refusal, Result},
    limits::MAX_JSON_DEPTH,
};

pub fn depth(value: &Value) -> usize {
    match value {
        Value::Array(items) => 1 + items.iter().map(depth).max().unwrap_or(0),
        Value::Object(map) => 1 + map.values().map(depth).max().unwrap_or(0),
        _ => 0,
    }
}

/// Reads `path` as admitted JSON. `file` names the input in refusals.
pub fn read_admitted(path: &Path, file: &'static str, max_bytes: u64) -> Result<Value> {
    let meta = fs::symlink_metadata(path).map_err(|_| Refusal::Unreadable { file })?;
    if meta.file_type().is_symlink() {
        return Err(Refusal::Symlink { file }.into());
    }
    if !meta.is_file() {
        return Err(Refusal::Unreadable { file }.into());
    }
    let handle = fs::File::open(path).map_err(|_| Refusal::Unreadable { file })?;
    let mut bytes = Vec::new();
    handle
        .take(max_bytes + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| Refusal::Unreadable { file })?;
    if bytes.len() as u64 > max_bytes {
        return Err(Refusal::TooLarge { file }.into());
    }
    let value: Value =
        serde_json::from_slice(&bytes).map_err(|_| Refusal::InvalidDocument { file })?;
    if depth(&value) > MAX_JSON_DEPTH {
        return Err(Refusal::TooDeep { file }.into());
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::BlastError;

    fn refusal(result: Result<Value>) -> Refusal {
        match result {
            Err(BlastError::Refused(r)) => r,
            other => panic!("expected a refusal, got {other:?}"),
        }
    }

    #[test]
    fn a_valid_file_is_admitted() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("g.json");
        fs::write(&path, br#"{"a":[1,{"b":2}]}"#).unwrap();
        assert_eq!(read_admitted(&path, "graph", 100).unwrap()["a"][0], 1);
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
                refusal(read_admitted(&link, "graph", 100)),
                Refusal::Symlink { file: "graph" }
            );
        }
        let big = dir.path().join("big.json");
        fs::write(&big, vec![b' '; 101]).unwrap();
        assert_eq!(
            refusal(read_admitted(&big, "graph", 100)),
            Refusal::TooLarge { file: "graph" }
        );
        fs::write(&big, vec![b' '; 100]).unwrap();
        assert_eq!(
            refusal(read_admitted(&big, "graph", 100)),
            Refusal::InvalidDocument { file: "graph" },
            "exactly at the limit is read, then refused as not JSON"
        );
        let deep = dir.path().join("deep.json");
        let text = format!("{}{}", "[".repeat(65), "]".repeat(65));
        fs::write(&deep, text).unwrap();
        assert_eq!(
            refusal(read_admitted(&deep, "scenario", 1 << 20)),
            Refusal::TooDeep { file: "scenario" }
        );
        let ok_deep = format!("{}{}", "[".repeat(64), "]".repeat(64));
        fs::write(&deep, ok_deep).unwrap();
        assert!(read_admitted(&deep, "scenario", 1 << 20).is_ok());
        let bad = dir.path().join("bad.json");
        fs::write(&bad, [0xff, 0xfe]).unwrap();
        assert_eq!(
            refusal(read_admitted(&bad, "graph", 100)),
            Refusal::InvalidDocument { file: "graph" }
        );
        assert_eq!(
            refusal(read_admitted(
                &dir.path().join("missing.json"),
                "graph",
                100
            )),
            Refusal::Unreadable { file: "graph" }
        );
        assert_eq!(
            refusal(read_admitted(dir.path(), "graph", 100)),
            Refusal::Unreadable { file: "graph" }
        );
    }
}
