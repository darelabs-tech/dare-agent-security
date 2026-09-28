//! File admission (BLUEPRINT §4.4 rule 3).
//!
//! Every file is checked in this order: not a symbolic link, resolves under
//! its directory, within the size bound (read through a hard `take` so a file
//! that grows after `stat` is still bounded), parses as JSON, and nests no
//! deeper than the depth bound. Engine-specific validation follows in the
//! caller.
use std::{
    fs,
    io::Read,
    path::{Path, PathBuf},
};

use serde_json::Value;

use crate::{
    error::{Refusal, Result},
    limits::{MAX_FILE_BYTES, MAX_JSON_DEPTH},
};

/// An admitted artifact directory: exists, is a directory, is not a link.
#[derive(Debug, Clone)]
pub struct AdmittedDir {
    pub index: usize,
    pub root: PathBuf,
}

pub fn admit_dir(index: usize, dir: &Path) -> Result<AdmittedDir> {
    let meta = fs::symlink_metadata(dir).map_err(|_| Refusal::NotADirectory { index })?;
    if meta.file_type().is_symlink() {
        return Err(Refusal::Symlink {
            index,
            file: "artifact directory",
        }
        .into());
    }
    if !meta.is_dir() {
        return Err(Refusal::NotADirectory { index }.into());
    }
    let root = dir
        .canonicalize()
        .map_err(|_| Refusal::NotADirectory { index })?;
    Ok(AdmittedDir { index, root })
}

impl AdmittedDir {
    /// Whether `relative` exists as a directory entry (without following a
    /// final symbolic link).
    pub fn has(&self, relative: &str) -> bool {
        fs::symlink_metadata(self.root.join(relative)).is_ok()
    }

    fn resolve(&self, relative: &str, file: &'static str) -> Result<PathBuf> {
        let index = self.index;
        let path = self.root.join(relative);
        let meta = fs::symlink_metadata(&path)
            .map_err(|_| Refusal::MissingInput { index, input: file })?;
        if meta.file_type().is_symlink() {
            return Err(Refusal::Symlink { index, file }.into());
        }
        let resolved = path
            .canonicalize()
            .map_err(|_| Refusal::MissingInput { index, input: file })?;
        if !resolved.starts_with(&self.root) {
            return Err(Refusal::PathEscape { index, file }.into());
        }
        Ok(resolved)
    }

    /// Reads a file under the size bound and returns its bytes.
    pub fn read_bytes(&self, relative: &str, file: &'static str) -> Result<Vec<u8>> {
        let index = self.index;
        let path = self.resolve(relative, file)?;
        if !path.is_file() {
            return Err(Refusal::InvalidDocument {
                index,
                file,
                reason: "not a regular file",
            }
            .into());
        }
        let handle =
            fs::File::open(&path).map_err(|_| Refusal::MissingInput { index, input: file })?;
        let mut bytes = Vec::new();
        handle
            .take(MAX_FILE_BYTES + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| Refusal::InvalidDocument {
                index,
                file,
                reason: "unreadable",
            })?;
        if bytes.len() as u64 > MAX_FILE_BYTES {
            return Err(Refusal::FileTooLarge { index, file }.into());
        }
        Ok(bytes)
    }

    /// Reads a file and parses it as depth-bounded JSON.
    pub fn read_json(&self, relative: &str, file: &'static str) -> Result<(Vec<u8>, Value)> {
        let bytes = self.read_bytes(relative, file)?;
        let value = parse_json(self.index, file, &bytes)?;
        Ok((bytes, value))
    }

    /// Lists the regular files directly under `relative`, sorted, refusing
    /// links and nested directories.
    pub fn list_files(&self, relative: &str, file: &'static str) -> Result<Vec<String>> {
        let index = self.index;
        let dir = self.resolve(relative, file)?;
        let mut names = Vec::new();
        let entries =
            fs::read_dir(&dir).map_err(|_| Refusal::MissingInput { index, input: file })?;
        for entry in entries {
            let entry = entry.map_err(|_| Refusal::MissingInput { index, input: file })?;
            let kind = entry
                .file_type()
                .map_err(|_| Refusal::MissingInput { index, input: file })?;
            if kind.is_symlink() {
                return Err(Refusal::Symlink { index, file }.into());
            }
            if !kind.is_file() {
                return Err(Refusal::InvalidDocument {
                    index,
                    file,
                    reason: "contains a non-file entry",
                }
                .into());
            }
            let name = entry
                .file_name()
                .into_string()
                .map_err(|_| Refusal::InvalidDocument {
                    index,
                    file,
                    reason: "non-UTF-8 file name",
                })?;
            names.push(name);
        }
        names.sort();
        Ok(names)
    }
}

pub fn parse_json(index: usize, file: &'static str, bytes: &[u8]) -> Result<Value> {
    let value: Value = serde_json::from_slice(bytes).map_err(|_| Refusal::InvalidDocument {
        index,
        file,
        reason: "not JSON",
    })?;
    if depth(&value) > MAX_JSON_DEPTH {
        return Err(Refusal::TooDeep { index, file }.into());
    }
    Ok(value)
}

/// Nesting depth, computed iteratively so a hostile document cannot overflow
/// the stack while being measured.
pub fn depth(value: &Value) -> usize {
    let mut deepest = 0;
    let mut stack = vec![(value, 1usize)];
    while let Some((current, level)) = stack.pop() {
        deepest = deepest.max(level);
        match current {
            Value::Array(items) => stack.extend(items.iter().map(|item| (item, level + 1))),
            Value::Object(map) => stack.extend(map.values().map(|item| (item, level + 1))),
            _ => {}
        }
    }
    deepest
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::AttackPathError;

    fn refusal<T: std::fmt::Debug>(result: Result<T>) -> Refusal {
        match result {
            Err(AttackPathError::Refused(r)) => r,
            other => panic!("expected a refusal, got {other:?}"),
        }
    }

    fn nested(levels: usize) -> String {
        format!("{}{}", "[".repeat(levels), "]".repeat(levels))
    }

    #[test]
    fn depth_is_counted_per_level() {
        assert_eq!(depth(&serde_json::json!(1)), 1);
        assert_eq!(depth(&serde_json::json!({"a": [1]})), 3);
        let value: Value = serde_json::from_str(&nested(64)).unwrap();
        assert_eq!(depth(&value), 64);
    }

    #[test]
    fn admission_refuses_links_escapes_oversize_and_depth() {
        let outside = tempfile::tempdir().unwrap();
        std::fs::write(outside.path().join("secret.json"), "{}").unwrap();
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        std::fs::write(root.join("ok.json"), r#"{"a":1}"#).unwrap();
        std::fs::write(root.join("deep.json"), nested(65)).unwrap();
        std::fs::write(root.join("broken.json"), "{").unwrap();
        let big = std::fs::File::create(root.join("big.json")).unwrap();
        big.set_len(MAX_FILE_BYTES + 1).unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink(outside.path().join("secret.json"), root.join("link.json"))
            .unwrap();
        std::fs::create_dir(root.join("inputs")).unwrap();

        let admitted = admit_dir(3, root).unwrap();
        assert!(admitted.read_json("ok.json", "result").is_ok());
        assert_eq!(
            refusal(admitted.read_json("deep.json", "result")),
            Refusal::TooDeep {
                index: 3,
                file: "result"
            }
        );
        assert_eq!(
            refusal(admitted.read_json("big.json", "result")),
            Refusal::FileTooLarge {
                index: 3,
                file: "result"
            }
        );
        assert!(matches!(
            refusal(admitted.read_json("broken.json", "result")),
            Refusal::InvalidDocument {
                reason: "not JSON",
                ..
            }
        ));
        #[cfg(unix)]
        assert_eq!(
            refusal(admitted.read_json("link.json", "scenario")),
            Refusal::Symlink {
                index: 3,
                file: "scenario"
            }
        );
        assert_eq!(
            refusal(admitted.read_json("../x.json", "scenario")),
            Refusal::MissingInput {
                index: 3,
                input: "scenario"
            }
        );
        assert!(matches!(
            refusal(admitted.read_json("inputs", "scenario")),
            Refusal::InvalidDocument { .. }
        ));
    }

    #[cfg(unix)]
    #[test]
    fn a_path_through_a_linked_directory_that_leaves_the_root_is_refused() {
        let outside = tempfile::tempdir().unwrap();
        std::fs::write(outside.path().join("scenario.json"), "{}").unwrap();
        let dir = tempfile::tempdir().unwrap();
        std::os::unix::fs::symlink(outside.path(), dir.path().join("inputs")).unwrap();
        let admitted = admit_dir(0, dir.path()).unwrap();
        assert_eq!(
            refusal(admitted.read_json("inputs/scenario.json", "scenario")),
            Refusal::PathEscape {
                index: 0,
                file: "scenario"
            }
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_linked_artifact_directory_is_refused() {
        let real = tempfile::tempdir().unwrap();
        let holder = tempfile::tempdir().unwrap();
        let link = holder.path().join("artifacts");
        std::os::unix::fs::symlink(real.path(), &link).unwrap();
        assert!(matches!(
            refusal(admit_dir(1, &link)),
            Refusal::Symlink { index: 1, .. }
        ));
        assert_eq!(
            refusal(admit_dir(2, &holder.path().join("absent"))),
            Refusal::NotADirectory { index: 2 }
        );
    }
}
