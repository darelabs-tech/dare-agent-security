use std::{
    fs::{self, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
};

use serde::{Deserialize, Serialize};
use time::{format_description::well_known::Rfc3339, OffsetDateTime};

use crate::{canonical::digest, snapshot::SecurityStateSnapshot, ContinuousError, Result};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TransitionRecord {
    pub baseline_digest: String,
    pub candidate_digest: String,
    pub change_set_digest: String,
    pub plan_digest: String,
    pub recorded_at: String,
}

pub struct SnapshotHistory {
    root: PathBuf,
}

impl SnapshotHistory {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    pub fn append_snapshot(&self, snapshot: &SecurityStateSnapshot) -> Result<PathBuf> {
        snapshot.validate()?;
        let snapshot_digest = snapshot.digest()?;
        let file_name = format!("{}.json", snapshot_digest.replace(':', "-"));
        let path = self.root.join("snapshots").join(file_name);
        write_immutable(&path, &serde_json::to_vec_pretty(snapshot)?)?;
        Ok(path)
    }

    pub fn append_transition(&self, mut record: TransitionRecord) -> Result<PathBuf> {
        if record.recorded_at.is_empty() {
            record.recorded_at = OffsetDateTime::now_utc()
                .format(&Rfc3339)
                .map_err(|error| ContinuousError::Invalid(error.to_string()))?;
        }
        let record_digest = digest(&record)?;
        let path = self
            .root
            .join("transitions")
            .join(format!("{}.json", record_digest.replace(':', "-")));
        write_immutable(&path, &serde_json::to_vec_pretty(&record)?)?;
        Ok(path)
    }
}

fn write_immutable(path: &Path, bytes: &[u8]) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|error| {
            if error.kind() == std::io::ErrorKind::AlreadyExists {
                ContinuousError::SafetyRefusal(format!(
                    "immutable history entry already exists: {}",
                    path.display()
                ))
            } else {
                error.into()
            }
        })?;
    file.write_all(bytes)?;
    Ok(())
}
