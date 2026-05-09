// SPDX-License-Identifier: Apache-2.0

use std::path::{Path, PathBuf};

use ignore::WalkBuilder;

use crate::error::{AuditError, AuditResult};

pub fn discover_skill_manifests(root: &Path) -> AuditResult<Vec<PathBuf>> {
    let mut manifests = Vec::new();

    for entry in WalkBuilder::new(root)
        .hidden(false)
        .parents(true)
        .ignore(true)
        .git_ignore(true)
        .git_global(true)
        .git_exclude(true)
        .build()
    {
        let entry = entry.map_err(|source| AuditError::Walk {
            path: root.to_path_buf(),
            source,
        })?;

        if entry
            .file_type()
            .map(|file_type| file_type.is_file())
            .unwrap_or(false)
            && entry.file_name() == "SKILL.md"
        {
            manifests.push(entry.into_path());
        }
    }

    manifests.sort();
    manifests.dedup();
    Ok(manifests)
}
