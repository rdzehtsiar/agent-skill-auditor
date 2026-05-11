// SPDX-License-Identifier: Apache-2.0

use std::path::{Path, PathBuf};

use crate::error::{AuditError, AuditResult};

pub(crate) fn display_path(root: &Path, path: &Path) -> String {
    path.strip_prefix(root)
        .unwrap_or(path)
        .to_string_lossy()
        .replace('\\', "/")
}

pub(crate) fn filename(path: &Path) -> String {
    path.file_name()
        .map(|filename| filename.to_string_lossy().into_owned())
        .unwrap_or_else(|| path.to_string_lossy().replace('\\', "/"))
}

pub(crate) fn sorted_directory_entries(directory: &Path) -> AuditResult<Vec<PathBuf>> {
    let mut entries = std::fs::read_dir(directory)
        .map_err(|source| AuditError::ReadDir {
            path: directory.to_path_buf(),
            source,
        })?
        .map(|entry| {
            entry
                .map(|entry| entry.path())
                .map_err(|source| AuditError::ReadDir {
                    path: directory.to_path_buf(),
                    source,
                })
        })
        .collect::<AuditResult<Vec<_>>>()?;
    entries.sort();
    Ok(entries)
}

pub(crate) fn collect_skill_package_files(
    skill_root: &Path,
    directory: &Path,
    files: &mut Vec<PathBuf>,
    include_file: &impl Fn(&Path) -> bool,
) -> AuditResult<()> {
    for path in sorted_directory_entries(directory)? {
        let metadata = std::fs::symlink_metadata(&path).map_err(|source| AuditError::Metadata {
            path: path.clone(),
            source,
        })?;

        if metadata.is_dir() {
            if path != skill_root && path.join("SKILL.md").is_file() {
                continue;
            }
            collect_skill_package_files(skill_root, &path, files, include_file)?;
        } else if metadata.is_file() && include_file(&path) {
            files.push(path);
        }
    }

    Ok(())
}
