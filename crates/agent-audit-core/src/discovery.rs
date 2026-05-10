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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::TestWorkspace;

    #[test]
    fn discovers_skill_manifests_recursively_in_stable_order() {
        let workspace = TestWorkspace::new("discovery-stable-order");
        workspace.write_file("zeta/SKILL.md", "# Zeta\n");
        workspace.write_file(".agents/skills/agent/SKILL.md", "# Agent\n");
        workspace.write_file(".claude/skills/claude/SKILL.md", "# Claude\n");
        workspace.write_file(".github/skills/github/SKILL.md", "# GitHub\n");
        workspace.write_file("alpha/nested/SKILL.md", "# Alpha\n");
        workspace.write_file("alpha/SKILL.txt", "# Not a manifest\n");

        let manifests = discover_skill_manifests(workspace.root()).expect("discover manifests");
        let relative_paths = manifests
            .iter()
            .map(|path| {
                path.strip_prefix(workspace.root())
                    .expect("manifest under workspace")
                    .to_string_lossy()
                    .replace('\\', "/")
            })
            .collect::<Vec<_>>();

        assert_eq!(
            relative_paths,
            vec![
                ".agents/skills/agent/SKILL.md",
                ".claude/skills/claude/SKILL.md",
                ".github/skills/github/SKILL.md",
                "alpha/nested/SKILL.md",
                "zeta/SKILL.md",
            ]
        );
    }

    #[test]
    fn ignores_directories_and_non_manifest_files_named_differently() {
        let workspace = TestWorkspace::new("discovery-ignores-non-manifests");
        workspace.create_dir("directory-named/SKILL.md");
        workspace.write_file("skill.md", "# Wrong case\n");
        workspace.write_file("docs/SKILL.markdown", "# Wrong extension\n");

        let manifests = discover_skill_manifests(workspace.root()).expect("discover manifests");

        assert!(manifests.is_empty());
    }
}
