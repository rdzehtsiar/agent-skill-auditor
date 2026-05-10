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
    fn discovers_skill_manifests_recursively() {
        let workspace = TestWorkspace::new("discovery-recursive");
        workspace.write_file("SKILL.md", "# Root\n");
        workspace.write_file("alpha/SKILL.md", "# Alpha\n");
        workspace.write_file("team/platform/deep-skill/SKILL.md", "# Deep Skill\n");

        assert_eq!(
            relative_manifest_paths(&workspace),
            vec![
                "SKILL.md",
                "alpha/SKILL.md",
                "team/platform/deep-skill/SKILL.md",
            ]
        );
    }

    #[test]
    fn returns_manifest_paths_in_stable_lexicographic_order() {
        let workspace = TestWorkspace::new("discovery-stable-order");
        workspace.write_file("zeta/SKILL.md", "# Zeta\n");
        workspace.write_file("alpha/nested/SKILL.md", "# Alpha\n");
        workspace.write_file("middle/SKILL.md", "# Middle\n");

        assert_eq!(
            relative_manifest_paths(&workspace),
            vec!["alpha/nested/SKILL.md", "middle/SKILL.md", "zeta/SKILL.md",]
        );
    }

    #[test]
    fn discovers_planned_host_path_conventions() {
        let workspace = TestWorkspace::new("discovery-host-paths");
        workspace.write_file(".agents/skills/agent-style/SKILL.md", "# Agent\n");
        workspace.write_file(".claude/skills/claude-style/SKILL.md", "# Claude\n");
        workspace.write_file(".github/skills/github-style/SKILL.md", "# GitHub\n");

        assert_eq!(
            relative_manifest_paths(&workspace),
            vec![
                ".agents/skills/agent-style/SKILL.md",
                ".claude/skills/claude-style/SKILL.md",
                ".github/skills/github-style/SKILL.md",
            ]
        );
    }

    #[test]
    fn ignores_files_not_named_exactly_skill_md() {
        let workspace = TestWorkspace::new("discovery-ignores-non-manifests");
        workspace.write_file("skill.md", "# Wrong case\n");
        workspace.write_file("Skill.md", "# Wrong case\n");
        workspace.write_file("SKILL.MD", "# Wrong extension case\n");
        workspace.write_file("docs/SKILL.markdown", "# Wrong extension\n");
        workspace.write_file("docs/SKILL.md.backup", "# Backup file\n");

        assert!(relative_manifest_paths(&workspace).is_empty());
    }

    #[test]
    fn ignores_directories_named_skill_md() {
        let workspace = TestWorkspace::new("discovery-ignores-directories");
        workspace.create_dir("directory-named/SKILL.md");
        workspace.write_file("valid/SKILL.md", "# Valid\n");

        assert_eq!(relative_manifest_paths(&workspace), vec!["valid/SKILL.md"]);
    }

    fn relative_manifest_paths(workspace: &TestWorkspace) -> Vec<String> {
        discover_skill_manifests(workspace.root())
            .expect("discover manifests")
            .iter()
            .map(|path| {
                path.strip_prefix(workspace.root())
                    .expect("manifest under workspace")
                    .to_string_lossy()
                    .replace('\\', "/")
            })
            .collect()
    }
}
