// SPDX-License-Identifier: Apache-2.0

use std::path::Path;

use crate::discovery::discover_skill_manifests;
use crate::error::{AuditError, AuditResult};
use crate::model::{
    FindingCategory, FindingLocation, ScanReport, ScanSummary, Severity, SkillArtifactKind,
    SkillFile, SkillFileKind, SkillFinding, SkillGraph, SkillPackage, SkillReference,
};
use crate::parse::parse_skill_manifest;

#[derive(Debug, Clone)]
pub struct ScanOptions {
    pub max_manifest_bytes: u64,
}

impl Default for ScanOptions {
    fn default() -> Self {
        Self {
            max_manifest_bytes: 256 * 1024,
        }
    }
}

pub fn scan_path(root: &Path, options: &ScanOptions) -> AuditResult<ScanReport> {
    let manifests = discover_skill_manifests(root)?;
    let mut packages = Vec::new();
    let mut findings = Vec::new();

    for manifest_path in manifests {
        let content =
            std::fs::read_to_string(&manifest_path).map_err(|source| AuditError::Read {
                path: manifest_path.clone(),
                source,
            })?;
        let skill_root = manifest_path.parent().unwrap_or(root);
        let manifest = parse_skill_manifest(&manifest_path, &content)?;
        let mut graph = SkillGraph {
            references: resolve_references(skill_root, &manifest.links),
            artifacts: discover_artifacts(skill_root),
            files: inventory_artifact_files(skill_root)?,
        };
        graph
            .references
            .sort_by(|left, right| left.target.cmp(&right.target));

        let manifest_display = display_path(root, &manifest_path);
        if manifest.name.is_none() {
            findings.push(structural_finding(
                "SKILL001",
                "Missing skill name",
                "The skill manifest does not declare a name.",
                &manifest_display,
                "Skills without stable names are hard to inventory and compare across hosts.",
                "Add a non-empty `name` field to frontmatter or a clear top-level heading.",
            ));
        }
        if manifest.description.is_none() {
            findings.push(structural_finding(
                "SKILL002",
                "Missing skill description",
                "The skill manifest does not declare a description.",
                &manifest_display,
                "Reviewers and host profiles need a concise behavior statement for the skill.",
                "Add a non-empty `description` field to frontmatter or an opening paragraph.",
            ));
        }
        if content.len() as u64 > options.max_manifest_bytes {
            findings.push(structural_finding(
                "SKILL020",
                "Oversized skill manifest",
                "The SKILL.md file exceeds the recommended manifest size.",
                &manifest_display,
                "Very large manifests are harder to review and may be rejected or truncated by hosts.",
                "Move long reference material into `references/` and link to it from SKILL.md.",
            ));
        }
        for reference in graph
            .references
            .iter()
            .filter(|reference| reference.exists == Some(false))
        {
            findings.push(structural_finding(
                "SKILL010",
                "Broken relative reference",
                &format!("The manifest references `{}`, but the file was not found.", reference.target),
                &manifest_display,
                "Broken references can make a skill behave differently than documented or fail at runtime.",
                "Create the referenced file, update the link, or remove the stale reference.",
            ));
        }

        packages.push(SkillPackage {
            root: display_path(root, skill_root),
            manifest_path: manifest_display,
            manifest,
            graph,
        });
    }

    findings.sort_by(|left, right| {
        left.location
            .path
            .cmp(&right.location.path)
            .then(left.location.line.cmp(&right.location.line))
            .then(left.rule_id.cmp(&right.rule_id))
            .then(left.message.cmp(&right.message))
    });

    let invalid_manifest_count = findings
        .iter()
        .filter(|finding| matches!(finding.rule_id.as_str(), "SKILL001" | "SKILL002"))
        .count();
    let broken_reference_count = findings
        .iter()
        .filter(|finding| finding.rule_id == "SKILL010")
        .count();

    Ok(ScanReport {
        summary: ScanSummary {
            package_count: packages.len(),
            finding_count: findings.len(),
            invalid_manifest_count,
            broken_reference_count,
        },
        packages,
        findings,
    })
}

fn resolve_references(skill_root: &Path, references: &[SkillReference]) -> Vec<SkillReference> {
    references
        .iter()
        .filter(|reference| is_relative_file_reference(&reference.target))
        .map(|reference| {
            let mut resolved = reference.clone();
            resolved.exists = Some(skill_root.join(&reference.target).exists());
            resolved
        })
        .collect()
}

fn is_relative_file_reference(target: &str) -> bool {
    !(target.starts_with("http://")
        || target.starts_with("https://")
        || target.starts_with("mailto:")
        || target.starts_with('#')
        || Path::new(target).is_absolute())
}

fn discover_artifacts(skill_root: &Path) -> Vec<String> {
    ["scripts", "references", "assets"]
        .iter()
        .map(|name| skill_root.join(name))
        .filter(|path| {
            std::fs::symlink_metadata(path)
                .map(|metadata| metadata.file_type().is_dir())
                .unwrap_or(false)
        })
        .map(|path| display_path(skill_root, &path))
        .collect()
}

fn inventory_artifact_files(skill_root: &Path) -> AuditResult<Vec<SkillFile>> {
    let mut files = Vec::new();

    for (name, artifact) in [
        ("scripts", SkillArtifactKind::Scripts),
        ("references", SkillArtifactKind::References),
        ("assets", SkillArtifactKind::Assets),
    ] {
        let artifact_root = skill_root.join(name);
        let metadata =
            match std::fs::symlink_metadata(&artifact_root).map_err(|source| AuditError::Metadata {
                path: artifact_root.clone(),
                source,
            }) {
                Ok(metadata) => metadata,
                Err(AuditError::Metadata { source, .. })
                    if source.kind() == std::io::ErrorKind::NotFound =>
                {
                    continue;
                }
                Err(error) => return Err(error),
            };

        if metadata.is_dir() {
            inventory_directory(skill_root, &artifact_root, artifact, &mut files)?;
        }
    }

    files.sort_by(|left, right| {
        left.path
            .cmp(&right.path)
            .then(left.artifact.cmp(&right.artifact))
            .then(left.kind.cmp(&right.kind))
    });
    Ok(files)
}

fn inventory_directory(
    skill_root: &Path,
    directory: &Path,
    artifact: SkillArtifactKind,
    files: &mut Vec<SkillFile>,
) -> AuditResult<()> {
    let mut entries = std::fs::read_dir(directory)
        .map_err(|source| AuditError::ReadDir {
            path: directory.to_path_buf(),
            source,
        })?
        .map(|entry| {
            entry.map_err(|source| AuditError::ReadDir {
                path: directory.to_path_buf(),
                source,
            })
        })
        .collect::<AuditResult<Vec<_>>>()?;

    entries.sort_by(|left, right| left.path().cmp(&right.path()));

    for entry in entries {
        let path = entry.path();
        let metadata = std::fs::symlink_metadata(&path).map_err(|source| AuditError::Metadata {
            path: path.clone(),
            source,
        })?;
        let kind = file_kind(&metadata);
        files.push(SkillFile {
            path: display_path(skill_root, &path),
            artifact,
            kind,
            size_bytes: if kind == SkillFileKind::Directory {
                0
            } else {
                metadata.len()
            },
            readonly: metadata.permissions().readonly(),
        });

        if kind == SkillFileKind::Directory {
            inventory_directory(skill_root, &path, artifact, files)?;
        }
    }

    Ok(())
}

fn file_kind(metadata: &std::fs::Metadata) -> SkillFileKind {
    let file_type = metadata.file_type();
    if file_type.is_symlink() {
        SkillFileKind::Symlink
    } else if file_type.is_file() {
        SkillFileKind::File
    } else if file_type.is_dir() {
        SkillFileKind::Directory
    } else {
        SkillFileKind::Other
    }
}

fn display_path(root: &Path, path: &Path) -> String {
    path.strip_prefix(root)
        .unwrap_or(path)
        .to_string_lossy()
        .replace('\\', "/")
}

fn structural_finding(
    rule_id: &str,
    title: &str,
    message: &str,
    path: &str,
    rationale: &str,
    remediation: &str,
) -> SkillFinding {
    SkillFinding {
        rule_id: rule_id.to_owned(),
        severity: Severity::Low,
        category: FindingCategory::Spec,
        title: title.to_owned(),
        message: message.to_owned(),
        location: FindingLocation {
            path: path.to_owned(),
            line: None,
        },
        rationale: rationale.to_owned(),
        remediation: remediation.to_owned(),
        suppression: format!(
            "Suppress `{rule_id}` only with a documented reason in the project audit config."
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::TestWorkspace;

    #[test]
    fn scan_reports_valid_manifest_with_references_and_artifacts() {
        let workspace = TestWorkspace::new("scan-valid");
        workspace.write_file(
            "SKILL.md",
            r#"---
name: valid-skill
description: Valid skill fixture.
---

# Valid Skill

Read [local guidance](references/guidance.md), [remote guidance](https://example.test),
and [heading](#valid-skill).
"#,
        );
        workspace.write_file("references/guidance.md", "# Guidance\n");
        workspace.create_dir("scripts");
        workspace.create_dir("assets");

        let report = scan_path(workspace.root(), &ScanOptions::default()).expect("scan path");

        assert_eq!(report.summary.package_count, 1);
        assert_eq!(report.summary.finding_count, 0);
        assert_eq!(report.summary.invalid_manifest_count, 0);
        assert_eq!(report.summary.broken_reference_count, 0);
        assert_eq!(report.packages[0].root, "");
        assert_eq!(report.packages[0].manifest_path, "SKILL.md");
        assert_eq!(
            report.packages[0]
                .graph
                .references
                .iter()
                .map(|reference| (&reference.target, reference.exists))
                .collect::<Vec<_>>(),
            vec![(&"references/guidance.md".to_owned(), Some(true))]
        );
        assert_eq!(
            report.packages[0].graph.artifacts,
            vec!["scripts", "references", "assets"]
        );
        assert_eq!(report.packages[0].graph.files.len(), 1);
        assert_eq!(
            report.packages[0].graph.files[0].path,
            "references/guidance.md"
        );
        assert_eq!(
            report.packages[0].graph.files[0].artifact,
            SkillArtifactKind::References
        );
        assert_eq!(report.packages[0].graph.files[0].kind, SkillFileKind::File);
        assert_eq!(report.packages[0].graph.files[0].size_bytes, 11);
    }

    #[test]
    fn scan_ignores_non_relative_file_references() {
        let workspace = TestWorkspace::new("scan-non-relative-references");
        let absolute_reference = workspace.root().join("outside.md");
        workspace.write_file(
            "SKILL.md",
            &format!(
                r#"---
name: non-relative-references
description: Non-relative reference fixture.
---

# Non Relative References

Use [http](http://example.test), [https](https://example.test),
[mail](mailto:security@example.test), [anchor](#non-relative-references),
and [absolute]({}).
"#,
                absolute_reference.to_string_lossy().replace('\\', "/")
            ),
        );

        let report = scan_path(workspace.root(), &ScanOptions::default()).expect("scan path");

        assert!(report.packages[0].graph.references.is_empty());
        assert!(report.findings.is_empty());
    }

    #[test]
    fn display_path_returns_original_path_when_not_under_root() {
        let root = Path::new("root");
        let outside = Path::new("outside").join("SKILL.md");

        assert_eq!(display_path(root, &outside), "outside/SKILL.md");
    }

    #[test]
    fn reports_skill001_missing_name_with_complete_finding_metadata() {
        let workspace = TestWorkspace::new("scan-skill001");
        workspace.write_file(
            "SKILL.md",
            r#"---
description: Missing name fixture.
---

This manifest has a description but no frontmatter name or heading fallback.
"#,
        );

        let report = scan_path(workspace.root(), &ScanOptions::default()).expect("scan path");

        assert_eq!(report.findings.len(), 1);
        assert_finding(
            &report.findings[0],
            ExpectedFinding {
                rule_id: "SKILL001",
                title: "Missing skill name",
                message: "The skill manifest does not declare a name.",
                path: "SKILL.md",
                rationale:
                    "Skills without stable names are hard to inventory and compare across hosts.",
                remediation:
                    "Add a non-empty `name` field to frontmatter or a clear top-level heading.",
            },
        );
    }

    #[test]
    fn reports_skill002_missing_description_with_complete_finding_metadata() {
        let workspace = TestWorkspace::new("scan-skill002");
        workspace.write_file(
            "SKILL.md",
            r#"---
name: missing-description
---

# Missing Description
"#,
        );

        let report = scan_path(workspace.root(), &ScanOptions::default()).expect("scan path");

        assert_eq!(report.findings.len(), 1);
        assert_finding(
            &report.findings[0],
            ExpectedFinding {
                rule_id: "SKILL002",
                title: "Missing skill description",
                message: "The skill manifest does not declare a description.",
                path: "SKILL.md",
                rationale:
                    "Reviewers and host profiles need a concise behavior statement for the skill.",
                remediation:
                    "Add a non-empty `description` field to frontmatter or an opening paragraph.",
            },
        );
    }

    #[test]
    fn reports_skill010_broken_relative_reference_with_complete_finding_metadata() {
        let workspace = TestWorkspace::new("scan-skill010");
        workspace.write_file(
            "SKILL.md",
            r#"---
name: broken-reference
description: Broken reference fixture.
---

# Broken Reference

Read [missing guidance](references/missing.md).
"#,
        );

        let report = scan_path(workspace.root(), &ScanOptions::default()).expect("scan path");

        assert_eq!(report.findings.len(), 1);
        assert_finding(
            &report.findings[0],
            ExpectedFinding {
                rule_id: "SKILL010",
                title: "Broken relative reference",
                message: "The manifest references `references/missing.md`, but the file was not found.",
                path: "SKILL.md",
                rationale: "Broken references can make a skill behave differently than documented or fail at runtime.",
                remediation: "Create the referenced file, update the link, or remove the stale reference.",
            },
        );
    }

    #[test]
    fn reports_skill020_oversized_manifest_with_complete_finding_metadata() {
        let workspace = TestWorkspace::new("scan-skill020");
        workspace.write_file(
            "SKILL.md",
            r#"---
name: oversized
description: Oversized fixture.
---

# Oversized

This manifest is valid but deliberately longer than the low test threshold.
"#,
        );

        let report = scan_path(
            workspace.root(),
            &ScanOptions {
                max_manifest_bytes: 80,
            },
        )
        .expect("scan path");

        assert_eq!(report.findings.len(), 1);
        assert_finding(
            &report.findings[0],
            ExpectedFinding {
                rule_id: "SKILL020",
                title: "Oversized skill manifest",
                message: "The SKILL.md file exceeds the recommended manifest size.",
                path: "SKILL.md",
                rationale: "Very large manifests are harder to review and may be rejected or truncated by hosts.",
                remediation: "Move long reference material into `references/` and link to it from SKILL.md.",
            },
        );
    }

    #[test]
    fn scan_reports_missing_name_missing_description_broken_reference_and_size() {
        let workspace = TestWorkspace::new("scan-structural-findings");
        workspace.write_file(
            "a-broken-reference/SKILL.md",
            r#"---
name: broken-reference
description: Broken reference fixture.
---

# Broken Reference

Read [missing](references/missing.md).
"#,
        );
        workspace.write_file(
            "b-missing-name/SKILL.md",
            r#"---
description: Missing name fixture.
---

This starts with a paragraph and has no heading fallback.
"#,
        );
        workspace.write_file(
            "c-missing-description/SKILL.md",
            r#"---
name: missing-description
---

# Missing Description
"#,
        );
        workspace.write_file(
            "d-oversized/SKILL.md",
            r#"---
name: oversized
description: Oversized fixture.
---

# Oversized

This content exceeds the deliberately tiny test threshold.
This extra line keeps only this manifest above the test size limit.
This second extra line makes the intended `SKILL020` case unambiguous.
"#,
        );

        let report = scan_path(
            workspace.root(),
            &ScanOptions {
                max_manifest_bytes: 180,
            },
        )
        .expect("scan path");

        let rule_ids = report
            .findings
            .iter()
            .map(|finding| finding.rule_id.as_str())
            .collect::<Vec<_>>();
        assert_eq!(
            rule_ids,
            vec!["SKILL010", "SKILL001", "SKILL002", "SKILL020"]
        );
        assert_eq!(report.summary.package_count, 4);
        assert_eq!(report.summary.finding_count, 4);
        assert_eq!(report.summary.invalid_manifest_count, 2);
        assert_eq!(report.summary.broken_reference_count, 1);

        let broken_reference = &report.findings[0];
        assert_eq!(broken_reference.severity, Severity::Low);
        assert_eq!(broken_reference.category, FindingCategory::Spec);
        assert_eq!(broken_reference.title, "Broken relative reference");
        assert!(broken_reference.message.contains("references/missing.md"));
        assert_eq!(
            broken_reference.location.path,
            "a-broken-reference/SKILL.md"
        );
        assert!(broken_reference.rationale.contains("Broken references"));
        assert!(broken_reference
            .remediation
            .contains("Create the referenced file"));
        assert!(broken_reference.suppression.contains("SKILL010"));
    }

    #[test]
    fn scan_sorts_packages_and_findings_deterministically() {
        let workspace = TestWorkspace::new("scan-deterministic-order");
        workspace.write_file("zeta/SKILL.md", "# Zeta\n");
        workspace.write_file("alpha/SKILL.md", "# Alpha\n");
        workspace.write_file("middle/SKILL.md", "# Middle\n");

        let report = scan_path(workspace.root(), &ScanOptions::default()).expect("scan path");

        assert_eq!(
            report
                .packages
                .iter()
                .map(|package| package.manifest_path.as_str())
                .collect::<Vec<_>>(),
            vec!["alpha/SKILL.md", "middle/SKILL.md", "zeta/SKILL.md"]
        );
        assert_eq!(
            report
                .findings
                .iter()
                .map(finding_sort_tuple)
                .collect::<Vec<_>>(),
            vec![
                (
                    "alpha/SKILL.md",
                    None,
                    "SKILL002",
                    "The skill manifest does not declare a description."
                ),
                (
                    "middle/SKILL.md",
                    None,
                    "SKILL002",
                    "The skill manifest does not declare a description."
                ),
                (
                    "zeta/SKILL.md",
                    None,
                    "SKILL002",
                    "The skill manifest does not declare a description."
                ),
            ]
        );
    }

    #[test]
    fn scan_inventories_artifact_files_recursively_without_top_level_dirs() {
        let workspace = TestWorkspace::new("scan-artifact-files");
        workspace.write_file(
            "SKILL.md",
            r#"---
name: artifact-files
description: Artifact file fixture.
---

# Artifact Files
"#,
        );
        workspace.write_file("scripts/build.ps1", "Write-Output build\n");
        workspace.write_file("scripts/nested/run.sh", "echo run\n");
        workspace.write_file("references/guide.md", "# Guide\n");
        workspace.create_dir("assets/images");

        let report = scan_path(workspace.root(), &ScanOptions::default()).expect("scan path");
        let files = &report.packages[0].graph.files;

        assert_eq!(
            files
                .iter()
                .map(|file| (
                    file.path.as_str(),
                    file.artifact,
                    file.kind,
                    file.size_bytes
                ))
                .collect::<Vec<_>>(),
            vec![
                (
                    "assets/images",
                    SkillArtifactKind::Assets,
                    SkillFileKind::Directory,
                    0
                ),
                (
                    "references/guide.md",
                    SkillArtifactKind::References,
                    SkillFileKind::File,
                    8
                ),
                (
                    "scripts/build.ps1",
                    SkillArtifactKind::Scripts,
                    SkillFileKind::File,
                    19
                ),
                (
                    "scripts/nested",
                    SkillArtifactKind::Scripts,
                    SkillFileKind::Directory,
                    0
                ),
                (
                    "scripts/nested/run.sh",
                    SkillArtifactKind::Scripts,
                    SkillFileKind::File,
                    9
                ),
            ]
        );
        assert!(files
            .iter()
            .all(|file| !matches!(file.path.as_str(), "scripts" | "references" | "assets")));
    }

    #[test]
    fn scan_ignores_top_level_artifact_file() {
        let workspace = TestWorkspace::new("scan-artifact-file");
        workspace.write_file(
            "SKILL.md",
            r#"---
name: artifact-file
description: Artifact file fixture.
---

# Artifact File
"#,
        );
        workspace.write_file("scripts", "not an artifact directory\n");

        let report = scan_path(workspace.root(), &ScanOptions::default()).expect("scan path");

        assert!(report.packages[0].graph.artifacts.is_empty());
        assert!(report.packages[0].graph.files.is_empty());
    }

    #[test]
    fn scan_returns_frontmatter_errors_without_panicking() {
        let workspace = TestWorkspace::new("scan-malformed-frontmatter");
        workspace.write_file(
            "SKILL.md",
            r#"---
name: [unterminated
---

# Malformed
"#,
        );

        let error =
            scan_path(workspace.root(), &ScanOptions::default()).expect_err("scan should fail");

        assert!(matches!(error, AuditError::Frontmatter { .. }));
    }

    #[test]
    fn json_output_uses_relative_paths_and_stable_summary_fields() {
        let workspace = TestWorkspace::new("scan-json-stability");
        workspace.write_file(
            "skill/SKILL.md",
            r#"---
name: json-stability
description: JSON stability fixture.
---

# JSON Stability
"#,
        );

        let report = scan_path(workspace.root(), &ScanOptions::default()).expect("scan path");
        let (json, value) = report_json_value(&report);

        assert_eq!(value["summary"]["package_count"], 1);
        assert_eq!(value["summary"]["finding_count"], 0);
        assert_eq!(value["summary"]["invalid_manifest_count"], 0);
        assert_eq!(value["summary"]["broken_reference_count"], 0);
        assert_eq!(value["packages"][0]["root"], "skill");
        assert_eq!(value["packages"][0]["manifest_path"], "skill/SKILL.md");
        assert_eq!(value["packages"][0]["manifest"]["name"], "json-stability");
        assert_eq!(
            value["packages"][0]["manifest"]["description"],
            "JSON stability fixture."
        );
        assert!(!json_contains_workspace_root(&json, workspace.root()));
        assert!(!json.contains("timestamp"));
        assert!(!json.contains("generated_at"));
    }

    #[test]
    fn json_output_matches_full_pretty_expected_report() {
        let workspace = TestWorkspace::new("scan-json-full-expected-report");
        workspace.write_file("SKILL.md", "# Stable Snapshot\n\nStable description.\n");

        let report = scan_path(workspace.root(), &ScanOptions::default()).expect("scan path");
        let json = serde_json::to_string_pretty(&report).expect("serialize report");

        let expected = r##"{
  "packages": [
    {
      "root": "",
      "manifest_path": "SKILL.md",
      "manifest": {
        "name": "Stable Snapshot",
        "description": "Stable description.",
        "frontmatter": {},
        "body": "# Stable Snapshot\n\nStable description.\n",
        "headings": [
          "Stable Snapshot"
        ],
        "links": [],
        "inline_code": [],
        "code_blocks": [],
        "declared_tools": [],
        "declared_permissions": []
      },
      "graph": {
        "references": [],
        "artifacts": [],
        "files": []
      }
    }
  ],
  "findings": [],
  "summary": {
    "package_count": 1,
    "finding_count": 0,
    "invalid_manifest_count": 0,
    "broken_reference_count": 0
  }
}"##;
        assert_eq!(json, expected);
        assert!(!json_contains_workspace_root(&json, workspace.root()));
    }

    #[test]
    fn json_output_orders_packages_deterministically() {
        let workspace = TestWorkspace::new("scan-json-package-order");
        workspace.write_file(
            ".agents/skills/beta/SKILL.md",
            r#"---
name: beta
description: Beta fixture.
---

# Beta
"#,
        );
        workspace.write_file(
            ".agents/skills/alpha/SKILL.md",
            r#"---
name: alpha
description: Alpha fixture.
---

# Alpha
"#,
        );
        workspace.write_file(
            ".agents/skills/zeta/SKILL.md",
            r#"---
name: zeta
description: Zeta fixture.
---

# Zeta
"#,
        );

        let report = scan_path(workspace.root(), &ScanOptions::default()).expect("scan path");
        let (_json, value) = report_json_value(&report);

        assert_eq!(value["summary"]["package_count"], 3);
        assert_eq!(value["summary"]["finding_count"], 0);
        assert_eq!(
            json_string_array(&value["packages"], "manifest_path"),
            vec![
                ".agents/skills/alpha/SKILL.md",
                ".agents/skills/beta/SKILL.md",
                ".agents/skills/zeta/SKILL.md",
            ]
        );
    }

    #[test]
    fn json_output_orders_findings_deterministically() {
        let workspace = TestWorkspace::new("scan-json-finding-order");
        workspace.write_file(
            "zeta/SKILL.md",
            r#"---
name: zeta
---

# Zeta
"#,
        );
        workspace.write_file(
            "alpha/SKILL.md",
            r#"---
name: alpha
---

# Alpha
"#,
        );
        workspace.write_file(
            "middle/SKILL.md",
            r#"---
name: middle
---

# Middle
"#,
        );

        let report = scan_path(workspace.root(), &ScanOptions::default()).expect("scan path");
        let (_json, value) = report_json_value(&report);

        assert_eq!(value["summary"]["package_count"], 3);
        assert_eq!(value["summary"]["finding_count"], 3);
        assert_eq!(value["summary"]["invalid_manifest_count"], 3);
        assert_eq!(value["summary"]["broken_reference_count"], 0);
        assert_eq!(
            value["findings"]
                .as_array()
                .expect("findings array")
                .iter()
                .map(|finding| (
                    finding["location"]["path"].as_str().expect("path"),
                    finding["rule_id"].as_str().expect("rule id"),
                    finding["message"].as_str().expect("message"),
                ))
                .collect::<Vec<_>>(),
            vec![
                (
                    "alpha/SKILL.md",
                    "SKILL002",
                    "The skill manifest does not declare a description."
                ),
                (
                    "middle/SKILL.md",
                    "SKILL002",
                    "The skill manifest does not declare a description."
                ),
                (
                    "zeta/SKILL.md",
                    "SKILL002",
                    "The skill manifest does not declare a description."
                ),
            ]
        );
    }

    #[test]
    fn json_output_preserves_finding_metadata_and_summary_counts() {
        let workspace = TestWorkspace::new("scan-json-finding-metadata");
        workspace.write_file(
            "a-broken-reference/SKILL.md",
            r#"---
name: broken-reference
description: Broken reference fixture.
---

# Broken Reference

Read [missing](references/missing.md).
"#,
        );
        workspace.write_file(
            "b-missing-name/SKILL.md",
            r#"---
description: Missing name fixture.
---

This starts with a paragraph and has no heading fallback.
"#,
        );
        workspace.write_file(
            "c-missing-description/SKILL.md",
            r#"---
name: missing-description
---

# Missing Description
"#,
        );
        workspace.write_file(
            "d-oversized/SKILL.md",
            r#"---
name: oversized
description: Oversized fixture.
---

# Oversized

This content exceeds the deliberately tiny test threshold.
This extra line keeps only this manifest above the test size limit.
This second extra line makes the intended `SKILL020` case unambiguous.
"#,
        );

        let report = scan_path(
            workspace.root(),
            &ScanOptions {
                max_manifest_bytes: 180,
            },
        )
        .expect("scan path");
        let (_json, value) = report_json_value(&report);

        assert_eq!(value["summary"]["package_count"], 4);
        assert_eq!(value["summary"]["finding_count"], 4);
        assert_eq!(value["summary"]["invalid_manifest_count"], 2);
        assert_eq!(value["summary"]["broken_reference_count"], 1);
        assert_eq!(
            json_string_array(&value["findings"], "rule_id"),
            vec!["SKILL010", "SKILL001", "SKILL002", "SKILL020"]
        );

        let findings = value["findings"].as_array().expect("findings array");
        for finding in findings {
            let object = finding.as_object().expect("finding object");
            for key in [
                "rule_id",
                "severity",
                "category",
                "title",
                "message",
                "location",
                "rationale",
                "remediation",
                "suppression",
            ] {
                assert!(object.contains_key(key), "missing finding key {key}");
            }
            assert_eq!(finding["severity"], "low");
            assert_eq!(finding["category"], "spec");
            assert!(finding["title"].as_str().expect("title").len() > 0);
            assert!(finding["message"].as_str().expect("message").len() > 0);
            assert!(finding["rationale"].as_str().expect("rationale").len() > 0);
            assert!(finding["remediation"].as_str().expect("remediation").len() > 0);
            assert!(finding["suppression"]
                .as_str()
                .expect("suppression")
                .contains(finding["rule_id"].as_str().expect("rule id")));

            let location = finding["location"].as_object().expect("location object");
            assert!(location.contains_key("path"));
            assert!(location.contains_key("line"));
            assert!(finding["location"]["path"]
                .as_str()
                .expect("location path")
                .ends_with("SKILL.md"));
            assert!(finding["location"]["line"].is_null());
        }
    }

    #[test]
    fn json_output_uses_relative_reference_paths_without_local_paths() {
        let workspace = TestWorkspace::new("scan-json-relative-references");
        workspace.write_file(
            "skill/SKILL.md",
            r#"---
name: relative-references
description: Relative references fixture.
---

# Relative References

Read [guidance](references/guidance.md).
"#,
        );
        workspace.write_file("skill/references/guidance.md", "# Guidance\n");
        workspace.create_dir("skill/scripts");
        workspace.create_dir("skill/assets");

        let report = scan_path(workspace.root(), &ScanOptions::default()).expect("scan path");
        let (json, value) = report_json_value(&report);

        assert_eq!(value["summary"]["package_count"], 1);
        assert_eq!(value["summary"]["finding_count"], 0);
        assert_eq!(
            value["packages"][0]["graph"]["references"][0]["target"],
            "references/guidance.md"
        );
        assert_eq!(
            value["packages"][0]["graph"]["references"][0]["exists"],
            true
        );
        assert_eq!(
            value["packages"][0]["graph"]["artifacts"]
                .as_array()
                .expect("artifacts array")
                .iter()
                .map(|artifact| artifact.as_str().expect("artifact"))
                .collect::<Vec<_>>(),
            vec!["scripts", "references", "assets"]
        );
        assert!(!json_contains_workspace_root(&json, workspace.root()));
    }

    #[test]
    fn json_output_workspace_root_detector_matches_escaped_windows_paths() {
        let root = Path::new(r"C:\ws\saas\agent_skill_auditor");

        assert!(json_contains_workspace_root(
            r"C:\ws\saas\agent_skill_auditor\skill\SKILL.md",
            root
        ));
        assert!(json_contains_workspace_root(
            "C:/ws/saas/agent_skill_auditor/skill/SKILL.md",
            root
        ));
        assert!(json_contains_workspace_root(
            r#"{"path":"C:\\ws\\saas\\agent_skill_auditor\\skill\\SKILL.md"}"#,
            root
        ));
    }

    struct ExpectedFinding {
        rule_id: &'static str,
        title: &'static str,
        message: &'static str,
        path: &'static str,
        rationale: &'static str,
        remediation: &'static str,
    }

    fn assert_finding(finding: &SkillFinding, expected: ExpectedFinding) {
        assert_eq!(finding.rule_id, expected.rule_id);
        assert_eq!(finding.severity, Severity::Low);
        assert_eq!(finding.category, FindingCategory::Spec);
        assert_eq!(finding.title, expected.title);
        assert_eq!(finding.message, expected.message);
        assert_eq!(finding.location.path, expected.path);
        assert_eq!(finding.location.line, None);
        assert_eq!(finding.rationale, expected.rationale);
        assert_eq!(finding.remediation, expected.remediation);
        assert_eq!(
            finding.suppression,
            format!(
                "Suppress `{}` only with a documented reason in the project audit config.",
                expected.rule_id
            )
        );
    }

    fn finding_sort_tuple(finding: &SkillFinding) -> (&str, Option<usize>, &str, &str) {
        (
            finding.location.path.as_str(),
            finding.location.line,
            finding.rule_id.as_str(),
            finding.message.as_str(),
        )
    }

    fn report_json_value(report: &ScanReport) -> (String, serde_json::Value) {
        let json = serde_json::to_string_pretty(report).expect("serialize report");
        let value = serde_json::from_str(&json).expect("parse report JSON");
        (json, value)
    }

    fn json_string_array(value: &serde_json::Value, key: &str) -> Vec<String> {
        value
            .as_array()
            .expect("JSON array")
            .iter()
            .map(|item| item[key].as_str().expect("string field").to_owned())
            .collect()
    }

    fn json_contains_workspace_root(json: &str, root: &Path) -> bool {
        let raw_root = root.to_string_lossy().into_owned();
        let normalized_root = raw_root.replace('\\', "/");

        for candidate in [raw_root.as_str(), normalized_root.as_str()] {
            if !candidate.is_empty()
                && (json.contains(candidate) || json.contains(&json_escaped_fragment(candidate)))
            {
                return true;
            }
        }

        false
    }

    fn json_escaped_fragment(value: &str) -> String {
        let escaped = serde_json::to_string(value).expect("escape JSON string");
        escaped
            .strip_prefix('"')
            .and_then(|value| value.strip_suffix('"'))
            .unwrap_or(&escaped)
            .to_owned()
    }
}
