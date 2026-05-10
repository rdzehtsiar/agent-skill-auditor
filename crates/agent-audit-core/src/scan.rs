// SPDX-License-Identifier: Apache-2.0

use std::path::Path;

use crate::discovery::discover_skill_manifests;
use crate::error::{AuditError, AuditResult};
use crate::model::{
    FindingCategory, FindingLocation, ScanReport, ScanSummary, Severity, SkillFinding, SkillGraph,
    SkillPackage, SkillReference,
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
        .filter(|path| path.exists())
        .map(|path| display_path(skill_root, &path))
        .collect()
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
                .map(|finding| finding.location.path.as_str())
                .collect::<Vec<_>>(),
            vec!["alpha/SKILL.md", "middle/SKILL.md", "zeta/SKILL.md"]
        );
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
        let json = serde_json::to_string_pretty(&report).expect("serialize report");

        assert!(json.contains("\"manifest_path\": \"skill/SKILL.md\""));
        assert!(json.contains("\"package_count\": 1"));
        assert!(json.contains("\"finding_count\": 0"));
        assert!(!json.contains(&workspace.root().to_string_lossy().to_string()));
        assert!(!json.contains("timestamp"));
    }
}
