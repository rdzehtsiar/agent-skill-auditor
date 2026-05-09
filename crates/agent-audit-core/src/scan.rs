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
