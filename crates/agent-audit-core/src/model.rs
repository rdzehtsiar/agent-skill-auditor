// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeMap;

use agent_audit_hosts::ProfileCompatibilityResult;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanReport {
    pub packages: Vec<SkillPackage>,
    pub findings: Vec<SkillFinding>,
    pub suppressed_findings: Vec<SuppressedFinding>,
    pub summary: ScanSummary,
    #[serde(default, skip_serializing_if = "CompatibilityMatrix::is_empty")]
    pub compatibility: CompatibilityMatrix,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompatibilityMatrix {
    pub profiles: Vec<String>,
    pub matrix: Vec<SkillCompatibilityRow>,
}

impl CompatibilityMatrix {
    pub fn is_empty(&self) -> bool {
        self.profiles.is_empty() && self.matrix.is_empty()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SkillCompatibilityRow {
    pub path: String,
    pub name: Option<String>,
    pub profiles: Vec<ProfileCompatibilityResult>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanSummary {
    pub package_count: usize,
    pub finding_count: usize,
    pub suppressed_finding_count: usize,
    pub invalid_manifest_count: usize,
    pub broken_reference_count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SkillPackage {
    pub root: String,
    pub manifest_path: String,
    pub manifest: SkillManifest,
    pub graph: SkillGraph,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SkillManifest {
    pub name: Option<String>,
    pub description: Option<String>,
    pub frontmatter: BTreeMap<String, serde_yaml::Value>,
    pub body: String,
    pub headings: Vec<String>,
    pub links: Vec<SkillReference>,
    pub inline_code: Vec<String>,
    pub code_blocks: Vec<MarkdownCodeBlock>,
    pub declared_tools: Vec<String>,
    pub declared_permissions: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SkillGraph {
    pub references: Vec<SkillReference>,
    pub artifacts: Vec<String>,
    pub files: Vec<SkillFile>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SkillFile {
    pub path: String,
    pub artifact: SkillArtifactKind,
    pub kind: SkillFileKind,
    pub size_bytes: u64,
    pub readonly: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SkillArtifactKind {
    Scripts,
    References,
    Assets,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SkillFileKind {
    File,
    Directory,
    Symlink,
    Other,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SkillReference {
    pub target: String,
    pub line: Option<usize>,
    pub exists: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MarkdownCodeBlock {
    pub language: Option<String>,
    pub content: String,
    pub line: Option<usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SkillFinding {
    pub rule_id: String,
    pub severity: Severity,
    pub category: FindingCategory,
    pub title: String,
    pub message: String,
    pub location: FindingLocation,
    pub rationale: String,
    pub remediation: String,
    pub suppression: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FindingLocation {
    pub path: String,
    pub line: Option<usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SuppressedFinding {
    pub finding: SkillFinding,
    pub suppression: SuppressionMatch,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SuppressionMatch {
    pub matched_rule: String,
    pub matched_path: String,
    pub reason: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum FindingCategory {
    Spec,
    Compatibility,
    Security,
    Quality,
    Portability,
    Reproducibility,
}

#[cfg(test)]
mod tests {
    use super::*;
    use agent_audit_hosts::{CompatibilityStatus, ProfileCompatibilityResult};

    #[test]
    fn empty_compatibility_matrix_is_omitted_from_report_json() {
        let report = empty_report();

        let value = serde_json::to_value(&report).expect("serialize report");

        assert!(value.get("compatibility").is_none());
    }

    #[test]
    fn compatibility_matrix_serializes_as_stable_report_relative_shape() {
        let report = ScanReport {
            compatibility: CompatibilityMatrix {
                profiles: vec!["agent-skills-spec".to_owned(), "codex".to_owned()],
                matrix: vec![SkillCompatibilityRow {
                    path: "skills/deploy/SKILL.md".to_owned(),
                    name: Some("deploy-helper".to_owned()),
                    profiles: vec![
                        ProfileCompatibilityResult {
                            profile: "agent-skills-spec".to_owned(),
                            status: CompatibilityStatus::Pass,
                            finding_ids: Vec::new(),
                        },
                        ProfileCompatibilityResult {
                            profile: "codex".to_owned(),
                            status: CompatibilityStatus::Warn,
                            finding_ids: vec!["HOST020".to_owned()],
                        },
                    ],
                }],
            },
            ..empty_report()
        };

        let value = serde_json::to_value(&report).expect("serialize report");

        assert_eq!(
            value["compatibility"],
            serde_json::json!({
                "profiles": ["agent-skills-spec", "codex"],
                "matrix": [
                    {
                        "path": "skills/deploy/SKILL.md",
                        "name": "deploy-helper",
                        "profiles": [
                            {
                                "profile": "agent-skills-spec",
                                "status": "pass",
                                "finding_ids": []
                            },
                            {
                                "profile": "codex",
                                "status": "warn",
                                "finding_ids": ["HOST020"]
                            }
                        ]
                    }
                ]
            })
        );
    }

    #[test]
    fn reports_without_compatibility_deserialize_with_empty_matrix() {
        let report: ScanReport = serde_json::from_value(serde_json::json!({
            "packages": [],
            "findings": [],
            "suppressed_findings": [],
            "summary": {
                "package_count": 0,
                "finding_count": 0,
                "suppressed_finding_count": 0,
                "invalid_manifest_count": 0,
                "broken_reference_count": 0
            }
        }))
        .expect("deserialize report");

        assert!(report.compatibility.is_empty());
    }

    fn empty_report() -> ScanReport {
        ScanReport {
            packages: Vec::new(),
            findings: Vec::new(),
            suppressed_findings: Vec::new(),
            summary: ScanSummary {
                package_count: 0,
                finding_count: 0,
                suppressed_finding_count: 0,
                invalid_manifest_count: 0,
                broken_reference_count: 0,
            },
            compatibility: CompatibilityMatrix::default(),
        }
    }
}
