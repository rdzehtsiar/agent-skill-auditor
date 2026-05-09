// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanReport {
    pub packages: Vec<SkillPackage>,
    pub findings: Vec<SkillFinding>,
    pub summary: ScanSummary,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanSummary {
    pub package_count: usize,
    pub finding_count: usize,
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
