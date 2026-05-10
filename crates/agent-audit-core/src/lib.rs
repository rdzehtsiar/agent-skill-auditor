// SPDX-License-Identifier: Apache-2.0

pub mod config;
pub mod discovery;
pub mod error;
pub mod fail;
pub mod model;
pub mod parse;
pub mod scan;
mod structural_rules;
#[cfg(test)]
mod test_support;

pub use config::{
    parse_audit_config, parse_severity, AuditConfig, ConfigIgnoreEntry, CONFIG_FILENAME,
};
pub use discovery::discover_skill_manifests;
pub use error::{AuditError, AuditResult};
pub use fail::report_matches_fail_on;
pub use model::{
    FindingCategory, FindingLocation, MarkdownCodeBlock, ScanReport, Severity, SkillArtifactKind,
    SkillFile, SkillFileKind, SkillFinding, SkillGraph, SkillManifest, SkillPackage,
    SkillReference, SuppressedFinding, SuppressionMatch,
};
pub use scan::{scan_path, ScanOptions};
