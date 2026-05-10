// SPDX-License-Identifier: Apache-2.0

pub mod discovery;
pub mod error;
pub mod model;
pub mod parse;
pub mod scan;
#[cfg(test)]
mod test_support;

pub use discovery::discover_skill_manifests;
pub use error::{AuditError, AuditResult};
pub use model::{
    FindingCategory, FindingLocation, MarkdownCodeBlock, ScanReport, Severity, SkillFinding,
    SkillGraph, SkillManifest, SkillPackage, SkillReference,
};
pub use scan::{scan_path, ScanOptions};
