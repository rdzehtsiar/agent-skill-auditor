// SPDX-License-Identifier: Apache-2.0

mod artifact_inventory;
pub mod config;
pub mod discovery;
pub mod error;
pub mod fail;
mod license_inventory;
pub mod model;
mod offline_readiness;
mod package_inventory;
pub mod parse;
mod path_utils;
mod permission_reconciliation;
pub mod scan;
#[cfg(test)]
mod test_support;
pub mod trust_manifest;
mod url_inventory;

pub use config::{
    parse_audit_config, parse_severity, AuditConfig, ConfigIgnoreEntry, SupplyChainConfig,
    SupplyChainPolicy, CONFIG_FILENAME,
};
pub use discovery::discover_skill_manifests;
pub use error::{AuditError, AuditResult};
pub use fail::report_matches_fail_on;
pub use model::{
    build_finding_groups, BinaryArtifact, BinaryArtifactKind, ChecksumAlgorithm, ChecksumEvidence,
    CompatibilityMatrix, EvidenceConfidence, ExecutableArtifact, ExecutableKind, ExternalUrl,
    ExternalUrlKind, FindingCategory, FindingConfidence, FindingEvidenceSample, FindingGroup,
    FindingLocation, LicenseEvidence, LicenseScope, LockfileEvidence, MarkdownCodeBlock,
    OfflineReadiness, OfflineReadinessScore, OfflineReadinessStatus, PackageManagerEvidence,
    PackageManagerKind, PermissionEvidence, PermissionEvidenceKind, PermissionKind,
    RemoteDependency, RemoteDependencyKind, ScanReport, Severity, SkillArtifactKind,
    SkillCompatibilityRow, SkillFile, SkillFileKind, SkillFinding, SkillGraph, SkillManifest,
    SkillPackage, SkillReference, SupplyChainInventory, SupplyChainSourceKind, SuppressedFinding,
    SuppressionMatch, TrustManifest, TrustManifestDeclaredDependencies, TrustManifestDiagnostic,
    TrustManifestDiagnosticKind, TrustManifestFormat, TrustManifestPackageDependency,
    TrustManifestPermissions, TrustManifestProvenance, TrustManifestSkill,
};
pub use scan::{scan_path, ScanOptions};
