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
mod text_utils;
pub mod trust_manifest;
mod url_inventory;

pub use agent_audit_rules::RuleExecutionMode;
pub use config::{
    parse_audit_config, parse_severity, AuditConfig, ConfigIgnoreEntry, CONFIG_FILENAME,
};
pub use discovery::discover_skill_manifests;
pub use error::{AuditError, AuditResult};
pub use fail::report_matches_fail_on;
pub use model::{
    build_ecosystem_patterns, build_external_url_domain_summaries, build_finding_groups,
    BinaryArtifact, BinaryArtifactKind, ChecksumAlgorithm, ChecksumEvidence, CompatibilityMatrix,
    DependencyManifestEvidence, DependencyManifestPinningKind, EcosystemPattern,
    EcosystemPatternEvidence, EvidenceConfidence, ExecutableArtifact, ExecutableKind, ExternalUrl,
    ExternalUrlDomainClassification, ExternalUrlDomainSummary, ExternalUrlKind, FindingCategory,
    FindingConfidence, FindingEvidenceSample, FindingGroup, FindingLocation, LicenseEvidence,
    LicenseScope, LockfileEvidence, MarkdownCodeBlock, OfflineDependencyEvidence, OfflineReadiness,
    OfflineReadinessScore, OfflineReadinessStatus, PackageManagerEvidence, PackageManagerKind,
    PermissionEvidence, PermissionEvidenceKind, PermissionKind, RemoteDependency,
    RemoteDependencyKind, RuntimeOfflineCapability, RuntimeOfflineCapabilityStatus, ScanReport,
    Severity, SkillArtifactKind, SkillCompatibilityRow, SkillFile, SkillFileKind, SkillFinding,
    SkillGraph, SkillManifest, SkillPackage, SkillReference, SupplyChainInventory,
    SupplyChainSourceKind, SuppressedFinding, SuppressionMatch, TrustManifest,
    TrustManifestDeclaredDependencies, TrustManifestDiagnostic, TrustManifestDiagnosticKind,
    TrustManifestFormat, TrustManifestPackageDependency, TrustManifestPermissions,
    TrustManifestProvenance, TrustManifestSkill,
};
pub use scan::{scan_path, ScanOptions};
