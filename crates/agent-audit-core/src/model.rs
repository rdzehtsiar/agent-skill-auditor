// SPDX-License-Identifier: Apache-2.0

use std::{collections::BTreeMap, fmt};

use agent_audit_hosts::ProfileCompatibilityResult;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanReport {
    pub packages: Vec<SkillPackage>,
    pub findings: Vec<SkillFinding>,
    pub suppressed_findings: Vec<SuppressedFinding>,
    pub summary: ScanSummary,
    #[serde(default)]
    pub supply_chain: SupplyChainInventory,
    #[serde(default, skip_serializing_if = "CompatibilityMatrix::is_empty")]
    pub compatibility: CompatibilityMatrix,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SupplyChainInventory {
    #[serde(default)]
    pub licenses: Vec<LicenseEvidence>,
    #[serde(default)]
    pub trust_manifests: Vec<TrustManifest>,
    #[serde(default)]
    pub external_urls: Vec<ExternalUrl>,
    #[serde(default)]
    pub remote_dependencies: Vec<RemoteDependency>,
    #[serde(default)]
    pub package_managers: Vec<PackageManagerEvidence>,
    #[serde(default)]
    pub lockfiles: Vec<LockfileEvidence>,
    #[serde(default)]
    pub executables: Vec<ExecutableArtifact>,
    #[serde(default)]
    pub binaries: Vec<BinaryArtifact>,
    #[serde(default)]
    pub checksums: Vec<ChecksumEvidence>,
    #[serde(default)]
    pub permissions: Vec<PermissionEvidence>,
    #[serde(default)]
    pub offline_readiness: Vec<OfflineReadiness>,
}

impl SupplyChainInventory {
    pub fn sort_deterministically(&mut self) {
        self.licenses.sort();
        self.trust_manifests.sort();
        self.external_urls.sort();
        self.remote_dependencies.sort();
        self.package_managers.sort();
        self.lockfiles.sort();
        self.executables.sort();
        self.binaries.sort();
        self.checksums.sort();
        self.permissions.sort();
        self.offline_readiness.sort();
    }
}

// Path fields in supply-chain evidence are report-relative by contract.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct LicenseEvidence {
    pub path: String,
    pub line: Option<usize>,
    pub source: SupplyChainSourceKind,
    pub scope: LicenseScope,
    pub normalized: String,
    pub raw: Option<String>,
    pub confidence: EvidenceConfidence,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct TrustManifest {
    pub path: String,
    pub line: Option<usize>,
    pub source: SupplyChainSourceKind,
    pub format: TrustManifestFormat,
    pub normalized: String,
    pub raw: Option<String>,
    pub confidence: EvidenceConfidence,
    pub valid: Option<bool>,
    #[serde(default)]
    pub diagnostics: Vec<TrustManifestDiagnostic>,
    #[serde(default)]
    pub skill: Option<TrustManifestSkill>,
    #[serde(default)]
    pub provenance: Option<TrustManifestProvenance>,
    #[serde(default)]
    pub permissions: Option<TrustManifestPermissions>,
    #[serde(default)]
    pub declared_dependencies: TrustManifestDeclaredDependencies,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct TrustManifestDeclaredDependencies {
    #[serde(default)]
    pub commands: Vec<String>,
    #[serde(default)]
    pub packages: Vec<TrustManifestPackageDependency>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct TrustManifestDiagnostic {
    pub path: String,
    pub line: Option<usize>,
    pub kind: TrustManifestDiagnosticKind,
    pub message: String,
    pub field: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum TrustManifestDiagnosticKind {
    ParseError,
    SchemaError,
    UnknownField,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct TrustManifestSkill {
    pub name: Option<String>,
    pub version: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct TrustManifestProvenance {
    pub source: Option<String>,
    pub commit: Option<String>,
    pub signed: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct TrustManifestPermissions {
    pub network: Option<bool>,
    pub filesystem_write: Option<String>,
    #[serde(default)]
    pub secrets: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct TrustManifestPackageDependency {
    pub ecosystem: Option<String>,
    pub name: Option<String>,
    pub version: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct ExternalUrl {
    pub path: String,
    pub line: Option<usize>,
    pub source: SupplyChainSourceKind,
    pub kind: ExternalUrlKind,
    pub normalized: String,
    pub raw: Option<String>,
    pub confidence: EvidenceConfidence,
    pub pinned: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct RemoteDependency {
    pub path: String,
    pub line: Option<usize>,
    pub source: SupplyChainSourceKind,
    pub kind: RemoteDependencyKind,
    pub package_manager: Option<PackageManagerKind>,
    pub name: Option<String>,
    pub version: Option<String>,
    pub normalized: String,
    pub raw: Option<String>,
    pub confidence: EvidenceConfidence,
    pub pinned: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct PackageManagerEvidence {
    pub path: String,
    pub line: Option<usize>,
    pub source: SupplyChainSourceKind,
    pub manager: PackageManagerKind,
    pub manifest_path: Option<String>,
    pub normalized: String,
    pub raw: Option<String>,
    pub confidence: EvidenceConfidence,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct LockfileEvidence {
    pub path: String,
    pub line: Option<usize>,
    pub source: SupplyChainSourceKind,
    pub manager: PackageManagerKind,
    pub normalized: String,
    pub raw: Option<String>,
    pub confidence: EvidenceConfidence,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct ExecutableArtifact {
    pub path: String,
    pub line: Option<usize>,
    pub source: SupplyChainSourceKind,
    pub kind: ExecutableKind,
    pub language: Option<String>,
    pub reason: String,
    pub referenced: bool,
    pub normalized: String,
    pub raw: Option<String>,
    pub confidence: EvidenceConfidence,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct BinaryArtifact {
    pub path: String,
    pub line: Option<usize>,
    pub source: SupplyChainSourceKind,
    pub kind: BinaryArtifactKind,
    pub size_bytes: u64,
    pub referenced: bool,
    pub normalized: String,
    pub raw: Option<String>,
    pub confidence: EvidenceConfidence,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct ChecksumEvidence {
    pub path: String,
    pub line: Option<usize>,
    pub source: SupplyChainSourceKind,
    pub algorithm: ChecksumAlgorithm,
    pub digest: String,
    pub target_path: Option<String>,
    pub normalized: String,
    pub raw: Option<String>,
    pub confidence: EvidenceConfidence,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct PermissionEvidence {
    pub path: String,
    pub line: Option<usize>,
    pub source: SupplyChainSourceKind,
    pub kind: PermissionKind,
    pub evidence: PermissionEvidenceKind,
    pub normalized: String,
    pub raw: Option<String>,
    pub confidence: EvidenceConfidence,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct OfflineReadiness {
    pub path: String,
    pub status: OfflineReadinessStatus,
    pub score: Option<OfflineReadinessScore>,
    pub reasons: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct OfflineReadinessScore(u8);

impl OfflineReadinessScore {
    pub const MIN: u8 = 0;
    pub const MAX: u8 = 100;

    pub const fn new(value: u8) -> Option<Self> {
        if value <= Self::MAX {
            Some(Self(value))
        } else {
            None
        }
    }

    pub const fn value(self) -> u8 {
        self.0
    }
}

impl TryFrom<u8> for OfflineReadinessScore {
    type Error = OfflineReadinessScoreError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        Self::new(value).ok_or(OfflineReadinessScoreError { value })
    }
}

impl From<OfflineReadinessScore> for u8 {
    fn from(score: OfflineReadinessScore) -> Self {
        score.value()
    }
}

impl Serialize for OfflineReadinessScore {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_u8(self.value())
    }
}

impl<'de> Deserialize<'de> for OfflineReadinessScore {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = u8::deserialize(deserializer)?;
        Self::try_from(value).map_err(serde::de::Error::custom)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OfflineReadinessScoreError {
    value: u8,
}

impl fmt::Display for OfflineReadinessScoreError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "offline readiness score {} is outside the supported range {}..={}",
            self.value,
            OfflineReadinessScore::MIN,
            OfflineReadinessScore::MAX
        )
    }
}

impl std::error::Error for OfflineReadinessScoreError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SupplyChainSourceKind {
    Frontmatter,
    MarkdownLink,
    InlineCode,
    CodeBlock,
    Script,
    PackageManifest,
    Lockfile,
    TrustManifest,
    Filesystem,
    Inferred,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum EvidenceConfidence {
    Low,
    Medium,
    High,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum LicenseScope {
    Repository,
    Skill,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum TrustManifestFormat {
    AgentAudit,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ExternalUrlKind {
    Documentation,
    RemoteScript,
    DownloadedArtifact,
    PackageRegistry,
    GithubRaw,
    GithubReleaseAsset,
    HttpEndpoint,
    Localhost,
    Internal,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RemoteDependencyKind {
    Package,
    Script,
    Artifact,
    Repository,
    Service,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum PackageManagerKind {
    Npm,
    Yarn,
    Pnpm,
    Pip,
    Poetry,
    Uv,
    Cargo,
    Go,
    Gem,
    Composer,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ExecutableKind {
    Script,
    Binary,
    Command,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum BinaryArtifactKind {
    Executable,
    Archive,
    Wasm,
    Jar,
    OpaqueAsset,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ChecksumAlgorithm {
    Sha256,
    Sha384,
    Sha512,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum PermissionKind {
    Network,
    FilesystemRead,
    FilesystemWrite,
    Secrets,
    Subprocess,
    PackageInstall,
    BinaryExecution,
    GitOperations,
    PrivilegeEscalation,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum PermissionEvidenceKind {
    Declared,
    Observed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum OfflineReadinessStatus {
    Ready,
    Partial,
    NotReady,
    Unknown,
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
    #[serde(default, skip_serializing)]
    pub inline_code_locations: Vec<MarkdownInlineCode>,
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
pub struct MarkdownInlineCode {
    pub content: String,
    pub line: Option<usize>,
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
    fn empty_supply_chain_inventory_serializes_as_stable_report_section() {
        let report = empty_report();

        let json = serde_json::to_string_pretty(&report).expect("serialize report");
        let expected = r#"{
  "packages": [],
  "findings": [],
  "suppressed_findings": [],
  "summary": {
    "package_count": 0,
    "finding_count": 0,
    "suppressed_finding_count": 0,
    "invalid_manifest_count": 0,
    "broken_reference_count": 0
  },
  "supply_chain": {
    "licenses": [],
    "trust_manifests": [],
    "external_urls": [],
    "remote_dependencies": [],
    "package_managers": [],
    "lockfiles": [],
    "executables": [],
    "binaries": [],
    "checksums": [],
    "permissions": [],
    "offline_readiness": []
  }
}"#;

        assert_eq!(json, expected);
    }

    #[test]
    fn populated_supply_chain_inventory_serializes_with_stable_field_names() {
        let report = ScanReport {
            supply_chain: SupplyChainInventory {
                licenses: vec![LicenseEvidence {
                    path: "LICENSE.txt".to_owned(),
                    line: None,
                    source: SupplyChainSourceKind::Filesystem,
                    scope: LicenseScope::Repository,
                    normalized: "Apache-2.0".to_owned(),
                    raw: Some("Apache License 2.0".to_owned()),
                    confidence: EvidenceConfidence::High,
                }],
                trust_manifests: vec![TrustManifest {
                    path: "skills/review/agent-audit.yaml".to_owned(),
                    line: Some(1),
                    source: SupplyChainSourceKind::Filesystem,
                    format: TrustManifestFormat::AgentAudit,
                    normalized: "agent-audit".to_owned(),
                    raw: None,
                    confidence: EvidenceConfidence::High,
                    valid: Some(true),
                    diagnostics: Vec::new(),
                    skill: Some(TrustManifestSkill {
                        name: Some("review".to_owned()),
                        version: Some("1.0.0".to_owned()),
                    }),
                    provenance: Some(TrustManifestProvenance {
                        source: Some("github.com/example/review".to_owned()),
                        commit: Some("0123456789abcdef0123456789abcdef01234567".to_owned()),
                        signed: Some(true),
                    }),
                    permissions: Some(TrustManifestPermissions {
                        network: Some(false),
                        filesystem_write: Some("repo-only".to_owned()),
                        secrets: vec!["REVIEW_TOKEN".to_owned()],
                    }),
                    declared_dependencies: TrustManifestDeclaredDependencies {
                        commands: vec!["git".to_owned()],
                        packages: vec![TrustManifestPackageDependency {
                            ecosystem: Some("npm".to_owned()),
                            name: Some("prettier".to_owned()),
                            version: Some("3.2.5".to_owned()),
                        }],
                    },
                }],
                external_urls: vec![ExternalUrl {
                    path: "skills/review/SKILL.md".to_owned(),
                    line: Some(8),
                    source: SupplyChainSourceKind::MarkdownLink,
                    kind: ExternalUrlKind::GithubRaw,
                    normalized: "https://raw.githubusercontent.com/example/repo/main/install.sh"
                        .to_owned(),
                    raw: None,
                    confidence: EvidenceConfidence::Medium,
                    pinned: Some(false),
                }],
                remote_dependencies: vec![RemoteDependency {
                    path: "skills/review/scripts/install.sh".to_owned(),
                    line: Some(3),
                    source: SupplyChainSourceKind::Script,
                    kind: RemoteDependencyKind::Package,
                    package_manager: Some(PackageManagerKind::Pip),
                    name: Some("requests".to_owned()),
                    version: Some("2.32.0".to_owned()),
                    normalized: "requests==2.32.0".to_owned(),
                    raw: Some("pip install requests==2.32.0".to_owned()),
                    confidence: EvidenceConfidence::High,
                    pinned: Some(true),
                }],
                package_managers: vec![PackageManagerEvidence {
                    path: "skills/review/requirements.txt".to_owned(),
                    line: None,
                    source: SupplyChainSourceKind::Filesystem,
                    manager: PackageManagerKind::Pip,
                    manifest_path: Some("skills/review/requirements.txt".to_owned()),
                    normalized: "pip".to_owned(),
                    raw: None,
                    confidence: EvidenceConfidence::High,
                }],
                lockfiles: vec![LockfileEvidence {
                    path: "skills/review/uv.lock".to_owned(),
                    line: None,
                    source: SupplyChainSourceKind::Filesystem,
                    manager: PackageManagerKind::Uv,
                    normalized: "uv.lock".to_owned(),
                    raw: None,
                    confidence: EvidenceConfidence::High,
                }],
                executables: vec![ExecutableArtifact {
                    path: "skills/review/scripts/install.sh".to_owned(),
                    line: None,
                    source: SupplyChainSourceKind::Filesystem,
                    kind: ExecutableKind::Script,
                    language: Some("shell".to_owned()),
                    reason: "script extension".to_owned(),
                    referenced: true,
                    normalized: "skills/review/scripts/install.sh".to_owned(),
                    raw: None,
                    confidence: EvidenceConfidence::High,
                }],
                binaries: vec![BinaryArtifact {
                    path: "skills/review/assets/tool.wasm".to_owned(),
                    line: None,
                    source: SupplyChainSourceKind::Filesystem,
                    kind: BinaryArtifactKind::Wasm,
                    size_bytes: 42,
                    referenced: false,
                    normalized: "skills/review/assets/tool.wasm".to_owned(),
                    raw: None,
                    confidence: EvidenceConfidence::Medium,
                }],
                checksums: vec![ChecksumEvidence {
                    path: "skills/review/checksums.txt".to_owned(),
                    line: Some(1),
                    source: SupplyChainSourceKind::Filesystem,
                    algorithm: ChecksumAlgorithm::Sha256,
                    digest: "0123456789abcdef".to_owned(),
                    target_path: Some("skills/review/assets/tool.wasm".to_owned()),
                    normalized: "sha256:0123456789abcdef".to_owned(),
                    raw: None,
                    confidence: EvidenceConfidence::High,
                }],
                permissions: vec![PermissionEvidence {
                    path: "skills/review/SKILL.md".to_owned(),
                    line: Some(4),
                    source: SupplyChainSourceKind::Frontmatter,
                    kind: PermissionKind::Network,
                    evidence: PermissionEvidenceKind::Declared,
                    normalized: "network".to_owned(),
                    raw: Some("network: true".to_owned()),
                    confidence: EvidenceConfidence::High,
                }],
                offline_readiness: vec![OfflineReadiness {
                    path: "skills/review".to_owned(),
                    status: OfflineReadinessStatus::Partial,
                    score: Some(OfflineReadinessScore::new(72).expect("valid score")),
                    reasons: vec!["1 mutable external URL".to_owned()],
                }],
            },
            ..empty_report()
        };

        let value = serde_json::to_value(&report).expect("serialize report");

        assert_eq!(
            value["supply_chain"],
            serde_json::json!({
                "licenses": [{
                    "path": "LICENSE.txt",
                    "line": null,
                    "source": "filesystem",
                    "scope": "repository",
                    "normalized": "Apache-2.0",
                    "raw": "Apache License 2.0",
                    "confidence": "high"
                }],
                "trust_manifests": [{
                    "path": "skills/review/agent-audit.yaml",
                    "line": 1,
                    "source": "filesystem",
                    "format": "agent-audit",
                    "normalized": "agent-audit",
                    "raw": null,
                    "confidence": "high",
                    "valid": true,
                    "diagnostics": [],
                    "skill": {
                        "name": "review",
                        "version": "1.0.0"
                    },
                    "provenance": {
                        "source": "github.com/example/review",
                        "commit": "0123456789abcdef0123456789abcdef01234567",
                        "signed": true
                    },
                    "permissions": {
                        "network": false,
                        "filesystem_write": "repo-only",
                        "secrets": ["REVIEW_TOKEN"]
                    },
                    "declared_dependencies": {
                        "commands": ["git"],
                        "packages": [{
                            "ecosystem": "npm",
                            "name": "prettier",
                            "version": "3.2.5"
                        }]
                    }
                }],
                "external_urls": [{
                    "path": "skills/review/SKILL.md",
                    "line": 8,
                    "source": "markdown-link",
                    "kind": "github-raw",
                    "normalized": "https://raw.githubusercontent.com/example/repo/main/install.sh",
                    "raw": null,
                    "confidence": "medium",
                    "pinned": false
                }],
                "remote_dependencies": [{
                    "path": "skills/review/scripts/install.sh",
                    "line": 3,
                    "source": "script",
                    "kind": "package",
                    "package_manager": "pip",
                    "name": "requests",
                    "version": "2.32.0",
                    "normalized": "requests==2.32.0",
                    "raw": "pip install requests==2.32.0",
                    "confidence": "high",
                    "pinned": true
                }],
                "package_managers": [{
                    "path": "skills/review/requirements.txt",
                    "line": null,
                    "source": "filesystem",
                    "manager": "pip",
                    "manifest_path": "skills/review/requirements.txt",
                    "normalized": "pip",
                    "raw": null,
                    "confidence": "high"
                }],
                "lockfiles": [{
                    "path": "skills/review/uv.lock",
                    "line": null,
                    "source": "filesystem",
                    "manager": "uv",
                    "normalized": "uv.lock",
                    "raw": null,
                    "confidence": "high"
                }],
                "executables": [{
                    "path": "skills/review/scripts/install.sh",
                    "line": null,
                    "source": "filesystem",
                    "kind": "script",
                    "language": "shell",
                    "reason": "script extension",
                    "referenced": true,
                    "normalized": "skills/review/scripts/install.sh",
                    "raw": null,
                    "confidence": "high"
                }],
                "binaries": [{
                    "path": "skills/review/assets/tool.wasm",
                    "line": null,
                    "source": "filesystem",
                    "kind": "wasm",
                    "size_bytes": 42,
                    "referenced": false,
                    "normalized": "skills/review/assets/tool.wasm",
                    "raw": null,
                    "confidence": "medium"
                }],
                "checksums": [{
                    "path": "skills/review/checksums.txt",
                    "line": 1,
                    "source": "filesystem",
                    "algorithm": "sha256",
                    "digest": "0123456789abcdef",
                    "target_path": "skills/review/assets/tool.wasm",
                    "normalized": "sha256:0123456789abcdef",
                    "raw": null,
                    "confidence": "high"
                }],
                "permissions": [{
                    "path": "skills/review/SKILL.md",
                    "line": 4,
                    "source": "frontmatter",
                    "kind": "network",
                    "evidence": "declared",
                    "normalized": "network",
                    "raw": "network: true",
                    "confidence": "high"
                }],
                "offline_readiness": [{
                    "path": "skills/review",
                    "status": "partial",
                    "score": 72,
                    "reasons": ["1 mutable external URL"]
                }]
            })
        );
    }

    #[test]
    fn offline_readiness_score_enforces_schema_bounds_on_construction() {
        assert_eq!(OfflineReadinessScore::new(0).map(u8::from), Some(0));
        assert_eq!(OfflineReadinessScore::new(100).map(u8::from), Some(100));
        assert_eq!(OfflineReadinessScore::new(101), None);
        assert_eq!(OfflineReadinessScore::new(u8::MAX), None);
    }

    #[test]
    fn offline_readiness_score_rejects_out_of_range_json() {
        let error = serde_json::from_value::<OfflineReadiness>(serde_json::json!({
            "path": "skills/review",
            "status": "partial",
            "score": 101,
            "reasons": []
        }))
        .expect_err("reject out-of-range score");

        assert!(error.to_string().contains("outside the supported range"));
    }

    #[test]
    fn offline_readiness_score_keeps_null_report_shape() {
        let readiness: OfflineReadiness = serde_json::from_value(serde_json::json!({
            "path": "skills/review",
            "status": "unknown",
            "score": null,
            "reasons": []
        }))
        .expect("deserialize null score");

        assert_eq!(readiness.score, None);
    }

    #[test]
    fn reports_without_supply_chain_deserialize_with_empty_inventory() {
        let report: ScanReport = serde_json::from_value(empty_report_json_without_defaults())
            .expect("deserialize report");

        assert_eq!(report.supply_chain, SupplyChainInventory::default());
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
        let report: ScanReport = serde_json::from_value(empty_report_json_without_defaults())
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
            supply_chain: SupplyChainInventory::default(),
            compatibility: CompatibilityMatrix::default(),
        }
    }

    fn empty_report_json_without_defaults() -> serde_json::Value {
        serde_json::json!({
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
        })
    }
}
