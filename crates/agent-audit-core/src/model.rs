// SPDX-License-Identifier: Apache-2.0

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
};

use agent_audit_hosts::{profiles, ProfileCompatibilityResult};
use agent_audit_rules::RULE_REGISTRY;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanReport {
    #[serde(default)]
    pub audit: AuditMetadata,
    pub packages: Vec<SkillPackage>,
    pub findings: Vec<SkillFinding>,
    #[serde(default)]
    pub finding_groups: Vec<FindingGroup>,
    pub suppressed_findings: Vec<SuppressedFinding>,
    pub summary: ScanSummary,
    #[serde(default)]
    pub supply_chain: SupplyChainInventory,
    #[serde(default, skip_serializing_if = "CompatibilityMatrix::is_empty")]
    pub compatibility: CompatibilityMatrix,
}

pub const REPORT_SCHEMA_VERSION: &str = "1";
const AUDIT_HASH_PREFIX: &str = "fnv1a64";
const FNV1A64_OFFSET: u64 = 0xcbf29ce484222325;
const FNV1A64_PRIME: u64 = 0x100000001b3;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditMetadata {
    pub output_schema_version: String,
    pub scanner: AuditScannerMetadata,
    pub ruleset: AuditRulesetMetadata,
    pub host_profiles: AuditHostProfileMetadata,
    pub config: AuditConfigMetadata,
    pub scan: AuditScanMetadata,
    pub command: AuditCommandMetadata,
    pub platform: Option<AuditPlatformMetadata>,
    pub repository: Option<AuditRepositoryMetadata>,
    pub timestamp: Option<String>,
}

impl Default for AuditMetadata {
    fn default() -> Self {
        Self {
            output_schema_version: REPORT_SCHEMA_VERSION.to_owned(),
            scanner: AuditScannerMetadata::default(),
            ruleset: AuditRulesetMetadata::default(),
            host_profiles: AuditHostProfileMetadata::default(),
            config: AuditConfigMetadata::default(),
            scan: AuditScanMetadata::default(),
            command: AuditCommandMetadata::default(),
            platform: None,
            repository: None,
            timestamp: None,
        }
    }
}

impl AuditMetadata {
    pub fn with_selected_profiles(mut self, profiles: Vec<String>) -> Self {
        self.host_profiles.selected = profiles;
        self
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditScannerMetadata {
    pub name: String,
    pub version: String,
}

impl Default for AuditScannerMetadata {
    fn default() -> Self {
        Self {
            name: "agent-audit".to_owned(),
            version: env!("CARGO_PKG_VERSION").to_owned(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditRulesetMetadata {
    pub version: String,
    pub hash: String,
}

impl Default for AuditRulesetMetadata {
    fn default() -> Self {
        Self {
            version: env!("CARGO_PKG_VERSION").to_owned(),
            hash: stable_audit_hash(&ruleset_fingerprint_input()),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditHostProfileMetadata {
    #[serde(default)]
    pub selected: Vec<String>,
    pub version: String,
    pub hash: String,
}

impl Default for AuditHostProfileMetadata {
    fn default() -> Self {
        Self {
            selected: Vec::new(),
            version: env!("CARGO_PKG_VERSION").to_owned(),
            hash: stable_audit_hash(&host_profile_fingerprint_input()),
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditConfigMetadata {
    pub path: Option<String>,
    pub hash: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditScanMetadata {
    pub root: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditCommandMetadata {
    pub name: Option<String>,
    pub format: Option<String>,
    pub mode: Option<String>,
    #[serde(default)]
    pub profiles: Vec<String>,
    #[serde(default)]
    pub fail_on: Vec<String>,
    pub supply_chain: bool,
    pub strict_supply_chain: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditPlatformMetadata {
    pub os: String,
    pub arch: String,
    pub family: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditRepositoryMetadata {
    pub remote_url: Option<String>,
    pub commit: Option<String>,
    pub dirty: Option<bool>,
}

pub fn stable_audit_hash(value: &str) -> String {
    let mut hash = FNV1A64_OFFSET;

    for byte in value.as_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(FNV1A64_PRIME);
    }

    format!("{AUDIT_HASH_PREFIX}:{hash:016x}")
}

pub fn stable_fingerprint(value: &str) -> String {
    stable_audit_hash(value)
}

fn ruleset_fingerprint_input() -> String {
    let mut input = String::new();

    for metadata in RULE_REGISTRY.rules() {
        input.push_str(metadata.id.as_str());
        input.push('|');
        input.push_str(metadata.status.as_str());
        input.push('|');
        input.push_str(metadata.severity.as_str());
        input.push('|');
        input.push_str(metadata.category.as_str());
        input.push('|');
        input.push_str(metadata.title);
        input.push('|');
        input.push_str(&metadata.applicable_profiles.join(","));
        input.push('\n');
    }

    input
}

fn host_profile_fingerprint_input() -> String {
    let mut input = String::new();

    for profile in profiles() {
        input.push_str(profile.id);
        input.push('|');
        input.push_str(profile.display_name);
        input.push('|');
        input.push_str(&profile.recommended_manifest_size_limit.bytes.to_string());
        input.push('|');
        input.push_str(&manifest_field_names(profile.required_fields).join(","));
        input.push('|');
        input.push_str(&manifest_field_names(profile.accepted_optional_fields).join(","));
        input.push('|');
        input.push_str(&manifest_field_names(profile.known_ignored_fields).join(","));
        input.push('\n');
    }

    input
}

fn manifest_field_names(fields: &[agent_audit_hosts::ManifestField]) -> Vec<&'static str> {
    fields.iter().map(|field| field.name).collect()
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
    pub dependency_manifests: Vec<DependencyManifestEvidence>,
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
        self.dependency_manifests.sort();
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
pub struct DependencyManifestEvidence {
    pub path: String,
    pub line: Option<usize>,
    pub source: SupplyChainSourceKind,
    pub manager: PackageManagerKind,
    pub normalized: String,
    pub raw: Option<String>,
    pub confidence: EvidenceConfidence,
    pub dependency_count: usize,
    pub unpinned_dependency_count: usize,
    pub pinning: DependencyManifestPinningKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DependencyManifestPinningKind {
    ExactPinned,
    RangeBased,
    Unknown,
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub runtime_offline_capability: Option<RuntimeOfflineCapability>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub external_service_dependency: Option<OfflineDependencyEvidence>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remote_fetch_dependency: Option<OfflineDependencyEvidence>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct RuntimeOfflineCapability {
    pub status: RuntimeOfflineCapabilityStatus,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct OfflineDependencyEvidence {
    pub detected: bool,
    pub evidence_count: usize,
    pub reason: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RuntimeOfflineCapabilityStatus {
    Supported,
    Unsupported,
    Unknown,
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
            "offline audit readiness score {} is outside the supported range {}..={}",
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
    DependencyManifest,
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
    #[serde(default)]
    pub actual_secret_evidence_count: usize,
    #[serde(default)]
    pub prompt_secret_exposure_count: usize,
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
    #[serde(default)]
    pub fingerprint: String,
    pub severity: Severity,
    #[serde(default)]
    pub confidence: FindingConfidence,
    pub category: FindingCategory,
    pub title: String,
    pub message: String,
    pub location: FindingLocation,
    pub rationale: String,
    pub remediation: String,
    pub suppression: String,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct FindingLocation {
    pub path: String,
    pub line: Option<usize>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FindingGroup {
    pub rule_id: String,
    #[serde(default)]
    pub group_fingerprint: String,
    pub severity: Severity,
    #[serde(default)]
    pub confidence: FindingConfidence,
    pub category: FindingCategory,
    pub title: String,
    pub rationale: String,
    pub remediation: String,
    pub suppression: String,
    pub evidence_key: String,
    pub dimensions: BTreeMap<String, String>,
    pub finding_count: usize,
    pub affected_package_count: usize,
    pub affected_packages: Vec<String>,
    pub evidence_samples: Vec<FindingEvidenceSample>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FindingEvidenceSample {
    pub location: FindingLocation,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SuppressedFinding {
    pub finding: SkillFinding,
    pub suppression: SuppressionMatch,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SuppressionMatch {
    pub matched_rule: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub matched_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub matched_match: Option<String>,
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

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum FindingConfidence {
    Low,
    #[default]
    Medium,
    High,
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

pub const FINDING_GROUP_EVIDENCE_SAMPLE_LIMIT: usize = 3;

pub fn populate_finding_fingerprints(findings: &mut [SkillFinding]) {
    for finding in findings {
        finding.fingerprint = finding_fingerprint(finding);
    }
}

pub fn finding_fingerprint(finding: &SkillFinding) -> String {
    stable_fingerprint(&finding_fingerprint_input(finding))
}

pub fn finding_group_fingerprint(group: &FindingGroup) -> String {
    finding_group_fingerprint_from_parts(
        &group.rule_id,
        group.category,
        &group.evidence_key,
        &group.dimensions,
    )
}

pub fn finding_group_fingerprint_from_parts(
    rule_id: &str,
    category: FindingCategory,
    evidence_key: &str,
    dimensions: &BTreeMap<String, String>,
) -> String {
    stable_fingerprint(&finding_group_fingerprint_input(
        rule_id,
        category,
        evidence_key,
        dimensions,
    ))
}

pub fn build_finding_groups(
    packages: &[SkillPackage],
    findings: &[SkillFinding],
    compatibility: &CompatibilityMatrix,
) -> Vec<FindingGroup> {
    let mut groups = BTreeMap::<FindingGroupKey, FindingGroupAccumulator>::new();
    let mut sorted_findings = findings.iter().collect::<Vec<_>>();
    sorted_findings.sort_by(|left, right| finding_order_key(left).cmp(&finding_order_key(right)));

    for finding in sorted_findings {
        let mut dimensions = finding_group_dimensions(finding, compatibility);
        let evidence_key = finding_group_evidence_key(finding, &dimensions);
        let key = FindingGroupKey {
            rule_id: finding.rule_id.clone(),
            evidence_key: evidence_key.clone(),
            severity: finding.severity,
            confidence: finding.confidence,
            category: finding.category,
            dimensions: dimensions.clone(),
        };
        let group = groups
            .entry(key)
            .or_insert_with(|| FindingGroupAccumulator {
                rule_id: finding.rule_id.clone(),
                severity: finding.severity,
                confidence: finding.confidence,
                category: finding.category,
                title: finding.title.clone(),
                rationale: finding.rationale.clone(),
                remediation: finding.remediation.clone(),
                suppression: finding.suppression.clone(),
                evidence_key,
                dimensions: std::mem::take(&mut dimensions),
                finding_count: 0,
                affected_packages: BTreeMap::new(),
                evidence_samples: Vec::new(),
            });

        group.finding_count += 1;
        if let Some(package) = package_for_finding(packages, finding) {
            group
                .affected_packages
                .entry(package.manifest_path.clone())
                .or_insert(());
        }
        if group.evidence_samples.len() < FINDING_GROUP_EVIDENCE_SAMPLE_LIMIT {
            group.evidence_samples.push(FindingEvidenceSample {
                location: finding.location.clone(),
                message: finding.message.clone(),
            });
        }
    }

    groups
        .into_values()
        .map(FindingGroupAccumulator::into_group)
        .collect()
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct FindingGroupKey {
    rule_id: String,
    evidence_key: String,
    severity: Severity,
    confidence: FindingConfidence,
    category: FindingCategory,
    dimensions: BTreeMap<String, String>,
}

#[derive(Debug, Clone)]
struct FindingGroupAccumulator {
    rule_id: String,
    severity: Severity,
    confidence: FindingConfidence,
    category: FindingCategory,
    title: String,
    rationale: String,
    remediation: String,
    suppression: String,
    evidence_key: String,
    dimensions: BTreeMap<String, String>,
    finding_count: usize,
    affected_packages: BTreeMap<String, ()>,
    evidence_samples: Vec<FindingEvidenceSample>,
}

impl FindingGroupAccumulator {
    fn into_group(self) -> FindingGroup {
        let affected_packages = self.affected_packages.into_keys().collect::<Vec<_>>();
        let group_fingerprint = finding_group_fingerprint_from_parts(
            &self.rule_id,
            self.category,
            &self.evidence_key,
            &self.dimensions,
        );

        FindingGroup {
            rule_id: self.rule_id,
            group_fingerprint,
            severity: self.severity,
            confidence: self.confidence,
            category: self.category,
            title: self.title,
            rationale: self.rationale,
            remediation: self.remediation,
            suppression: self.suppression,
            evidence_key: self.evidence_key,
            dimensions: self.dimensions,
            finding_count: self.finding_count,
            affected_package_count: affected_packages.len(),
            affected_packages,
            evidence_samples: self.evidence_samples,
        }
    }
}

fn finding_group_dimensions(
    finding: &SkillFinding,
    compatibility: &CompatibilityMatrix,
) -> BTreeMap<String, String> {
    let mut dimensions = finding_base_dimensions(finding);
    if let Some(profile) = host_profile_for_finding(finding, compatibility) {
        dimensions.insert("host_profile".to_owned(), profile);
    }

    dimensions
}

pub fn finding_suppression_match_keys(finding: &SkillFinding) -> BTreeSet<String> {
    let dimensions = finding_base_dimensions(finding);
    let mut keys = BTreeSet::new();

    keys.insert(normalized_evidence_value(&finding_group_evidence_key(
        finding,
        &dimensions,
    )));
    for (key, value) in dimensions {
        keys.insert(normalized_evidence_value(&format!("{key}={value}")));
        keys.insert(normalized_evidence_value(&value));
    }
    if let Some(value) = first_backtick_value(&finding.message) {
        keys.insert(normalized_evidence_value(&value));
    }
    keys.insert(normalized_evidence_value(&finding.message));

    keys
}

fn finding_base_dimensions(finding: &SkillFinding) -> BTreeMap<String, String> {
    let mut dimensions = BTreeMap::new();

    if let Some(field) = frontmatter_field_for_finding(finding) {
        dimensions.insert("frontmatter_field".to_owned(), field);
    }
    if let Some(pattern) = command_pattern_for_finding(finding) {
        dimensions.insert("command_pattern".to_owned(), pattern);
    }
    if let Some(manager) = package_manager_for_finding(finding) {
        dimensions.insert("package_manager".to_owned(), manager);
    }
    if let Some(profile) = host_profile_from_message(finding) {
        dimensions.insert("host_profile".to_owned(), profile);
    }

    dimensions
}

fn frontmatter_field_for_finding(finding: &SkillFinding) -> Option<String> {
    let message = finding.message.to_ascii_lowercase();
    if !message.contains("frontmatter field") && !message.contains("unknown field") {
        return None;
    }

    first_backtick_value(&finding.message)
}

fn command_pattern_for_finding(finding: &SkillFinding) -> Option<String> {
    let message = finding.message.to_ascii_lowercase();

    if message.contains("npm install") {
        Some("npm install".to_owned())
    } else if message.contains("pip install") {
        Some("pip install".to_owned())
    } else if message.contains("cargo install") {
        Some("cargo install".to_owned())
    } else if message.contains("gem install") {
        Some("gem install".to_owned())
    } else if message.contains("javascript package install") {
        Some("javascript package install".to_owned())
    } else if message.contains("python package install") {
        Some("python package install".to_owned())
    } else if message.contains("ruby gem install") {
        Some("ruby gem install".to_owned())
    } else if message.contains("system package install") {
        Some("system package install".to_owned())
    } else {
        None
    }
}

fn package_manager_for_finding(finding: &SkillFinding) -> Option<String> {
    let message = finding.message.to_ascii_lowercase();

    for manager in [
        "npm", "yarn", "pnpm", "pip", "poetry", "uv", "cargo", "go", "gem", "composer",
    ] {
        if message.contains(&format!("{manager} install")) {
            return Some(manager.to_owned());
        }
    }

    None
}

fn host_profile_for_finding(
    finding: &SkillFinding,
    compatibility: &CompatibilityMatrix,
) -> Option<String> {
    if let Some(profile) = host_profile_from_message(finding) {
        return Some(profile);
    }

    let profiles = compatibility
        .matrix
        .iter()
        .filter(|row| row.path == finding.location.path)
        .flat_map(|row| row.profiles.iter())
        .filter(|profile| {
            profile
                .finding_ids
                .iter()
                .any(|rule_id| rule_id == &finding.rule_id)
        })
        .map(|profile| profile.profile.as_str())
        .collect::<std::collections::BTreeSet<_>>();

    (!profiles.is_empty()).then(|| profiles.into_iter().collect::<Vec<_>>().join(","))
}

fn host_profile_from_message(finding: &SkillFinding) -> Option<String> {
    if finding.message.starts_with("Claude Code ") {
        Some("claude-code".to_owned())
    } else if finding.message.starts_with("Codex ") {
        Some("codex".to_owned())
    } else if finding.message.starts_with("GitHub Copilot ") {
        Some("github-copilot".to_owned())
    } else if finding.message.starts_with("VS Code Copilot ") {
        Some("vscode-copilot".to_owned())
    } else {
        None
    }
}

fn finding_group_evidence_key(
    finding: &SkillFinding,
    dimensions: &BTreeMap<String, String>,
) -> String {
    if !dimensions.is_empty() {
        return dimensions
            .iter()
            .map(|(key, value)| format!("{key}={value}"))
            .collect::<Vec<_>>()
            .join("|");
    }

    first_backtick_value(&finding.message)
        .map(|value| format!("evidence={}", normalized_evidence_value(&value)))
        .unwrap_or_else(|| normalized_evidence_value(&finding.message))
}

fn first_backtick_value(value: &str) -> Option<String> {
    let (_, after_open) = value.split_once('`')?;
    let (inside, _) = after_open.split_once('`')?;
    let trimmed = inside.trim();

    (!trimmed.is_empty()).then(|| trimmed.to_owned())
}

fn normalized_evidence_value(value: &str) -> String {
    value
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .trim_matches(|character: char| matches!(character, '.' | ',' | ';' | ':'))
        .to_ascii_lowercase()
}

fn finding_fingerprint_input(finding: &SkillFinding) -> String {
    [
        "agent-audit-finding-v1".to_owned(),
        format!("rule_id={}", finding.rule_id),
        format!(
            "path={}",
            normalize_fingerprint_path(&finding.location.path)
        ),
        format!("line={}", finding.location.line.unwrap_or(0)),
        format!("category={}", finding_category_name(finding.category)),
        format!("message={}", normalized_evidence_value(&finding.message)),
    ]
    .join("\n")
}

fn finding_group_fingerprint_input(
    rule_id: &str,
    category: FindingCategory,
    evidence_key: &str,
    dimensions: &BTreeMap<String, String>,
) -> String {
    let dimensions = dimensions
        .iter()
        .map(|(key, value)| {
            format!(
                "{}={}",
                normalized_evidence_value(key),
                normalized_evidence_value(value)
            )
        })
        .collect::<Vec<_>>()
        .join("|");

    [
        "agent-audit-finding-group-v1".to_owned(),
        format!("rule_id={rule_id}"),
        format!("category={}", finding_category_name(category)),
        format!("evidence_key={}", normalized_evidence_value(evidence_key)),
        format!("dimensions={dimensions}"),
    ]
    .join("\n")
}

fn normalize_fingerprint_path(path: &str) -> String {
    path.replace('\\', "/")
}

fn finding_category_name(category: FindingCategory) -> &'static str {
    match category {
        FindingCategory::Spec => "spec",
        FindingCategory::Compatibility => "compatibility",
        FindingCategory::Security => "security",
        FindingCategory::Quality => "quality",
        FindingCategory::Portability => "portability",
        FindingCategory::Reproducibility => "reproducibility",
    }
}

fn package_for_finding<'a>(
    packages: &'a [SkillPackage],
    finding: &SkillFinding,
) -> Option<&'a SkillPackage> {
    packages
        .iter()
        .find(|package| package.manifest_path == finding.location.path)
        .or_else(|| {
            packages
                .iter()
                .filter(|package| path_has_root_prefix(&finding.location.path, &package.root))
                .max_by(|left, right| {
                    left.root
                        .len()
                        .cmp(&right.root.len())
                        .then_with(|| right.manifest_path.cmp(&left.manifest_path))
                })
        })
}

fn path_has_root_prefix(path: &str, root: &str) -> bool {
    if root.is_empty() || root == "." {
        return true;
    }

    path == root
        || path
            .strip_prefix(root)
            .is_some_and(|suffix| suffix.starts_with('/'))
}

fn finding_order_key(finding: &SkillFinding) -> (&str, Option<usize>, &str, &str) {
    (
        finding.location.path.as_str(),
        finding.location.line,
        finding.rule_id.as_str(),
        finding.message.as_str(),
    )
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

        let value = serde_json::to_value(&report).expect("serialize report");

        assert_eq!(
            value,
            serde_json::json!({
                "audit": serde_json::to_value(AuditMetadata::default()).expect("audit metadata"),
                "packages": [],
                "findings": [],
                "finding_groups": [],
                "suppressed_findings": [],
                "summary": {
                    "package_count": 0,
                    "finding_count": 0,
                    "suppressed_finding_count": 0,
                    "invalid_manifest_count": 0,
                    "broken_reference_count": 0,
                    "actual_secret_evidence_count": 0,
                    "prompt_secret_exposure_count": 0
                },
                "supply_chain": {
                    "licenses": [],
                    "trust_manifests": [],
                    "external_urls": [],
                    "remote_dependencies": [],
                    "dependency_manifests": [],
                    "package_managers": [],
                    "lockfiles": [],
                    "executables": [],
                    "binaries": [],
                    "checksums": [],
                    "permissions": [],
                    "offline_readiness": []
                }
            })
        );
    }

    #[test]
    fn audit_metadata_defaults_are_stable_and_timestamp_free() {
        let audit = AuditMetadata::default();

        assert_eq!(audit.output_schema_version, REPORT_SCHEMA_VERSION);
        assert_eq!(audit.scanner.name, "agent-audit");
        assert_eq!(audit.scanner.version, env!("CARGO_PKG_VERSION"));
        assert_eq!(audit.ruleset.version, env!("CARGO_PKG_VERSION"));
        assert!(audit.ruleset.hash.starts_with("fnv1a64:"));
        assert!(audit.host_profiles.hash.starts_with("fnv1a64:"));
        assert_eq!(audit.timestamp, None);
        assert_eq!(
            stable_audit_hash("agent-audit\n"),
            stable_audit_hash("agent-audit\n")
        );
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
                dependency_manifests: vec![DependencyManifestEvidence {
                    path: "skills/review/requirements.txt".to_owned(),
                    line: Some(1),
                    source: SupplyChainSourceKind::DependencyManifest,
                    manager: PackageManagerKind::Pip,
                    normalized: "requirements.txt".to_owned(),
                    raw: Some("requirements.txt".to_owned()),
                    confidence: EvidenceConfidence::High,
                    dependency_count: 1,
                    unpinned_dependency_count: 0,
                    pinning: DependencyManifestPinningKind::ExactPinned,
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
                    runtime_offline_capability: None,
                    external_service_dependency: None,
                    remote_fetch_dependency: None,
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
                "dependency_manifests": [{
                    "path": "skills/review/requirements.txt",
                    "line": 1,
                    "source": "dependency-manifest",
                    "manager": "pip",
                    "normalized": "requirements.txt",
                    "raw": "requirements.txt",
                    "confidence": "high",
                    "dependency_count": 1,
                    "unpinned_dependency_count": 0,
                    "pinning": "exact-pinned"
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

    #[test]
    fn finding_confidence_serializes_and_legacy_findings_default_to_medium() {
        let finding = test_finding(
            "SEC001",
            Severity::High,
            FindingCategory::Security,
            "Remote content piped into shell",
            "Remote content is piped directly into a shell.",
            "scripts/install.sh",
            Some(3),
        );

        let value = serde_json::to_value(&finding).expect("serialize finding");
        assert_eq!(value["confidence"], "medium");

        let legacy: SkillFinding = serde_json::from_value(serde_json::json!({
            "rule_id": "SKILL001",
            "severity": "low",
            "category": "spec",
            "title": "Missing skill name",
            "message": "The skill manifest does not declare a name.",
            "location": {
                "path": "SKILL.md",
                "line": 1
            },
            "rationale": "Skills without stable names are hard to inventory.",
            "remediation": "Add a non-empty name.",
            "suppression": "Suppress only with a documented reason."
        }))
        .expect("deserialize legacy finding");

        assert_eq!(legacy.confidence, FindingConfidence::Medium);
        assert_eq!(legacy.fingerprint, "");
    }

    #[test]
    fn finding_fingerprints_are_stable_and_path_normalized() {
        let mut first = test_finding(
            "SEC001",
            Severity::High,
            FindingCategory::Security,
            "Remote content piped into shell",
            "Remote content is piped directly into a shell.",
            "skills\\review\\SKILL.md",
            Some(3),
        );
        let mut second = test_finding(
            "SEC001",
            Severity::High,
            FindingCategory::Security,
            "Remote content piped into shell",
            "Remote content is   piped directly into a shell.",
            "skills/review/SKILL.md",
            Some(3),
        );
        let mut different_path = second.clone();
        different_path.location.path = "other/review/SKILL.md".to_owned();

        populate_finding_fingerprints(std::slice::from_mut(&mut first));
        populate_finding_fingerprints(std::slice::from_mut(&mut second));
        populate_finding_fingerprints(std::slice::from_mut(&mut different_path));

        assert!(first.fingerprint.starts_with("fnv1a64:"));
        assert_eq!(first.fingerprint, second.fingerprint);
        assert_ne!(second.fingerprint, different_path.fingerprint);
    }

    #[test]
    fn finding_groups_order_deterministically_and_capture_inferable_dimensions() {
        let packages = vec![
            test_package("skills/beta", "skills/beta/SKILL.md", "beta"),
            test_package("skills/alpha", "skills/alpha/SKILL.md", "alpha"),
        ];
        let findings = vec![
            test_finding(
                "SKILL050",
                Severity::Low,
                FindingCategory::Compatibility,
                "Host-specific metadata may be ignored",
                "Codex is likely to ignore the `permissions` frontmatter field.",
                "skills/beta/SKILL.md",
                Some(1),
            ),
            test_finding(
                "SUPPLY003",
                Severity::Medium,
                FindingCategory::Reproducibility,
                "Install command without matching reproducibility evidence",
                "The skill runs a npm install command without matching lockfile or exact-pinned dependency manifest evidence.",
                "skills/alpha/scripts/install.sh",
                Some(4),
            ),
        ];

        let groups = build_finding_groups(&packages, &findings, &CompatibilityMatrix::default());

        assert_eq!(
            groups
                .iter()
                .map(|group| (
                    group.rule_id.as_str(),
                    group.confidence,
                    group.evidence_key.as_str(),
                    group.affected_package_count,
                    group.dimensions.clone()
                ))
                .collect::<Vec<_>>(),
            vec![
                (
                    "SKILL050",
                    FindingConfidence::Medium,
                    "frontmatter_field=permissions|host_profile=codex",
                    1,
                    BTreeMap::from([
                        ("frontmatter_field".to_owned(), "permissions".to_owned()),
                        ("host_profile".to_owned(), "codex".to_owned()),
                    ]),
                ),
                (
                    "SUPPLY003",
                    FindingConfidence::Medium,
                    "command_pattern=npm install|package_manager=npm",
                    1,
                    BTreeMap::from([
                        ("command_pattern".to_owned(), "npm install".to_owned()),
                        ("package_manager".to_owned(), "npm".to_owned()),
                    ]),
                ),
            ]
        );
        assert!(groups
            .iter()
            .all(|group| group.group_fingerprint.starts_with("fnv1a64:")));
        assert_eq!(
            groups
                .iter()
                .map(|group| group.group_fingerprint.as_str())
                .collect::<BTreeSet<_>>()
                .len(),
            groups.len()
        );
    }

    #[test]
    fn finding_groups_count_affected_packages_and_limit_evidence_samples() {
        let packages = vec![
            test_package("skills/alpha", "skills/alpha/SKILL.md", "alpha"),
            test_package("skills/beta", "skills/beta/SKILL.md", "beta"),
        ];
        let findings = vec![
            test_finding(
                "SEC009",
                Severity::Medium,
                FindingCategory::Security,
                "Package install without lockfile",
                "The artifact runs a JavaScript package install without nearby lockfile evidence.",
                "skills/beta/scripts/install.sh",
                Some(2),
            ),
            test_finding(
                "SEC009",
                Severity::Medium,
                FindingCategory::Security,
                "Package install without lockfile",
                "The artifact runs a JavaScript package install without nearby lockfile evidence.",
                "skills/alpha/scripts/install.sh",
                Some(3),
            ),
            test_finding(
                "SEC009",
                Severity::Medium,
                FindingCategory::Security,
                "Package install without lockfile",
                "The artifact runs a JavaScript package install without nearby lockfile evidence.",
                "skills/alpha/scripts/bootstrap.sh",
                Some(4),
            ),
            test_finding(
                "SEC009",
                Severity::Medium,
                FindingCategory::Security,
                "Package install without lockfile",
                "The artifact runs a JavaScript package install without nearby lockfile evidence.",
                "skills/beta/scripts/bootstrap.sh",
                Some(5),
            ),
        ];

        let groups = build_finding_groups(&packages, &findings, &CompatibilityMatrix::default());

        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0].finding_count, 4);
        assert_eq!(groups[0].affected_package_count, 2);
        assert_eq!(
            groups[0].affected_packages,
            vec!["skills/alpha/SKILL.md", "skills/beta/SKILL.md"]
        );
        assert_eq!(
            groups[0]
                .evidence_samples
                .iter()
                .map(|sample| sample.location.path.as_str())
                .collect::<Vec<_>>(),
            vec![
                "skills/alpha/scripts/bootstrap.sh",
                "skills/alpha/scripts/install.sh",
                "skills/beta/scripts/bootstrap.sh",
            ]
        );
    }

    fn empty_report() -> ScanReport {
        ScanReport {
            audit: AuditMetadata::default(),
            packages: Vec::new(),
            findings: Vec::new(),
            finding_groups: Vec::new(),
            suppressed_findings: Vec::new(),
            summary: ScanSummary {
                package_count: 0,
                finding_count: 0,
                suppressed_finding_count: 0,
                invalid_manifest_count: 0,
                broken_reference_count: 0,
                actual_secret_evidence_count: 0,
                prompt_secret_exposure_count: 0,
            },
            supply_chain: SupplyChainInventory::default(),
            compatibility: CompatibilityMatrix::default(),
        }
    }

    fn test_package(root: &str, manifest_path: &str, name: &str) -> SkillPackage {
        SkillPackage {
            root: root.to_owned(),
            manifest_path: manifest_path.to_owned(),
            manifest: SkillManifest {
                name: Some(name.to_owned()),
                description: Some(format!("{name} description.")),
                frontmatter: BTreeMap::new(),
                body: String::new(),
                headings: Vec::new(),
                links: Vec::new(),
                inline_code: Vec::new(),
                inline_code_locations: Vec::new(),
                code_blocks: Vec::new(),
                declared_tools: Vec::new(),
                declared_permissions: Vec::new(),
            },
            graph: SkillGraph {
                references: Vec::new(),
                artifacts: Vec::new(),
                files: Vec::new(),
            },
        }
    }

    fn test_finding(
        rule_id: &str,
        severity: Severity,
        category: FindingCategory,
        title: &str,
        message: &str,
        path: &str,
        line: Option<usize>,
    ) -> SkillFinding {
        SkillFinding {
            rule_id: rule_id.to_owned(),
            fingerprint: String::new(),
            severity,
            confidence: FindingConfidence::Medium,
            category,
            title: title.to_owned(),
            message: message.to_owned(),
            location: FindingLocation {
                path: path.to_owned(),
                line,
            },
            rationale: "Rationale.".to_owned(),
            remediation: "Remediation.".to_owned(),
            suppression: "Suppression.".to_owned(),
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
