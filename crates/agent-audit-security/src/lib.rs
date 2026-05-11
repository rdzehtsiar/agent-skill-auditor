// SPDX-License-Identifier: Apache-2.0

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

pub const INITIAL_SECURITY_RULE_IDS: &[&str] = &[
    "SEC001", "SEC002", "SEC003", "SEC004", "SEC005", "SEC006", "SEC007", "SEC008", "SEC009",
    "SEC010", "SEC011", "SEC012",
];

#[derive(Debug, Clone, Default, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct SecurityScan {
    pub artifacts: Vec<SecurityArtifact>,
    pub signals: Vec<SecuritySignal>,
}

impl SecurityScan {
    pub fn is_empty(&self) -> bool {
        self.artifacts.is_empty() && self.signals.is_empty()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct SecurityArtifact {
    pub path: String,
    pub kind: SecurityArtifactKind,
    pub language: SecurityLanguage,
    pub size_bytes: u64,
    pub executable: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SecurityArtifactKind {
    Manifest,
    Script,
    Reference,
    Asset,
    Config,
    Other,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SecurityLanguage {
    Bash,
    Binary,
    #[serde(rename = "javascript")]
    JavaScript,
    Json,
    Markdown,
    #[serde(rename = "powershell")]
    PowerShell,
    Python,
    Text,
    Toml,
    #[serde(rename = "typescript")]
    TypeScript,
    Unknown,
    Yaml,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecurityArtifactSelection {
    pub artifacts: Vec<SelectedSecurityArtifact>,
}

impl SecurityArtifactSelection {
    pub fn is_empty(&self) -> bool {
        self.artifacts.is_empty()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct SelectedSecurityArtifact {
    pub path: String,
    pub reasons: Vec<SecurityArtifactSelectionReason>,
    pub executable: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SecurityArtifactSelectionReason {
    Manifest,
    Referenced,
    KnownArtifactDirectory,
    Executable,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecurityPackageSelectionInput {
    pub package_root: String,
    pub manifest_path: String,
    pub references: Vec<SecurityReferenceSelectionInput>,
    pub artifact_inventory: Vec<SecurityArtifactInventoryEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecurityReferenceSelectionInput {
    pub target: String,
    pub exists: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecurityArtifactInventoryEntry {
    pub path: String,
    pub kind: SecurityArtifactKind,
    pub file_kind: SecurityArtifactFileKind,
    pub size_bytes: u64,
    pub executable: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SecurityArtifactFileKind {
    File,
    Directory,
    Symlink,
    Other,
}

pub fn select_security_artifacts(
    packages: &[SecurityPackageSelectionInput],
) -> SecurityArtifactSelection {
    let mut selected = BTreeMap::new();

    for package in packages {
        select_package_security_artifacts(package, &mut selected);
    }

    SecurityArtifactSelection {
        artifacts: selected
            .into_iter()
            .map(|(path, artifact)| SelectedSecurityArtifact {
                path,
                reasons: artifact.reasons.into_iter().collect(),
                executable: artifact.executable,
            })
            .collect(),
    }
}

fn select_package_security_artifacts(
    package: &SecurityPackageSelectionInput,
    selected: &mut BTreeMap<String, SelectedArtifactAccumulator>,
) {
    let Some(package_root) = normalize_package_root(&package.package_root) else {
        return;
    };

    if let Some(manifest_path) = normalize_scan_relative_path(&package.manifest_path) {
        record_selection(
            selected,
            manifest_path,
            SecurityArtifactSelectionReason::Manifest,
            false,
        );
    }

    for reference in &package.references {
        if !reference.exists {
            continue;
        }
        let Some(reference_path) =
            normalize_package_relative_path(strip_query_and_fragment(&reference.target))
        else {
            continue;
        };
        record_selection(
            selected,
            join_package_path(&package_root, &reference_path),
            SecurityArtifactSelectionReason::Referenced,
            false,
        );
    }

    for entry in &package.artifact_inventory {
        if entry.file_kind == SecurityArtifactFileKind::Directory {
            continue;
        }

        let mut reasons = BTreeSet::new();
        if is_known_artifact_directory_kind(entry.kind) {
            reasons.insert(SecurityArtifactSelectionReason::KnownArtifactDirectory);
        }
        if entry.executable {
            reasons.insert(SecurityArtifactSelectionReason::Executable);
        }
        if reasons.is_empty() {
            continue;
        }

        let Some(entry_path) = normalize_package_relative_path(&entry.path) else {
            continue;
        };
        let output_path = join_package_path(&package_root, &entry_path);
        for reason in reasons {
            record_selection(selected, output_path.clone(), reason, entry.executable);
        }
    }
}

#[derive(Debug, Clone, Default)]
struct SelectedArtifactAccumulator {
    reasons: BTreeSet<SecurityArtifactSelectionReason>,
    executable: bool,
}

fn record_selection(
    selected: &mut BTreeMap<String, SelectedArtifactAccumulator>,
    path: String,
    reason: SecurityArtifactSelectionReason,
    executable: bool,
) {
    let artifact = selected.entry(path).or_default();
    artifact.reasons.insert(reason);
    artifact.executable |= executable;
}

fn is_known_artifact_directory_kind(kind: SecurityArtifactKind) -> bool {
    matches!(
        kind,
        SecurityArtifactKind::Script
            | SecurityArtifactKind::Reference
            | SecurityArtifactKind::Asset
    )
}

fn normalize_scan_relative_path(path: &str) -> Option<String> {
    normalize_local_relative_path(path, false)
}

fn normalize_package_root(path: &str) -> Option<String> {
    normalize_local_relative_path(path, true)
}

fn normalize_package_relative_path(path: &str) -> Option<String> {
    normalize_local_relative_path(path, false)
}

fn normalize_local_relative_path(path: &str, allow_empty: bool) -> Option<String> {
    let normalized = path.replace('\\', "/");
    if normalized.is_empty() || normalized == "." {
        return allow_empty.then(String::new);
    }
    if has_uri_scheme(&normalized) || normalized.starts_with('/') || has_windows_prefix(&normalized)
    {
        return None;
    }

    let mut components = Vec::new();
    for component in normalized.split('/') {
        match component {
            "" | "." => {}
            ".." => return None,
            value => components.push(value),
        }
    }

    if components.is_empty() {
        allow_empty.then(String::new)
    } else {
        Some(components.join("/"))
    }
}

fn join_package_path(package_root: &str, package_relative_path: &str) -> String {
    if package_root.is_empty() {
        package_relative_path.to_owned()
    } else {
        format!("{package_root}/{package_relative_path}")
    }
}

fn strip_query_and_fragment(target: &str) -> &str {
    match (target.find('?'), target.find('#')) {
        (Some(query), Some(fragment)) => &target[..query.min(fragment)],
        (Some(index), None) | (None, Some(index)) => &target[..index],
        (None, None) => target,
    }
}

fn has_uri_scheme(target: &str) -> bool {
    let Some(colon_index) = target.find(':') else {
        return false;
    };
    if target[..colon_index].contains('/') {
        return false;
    }

    let mut chars = target[..colon_index].chars();
    matches!(chars.next(), Some(first) if first.is_ascii_alphabetic())
        && chars.all(|value| value.is_ascii_alphanumeric() || matches!(value, '+' | '-' | '.'))
}

fn has_windows_prefix(target: &str) -> bool {
    let bytes = target.as_bytes();
    matches!(
        bytes,
        [drive, b':', ..] if drive.is_ascii_alphabetic()
    ) || target.starts_with("//")
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct SecuritySignal {
    pub location: SecurityLocation,
    pub kind: SecuritySignalKind,
    pub source: Option<SecuritySource>,
    pub sink: Option<SecuritySink>,
    pub risk: SecurityRiskScore,
    pub confidence: AnalyzerConfidence,
    pub classification: ClassificationMethod,
    pub evidence: String,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct SecurityLocation {
    pub path: String,
    pub line: Option<usize>,
    pub column: Option<usize>,
    pub byte_offset: Option<usize>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SecuritySignalKind {
    CredentialUse,
    DataExfiltration,
    DestructiveCommand,
    DynamicCodeEvaluation,
    EnvironmentVariableRead,
    FileWrite,
    GitHistoryModification,
    HiddenInstruction,
    NetworkAccess,
    ObfuscatedCommand,
    PackageInstallation,
    PromptInjectionInstruction,
    RemoteCodeExecution,
    SecretRead,
    SubprocessExecution,
    PrivilegeEscalation,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct SecuritySource {
    pub kind: SecuritySourceKind,
    pub name: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SecuritySourceKind {
    CredentialStore,
    EnvironmentVariable,
    FileSystem,
    NetworkResponse,
    ProcessArgument,
    StandardInput,
    UserInput,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct SecuritySink {
    pub kind: SecuritySinkKind,
    pub target: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SecuritySinkKind {
    DynamicCodeEvaluation,
    EnvironmentWrite,
    FileDelete,
    FileWrite,
    GitHistoryRewrite,
    NetworkRequest,
    PackageInstall,
    PrivilegeEscalation,
    ProcessExecution,
    ShellExecution,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct SecurityRiskScore {
    pub value: u8,
}

impl SecurityRiskScore {
    pub const MIN: u8 = 0;
    pub const MAX: u8 = 100;

    pub const fn new(value: u8) -> Self {
        Self { value }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AnalyzerConfidence {
    Low,
    Medium,
    High,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ClassificationMethod {
    AstPattern,
    FrontmatterField,
    ManifestText,
    RegexFallback,
    StaticMetadata,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    #[test]
    fn initial_security_rule_ids_are_stable_and_unique() {
        assert_eq!(INITIAL_SECURITY_RULE_IDS.first(), Some(&"SEC001"));
        assert_eq!(INITIAL_SECURITY_RULE_IDS.last(), Some(&"SEC012"));
        assert_eq!(INITIAL_SECURITY_RULE_IDS.len(), 12);

        let mut sorted = INITIAL_SECURITY_RULE_IDS.to_vec();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), INITIAL_SECURITY_RULE_IDS.len());
    }

    #[test]
    fn security_artifacts_have_stable_equality_and_ordering() {
        let artifacts = vec![
            SecurityArtifact {
                path: "scripts/install.sh".to_owned(),
                kind: SecurityArtifactKind::Script,
                language: SecurityLanguage::Bash,
                size_bytes: 120,
                executable: true,
            },
            SecurityArtifact {
                path: "SKILL.md".to_owned(),
                kind: SecurityArtifactKind::Manifest,
                language: SecurityLanguage::Markdown,
                size_bytes: 80,
                executable: false,
            },
        ];
        let mut sorted = artifacts.clone();

        sorted.sort();

        assert_ne!(artifacts[0], artifacts[1]);
        assert_eq!(
            sorted
                .iter()
                .map(|artifact| artifact.path.as_str())
                .collect::<Vec<_>>(),
            vec!["SKILL.md", "scripts/install.sh",]
        );
    }

    #[test]
    fn security_signals_deduplicate_with_ord_consistent_equality() {
        let first = sudo_signal("scripts/install.sh", 9, 4);
        let duplicate = sudo_signal("scripts/install.sh", 9, 4);
        let later = sudo_signal("scripts/install.sh", 12, 4);
        let mut signals = BTreeSet::new();

        signals.insert(later.clone());
        signals.insert(first.clone());
        signals.insert(duplicate);

        assert_eq!(signals.len(), 2);
        assert_eq!(signals.into_iter().collect::<Vec<_>>(), vec![first, later]);
    }

    #[test]
    fn security_scan_serializes_with_stable_field_and_enum_names() {
        let scan = SecurityScan {
            artifacts: vec![SecurityArtifact {
                path: "scripts/install.sh".to_owned(),
                kind: SecurityArtifactKind::Script,
                language: SecurityLanguage::Bash,
                size_bytes: 120,
                executable: true,
            }],
            signals: vec![sudo_signal("scripts/install.sh", 9, 4)],
        };

        assert_eq!(
            serde_json::to_value(&scan).expect("serialize security scan"),
            serde_json::json!({
                "artifacts": [
                    {
                        "path": "scripts/install.sh",
                        "kind": "script",
                        "language": "bash",
                        "size_bytes": 120,
                        "executable": true
                    }
                ],
                "signals": [
                    {
                        "location": {
                            "path": "scripts/install.sh",
                            "line": 9,
                            "column": 4,
                            "byte_offset": null
                        },
                        "kind": "privilege-escalation",
                        "source": null,
                        "sink": {
                            "kind": "privilege-escalation",
                            "target": "sudo"
                        },
                        "risk": {
                            "value": 75
                        },
                        "confidence": "high",
                        "classification": "regex-fallback",
                        "evidence": "sudo apt-get update"
                    }
                ]
            })
        );
    }

    #[test]
    fn security_artifact_selection_orders_paths_stably() {
        let packages = vec![
            selection_package(
                "zeta",
                "zeta\\SKILL.md",
                vec![existing_reference("references\\guide.md")],
                vec![inventory_file(
                    "scripts\\run.sh",
                    SecurityArtifactKind::Script,
                    true,
                )],
            ),
            selection_package(
                "alpha",
                "alpha/SKILL.md",
                vec![existing_reference("references/setup.md#install")],
                vec![inventory_file(
                    "assets/icon.png",
                    SecurityArtifactKind::Asset,
                    false,
                )],
            ),
        ];

        let first = select_security_artifacts(&packages);
        let second = select_security_artifacts(&packages);

        assert_eq!(first, second);
        assert_eq!(
            selected_paths(&first),
            vec![
                "alpha/SKILL.md",
                "alpha/assets/icon.png",
                "alpha/references/setup.md",
                "zeta/SKILL.md",
                "zeta/references/guide.md",
                "zeta/scripts/run.sh",
            ]
        );
    }

    #[test]
    fn security_artifact_selection_deduplicates_paths_and_reasons() {
        let package = selection_package(
            "skill",
            "skill/SKILL.md",
            vec![
                existing_reference("references/guide.md"),
                existing_reference("references/guide.md?raw=1#setup"),
            ],
            vec![
                inventory_file("references/guide.md", SecurityArtifactKind::Reference, true),
                inventory_file("references/guide.md", SecurityArtifactKind::Reference, true),
            ],
        );

        let selection = select_security_artifacts(&[package]);
        let guide = selection
            .artifacts
            .iter()
            .find(|artifact| artifact.path == "skill/references/guide.md")
            .expect("guide selected");

        assert_eq!(selection.artifacts.len(), 2);
        assert_eq!(
            guide.reasons,
            vec![
                SecurityArtifactSelectionReason::Referenced,
                SecurityArtifactSelectionReason::KnownArtifactDirectory,
                SecurityArtifactSelectionReason::Executable,
            ]
        );
        assert!(guide.executable);
    }

    #[test]
    fn security_artifact_selection_excludes_missing_references() {
        let package = selection_package(
            "",
            "SKILL.md",
            vec![
                existing_reference("references/guide.md"),
                SecurityReferenceSelectionInput {
                    target: "references/missing.md".to_owned(),
                    exists: false,
                },
            ],
            Vec::new(),
        );

        let selection = select_security_artifacts(&[package]);

        assert_eq!(
            selected_paths(&selection),
            vec!["SKILL.md", "references/guide.md"]
        );
        assert!(!selected_paths(&selection).contains(&"references/missing.md"));
    }

    #[test]
    fn security_artifact_selection_excludes_unrelated_repository_files() {
        let package = selection_package(
            "skill",
            "skill/SKILL.md",
            vec![
                existing_reference("references/guide.md"),
                existing_reference("../outside.md"),
                existing_reference("https://example.test/remote.md"),
            ],
            vec![
                inventory_file("scripts/run.sh", SecurityArtifactKind::Script, false),
                inventory_file("../scripts/outside.sh", SecurityArtifactKind::Script, true),
                inventory_file("src/lib.rs", SecurityArtifactKind::Other, false),
                inventory_directory("scripts/nested", SecurityArtifactKind::Script),
            ],
        );

        let selection = select_security_artifacts(&[package]);

        assert_eq!(
            selected_paths(&selection),
            vec![
                "skill/SKILL.md",
                "skill/references/guide.md",
                "skill/scripts/run.sh",
            ]
        );
    }

    #[test]
    fn security_artifact_selection_can_select_explicit_executable_inventory() {
        let package = selection_package(
            "skill",
            "skill/SKILL.md",
            Vec::new(),
            vec![inventory_file(
                "tools/local-helper",
                SecurityArtifactKind::Other,
                true,
            )],
        );

        let selection = select_security_artifacts(&[package]);

        assert_eq!(
            selected_paths(&selection),
            vec!["skill/SKILL.md", "skill/tools/local-helper"]
        );
        assert_eq!(
            selection.artifacts[1].reasons,
            vec![SecurityArtifactSelectionReason::Executable]
        );
        assert!(selection.artifacts[1].executable);
    }

    #[test]
    fn enum_serialization_names_are_stable_for_public_output() {
        assert_eq!(
            serde_json::to_value([
                SecuritySignalKind::RemoteCodeExecution,
                SecuritySignalKind::GitHistoryModification,
                SecuritySignalKind::HiddenInstruction,
            ])
            .expect("serialize signal kinds"),
            serde_json::json!([
                "remote-code-execution",
                "git-history-modification",
                "hidden-instruction"
            ])
        );
        assert_eq!(
            serde_json::to_value([
                SecurityLanguage::JavaScript,
                SecurityLanguage::PowerShell,
                SecurityLanguage::TypeScript,
            ])
            .expect("serialize security languages"),
            serde_json::json!(["javascript", "powershell", "typescript"])
        );
        assert_eq!(
            serde_json::to_value([
                ClassificationMethod::AstPattern,
                ClassificationMethod::RegexFallback,
                ClassificationMethod::StaticMetadata,
            ])
            .expect("serialize classification methods"),
            serde_json::json!(["ast-pattern", "regex-fallback", "static-metadata"])
        );
        assert_eq!(
            serde_json::to_value([
                SecurityArtifactSelectionReason::KnownArtifactDirectory,
                SecurityArtifactSelectionReason::Executable,
            ])
            .expect("serialize selection reasons"),
            serde_json::json!(["known-artifact-directory", "executable"])
        );
    }

    #[test]
    fn empty_security_scan_is_explicit() {
        assert!(SecurityScan::default().is_empty());
        assert!(!SecurityScan {
            artifacts: Vec::new(),
            signals: vec![sudo_signal("scripts/install.sh", 9, 4)],
        }
        .is_empty());
    }

    fn sudo_signal(path: &str, line: usize, column: usize) -> SecuritySignal {
        SecuritySignal {
            location: SecurityLocation {
                path: path.to_owned(),
                line: Some(line),
                column: Some(column),
                byte_offset: None,
            },
            kind: SecuritySignalKind::PrivilegeEscalation,
            source: None,
            sink: Some(SecuritySink {
                kind: SecuritySinkKind::PrivilegeEscalation,
                target: Some("sudo".to_owned()),
            }),
            risk: SecurityRiskScore::new(75),
            confidence: AnalyzerConfidence::High,
            classification: ClassificationMethod::RegexFallback,
            evidence: "sudo apt-get update".to_owned(),
        }
    }

    fn selection_package(
        package_root: &str,
        manifest_path: &str,
        references: Vec<SecurityReferenceSelectionInput>,
        artifact_inventory: Vec<SecurityArtifactInventoryEntry>,
    ) -> SecurityPackageSelectionInput {
        SecurityPackageSelectionInput {
            package_root: package_root.to_owned(),
            manifest_path: manifest_path.to_owned(),
            references,
            artifact_inventory,
        }
    }

    fn existing_reference(target: &str) -> SecurityReferenceSelectionInput {
        SecurityReferenceSelectionInput {
            target: target.to_owned(),
            exists: true,
        }
    }

    fn inventory_file(
        path: &str,
        kind: SecurityArtifactKind,
        executable: bool,
    ) -> SecurityArtifactInventoryEntry {
        SecurityArtifactInventoryEntry {
            path: path.to_owned(),
            kind,
            file_kind: SecurityArtifactFileKind::File,
            size_bytes: 10,
            executable,
        }
    }

    fn inventory_directory(
        path: &str,
        kind: SecurityArtifactKind,
    ) -> SecurityArtifactInventoryEntry {
        SecurityArtifactInventoryEntry {
            path: path.to_owned(),
            kind,
            file_kind: SecurityArtifactFileKind::Directory,
            size_bytes: 0,
            executable: false,
        }
    }

    fn selected_paths(selection: &SecurityArtifactSelection) -> Vec<&str> {
        selection
            .artifacts
            .iter()
            .map(|artifact| artifact.path.as_str())
            .collect()
    }
}
