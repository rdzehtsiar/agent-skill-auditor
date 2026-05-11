// SPDX-License-Identifier: Apache-2.0

use serde::{Deserialize, Serialize};

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
}
