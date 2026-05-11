// SPDX-License-Identifier: Apache-2.0

use agent_audit_security::{AnalyzerConfidence, SecuritySignal, SecuritySignalKind};

use crate::model::{
    EvidenceConfidence, ExecutableKind, PermissionEvidence, PermissionEvidenceKind, PermissionKind,
    SkillManifest, SupplyChainInventory, SupplyChainSourceKind,
};

pub fn inventory_manifest_permissions_and_tools(
    manifest_path: &str,
    manifest: &SkillManifest,
    permission_line: Option<usize>,
    tools_line: Option<usize>,
) -> SupplyChainInventory {
    let mut inventory = SupplyChainInventory::default();

    inventory.permissions.extend(
        manifest
            .declared_permissions
            .iter()
            .filter_map(|permission| {
                permission_kind(permission).map(|kind| PermissionEvidence {
                    path: manifest_path.to_owned(),
                    line: permission_line,
                    source: SupplyChainSourceKind::Frontmatter,
                    kind,
                    evidence: PermissionEvidenceKind::Declared,
                    normalized: normalized_declared_permission(kind, permission),
                    raw: Some(permission.clone()),
                    confidence: EvidenceConfidence::High,
                })
            }),
    );

    inventory
        .executables
        .extend(
            manifest
                .declared_tools
                .iter()
                .map(|tool| crate::model::ExecutableArtifact {
                    path: manifest_path.to_owned(),
                    line: tools_line,
                    source: SupplyChainSourceKind::Frontmatter,
                    kind: ExecutableKind::Command,
                    language: None,
                    reason: "declared manifest tool dependency".to_owned(),
                    referenced: false,
                    normalized: tool.clone(),
                    raw: Some(tool.clone()),
                    confidence: EvidenceConfidence::High,
                }),
        );

    inventory.sort_deterministically();
    inventory
}

pub fn reconcile_observed_permissions(
    inventory: &mut SupplyChainInventory,
    security_signals: &[SecuritySignal],
) {
    inventory
        .permissions
        .extend(observed_signal_permissions(security_signals));
    inventory
        .permissions
        .extend(observed_binary_execution_permissions(inventory));
    inventory.sort_deterministically();
    inventory.permissions.dedup();
}

fn observed_signal_permissions(signals: &[SecuritySignal]) -> Vec<PermissionEvidence> {
    let mut permissions = signals
        .iter()
        .filter(|signal| {
            matches!(
                signal.confidence,
                AnalyzerConfidence::Medium | AnalyzerConfidence::High
            )
        })
        .filter_map(observed_signal_permission)
        .collect::<Vec<_>>();
    permissions.sort();
    permissions.dedup();
    permissions
}

fn observed_signal_permission(signal: &SecuritySignal) -> Option<PermissionEvidence> {
    let kind = signal_permission_kind(signal.kind)?;
    let value = signal_value(signal);

    Some(PermissionEvidence {
        path: signal.location.path.clone(),
        line: signal.location.line,
        source: signal_source_kind(signal),
        kind,
        evidence: PermissionEvidenceKind::Observed,
        normalized: normalized_observed_permission(kind, value.as_deref()),
        raw: Some(signal.evidence.clone()),
        confidence: evidence_confidence(signal.confidence),
    })
}

fn observed_binary_execution_permissions(
    inventory: &SupplyChainInventory,
) -> Vec<PermissionEvidence> {
    let mut permissions = inventory
        .executables
        .iter()
        .filter(|executable| {
            executable.kind == ExecutableKind::Binary
                && executable.source == SupplyChainSourceKind::Filesystem
        })
        .map(|executable| PermissionEvidence {
            path: executable.path.clone(),
            line: executable.line,
            source: executable.source,
            kind: PermissionKind::BinaryExecution,
            evidence: PermissionEvidenceKind::Observed,
            normalized: format!("binary_execution={}", executable.normalized),
            raw: executable.raw.clone(),
            confidence: executable.confidence,
        })
        .collect::<Vec<_>>();
    permissions.sort();
    permissions.dedup();
    permissions
}

fn signal_permission_kind(kind: SecuritySignalKind) -> Option<PermissionKind> {
    match kind {
        SecuritySignalKind::NetworkAccess
        | SecuritySignalKind::DataExfiltration
        | SecuritySignalKind::ExecutableDownload
        | SecuritySignalKind::RemoteCodeExecution => Some(PermissionKind::Network),
        SecuritySignalKind::SecretRead
        | SecuritySignalKind::CredentialUse
        | SecuritySignalKind::EnvironmentVariableRead => Some(PermissionKind::Secrets),
        SecuritySignalKind::FileWrite | SecuritySignalKind::DestructiveCommand => {
            Some(PermissionKind::FilesystemWrite)
        }
        SecuritySignalKind::SubprocessExecution | SecuritySignalKind::DynamicCodeEvaluation => {
            Some(PermissionKind::Subprocess)
        }
        SecuritySignalKind::PackageInstallation => Some(PermissionKind::PackageInstall),
        SecuritySignalKind::GitHistoryModification => Some(PermissionKind::GitOperations),
        SecuritySignalKind::PrivilegeEscalation => Some(PermissionKind::PrivilegeEscalation),
        SecuritySignalKind::HiddenInstruction
        | SecuritySignalKind::ObfuscatedCommand
        | SecuritySignalKind::PromptInjectionInstruction => None,
    }
}

fn permission_kind(value: &str) -> Option<PermissionKind> {
    match normalized_name(value).as_str() {
        "network" | "network_access" | "internet" | "http" | "https" => {
            Some(PermissionKind::Network)
        }
        "filesystem_read" | "file_read" | "read_files" | "read-files" => {
            Some(PermissionKind::FilesystemRead)
        }
        "filesystem_write" | "file_write" | "write_files" | "write-files" => {
            Some(PermissionKind::FilesystemWrite)
        }
        "secrets" | "secret" | "env" | "environment" | "environment_variables" => {
            Some(PermissionKind::Secrets)
        }
        "subprocess" | "process" | "shell" | "command" | "commands" => {
            Some(PermissionKind::Subprocess)
        }
        "package_install" | "package_installation" | "install_packages" => {
            Some(PermissionKind::PackageInstall)
        }
        "binary_execution" | "execute_binary" | "binaries" => Some(PermissionKind::BinaryExecution),
        "git" | "git_operations" => Some(PermissionKind::GitOperations),
        "sudo" | "privilege_escalation" => Some(PermissionKind::PrivilegeEscalation),
        _ => None,
    }
}

fn signal_value(signal: &SecuritySignal) -> Option<String> {
    match signal.kind {
        SecuritySignalKind::NetworkAccess
        | SecuritySignalKind::DataExfiltration
        | SecuritySignalKind::RemoteCodeExecution => signal_external_value(signal),
        SecuritySignalKind::SecretRead
        | SecuritySignalKind::CredentialUse
        | SecuritySignalKind::EnvironmentVariableRead => signal_source_name(signal),
        SecuritySignalKind::PackageInstallation => trimmed_value(&signal.evidence),
        SecuritySignalKind::ExecutableDownload => signal_external_value(signal),
        _ => signal_source_name(signal).or_else(|| signal_sink_target(signal)),
    }
}

fn signal_source_name(signal: &SecuritySignal) -> Option<String> {
    signal
        .source
        .as_ref()
        .and_then(|source| source.name.clone())
        .and_then(|value| trimmed_value(&value))
}

fn signal_sink_target(signal: &SecuritySignal) -> Option<String> {
    signal
        .sink
        .as_ref()
        .and_then(|sink| sink.target.clone())
        .and_then(|value| trimmed_value(&value))
}

fn signal_external_value(signal: &SecuritySignal) -> Option<String> {
    [signal_source_name(signal), signal_sink_target(signal)]
        .into_iter()
        .flatten()
        .find(|value| is_external_url(value))
}

fn is_external_url(value: &str) -> bool {
    value.starts_with("http://") || value.starts_with("https://")
}

fn trimmed_value(value: &str) -> Option<String> {
    Some(value.trim().to_owned()).filter(|value| !value.is_empty())
}

fn normalized_declared_permission(kind: PermissionKind, raw: &str) -> String {
    match kind {
        PermissionKind::Network => format!("network={}", raw.trim()),
        PermissionKind::FilesystemRead => format!("filesystem_read={}", raw.trim()),
        PermissionKind::FilesystemWrite => format!("filesystem_write={}", raw.trim()),
        PermissionKind::Secrets => format!("secrets={}", raw.trim()),
        PermissionKind::Subprocess => format!("subprocess={}", raw.trim()),
        PermissionKind::PackageInstall => format!("package_install={}", raw.trim()),
        PermissionKind::BinaryExecution => format!("binary_execution={}", raw.trim()),
        PermissionKind::GitOperations => format!("git_operations={}", raw.trim()),
        PermissionKind::PrivilegeEscalation => {
            format!("privilege_escalation={}", raw.trim())
        }
    }
}

fn normalized_observed_permission(kind: PermissionKind, value: Option<&str>) -> String {
    let label = match kind {
        PermissionKind::Network => "network",
        PermissionKind::FilesystemRead => "filesystem_read",
        PermissionKind::FilesystemWrite => "filesystem_write",
        PermissionKind::Secrets => "secrets",
        PermissionKind::Subprocess => "subprocess",
        PermissionKind::PackageInstall => "package_install",
        PermissionKind::BinaryExecution => "binary_execution",
        PermissionKind::GitOperations => "git_operations",
        PermissionKind::PrivilegeEscalation => "privilege_escalation",
    };
    value.map_or_else(|| label.to_owned(), |value| format!("{label}={value}"))
}

fn signal_source_kind(signal: &SecuritySignal) -> SupplyChainSourceKind {
    if signal.location.path.ends_with("/SKILL.md") || signal.location.path == "SKILL.md" {
        SupplyChainSourceKind::Inferred
    } else if signal.location.path.starts_with("scripts/")
        || signal.location.path.contains("/scripts/")
    {
        SupplyChainSourceKind::Script
    } else {
        SupplyChainSourceKind::Inferred
    }
}

fn evidence_confidence(confidence: AnalyzerConfidence) -> EvidenceConfidence {
    match confidence {
        AnalyzerConfidence::Low => EvidenceConfidence::Low,
        AnalyzerConfidence::Medium => EvidenceConfidence::Medium,
        AnalyzerConfidence::High => EvidenceConfidence::High,
    }
}

fn normalized_name(value: &str) -> String {
    value.trim().to_ascii_lowercase().replace([' ', '-'], "_")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scan::{scan_path, ScanOptions};
    use crate::test_support::TestWorkspace;

    #[test]
    fn scan_reconciles_declared_only_observed_only_and_matching_permissions() {
        let workspace = TestWorkspace::new("permission-reconciliation-basic");
        workspace.write_file(
            "SKILL.md",
            "---\nname: permissions\ndescription: Reconciles permissions.\npermissions:\n  - network\n  - filesystem_write\ntools:\n  - git\n---\n\nRun `scripts/run.sh`.\n",
        );
        workspace.write_file("scripts/run.sh", "curl https://example.invalid\n");

        let report = scan_path(workspace.root(), &ScanOptions::default()).expect("scan fixture");
        let permissions = report
            .supply_chain
            .permissions
            .iter()
            .map(|permission| {
                (
                    permission.path.as_str(),
                    permission.kind,
                    permission.evidence,
                    permission.normalized.as_str(),
                )
            })
            .collect::<Vec<_>>();

        assert_eq!(
            permissions,
            vec![
                (
                    "SKILL.md",
                    PermissionKind::Network,
                    PermissionEvidenceKind::Declared,
                    "network=network",
                ),
                (
                    "SKILL.md",
                    PermissionKind::FilesystemWrite,
                    PermissionEvidenceKind::Declared,
                    "filesystem_write=filesystem_write",
                ),
                (
                    "scripts/run.sh",
                    PermissionKind::Network,
                    PermissionEvidenceKind::Observed,
                    "network=https://example.invalid",
                ),
            ]
        );
        assert!(report
            .supply_chain
            .executables
            .iter()
            .any(
                |executable| executable.source == SupplyChainSourceKind::Frontmatter
                    && executable.normalized == "git"
            ));
    }

    #[test]
    fn scan_reconciles_conflicting_secret_and_package_install_evidence() {
        let workspace = TestWorkspace::new("permission-reconciliation-conflict");
        workspace.write_file(
            "SKILL.md",
            "---\nname: conflict\ndescription: Reconciles conflicts.\n---\n\nRun `scripts/install.sh`.\n",
        );
        workspace.write_file(
            "agent-audit.trust.yaml",
            "permissions:\n  network: false\n  secrets:\n    - DECLARED_TOKEN\n",
        );
        workspace.write_file(
            "scripts/install.sh",
            "curl -H \"Authorization: Bearer $API_TOKEN\" https://example.invalid\nnpm install left-pad@1.3.0\n",
        );

        let report = scan_path(workspace.root(), &ScanOptions::default()).expect("scan fixture");
        let normalized = report
            .supply_chain
            .permissions
            .iter()
            .map(|permission| permission.normalized.as_str())
            .collect::<Vec<_>>();

        assert_eq!(
            normalized,
            vec![
                "network=false",
                "secrets=DECLARED_TOKEN",
                "network=https://example.invalid",
                "secrets=API_TOKEN",
                "package_install=npm install left-pad@1.3.0",
            ]
        );
    }

    #[test]
    fn scan_permission_reconciliation_order_is_deterministic_across_nested_skills() {
        let workspace = TestWorkspace::new("permission-reconciliation-nested");
        workspace.write_file(
            "SKILL.md",
            "---\nname: outer\ndescription: Outer skill.\n---\n",
        );
        workspace.write_file("scripts/write.sh", "echo ok > output.txt\n");
        workspace.write_file(
            "nested/SKILL.md",
            "---\nname: inner\ndescription: Inner skill.\n---\n",
        );
        workspace.write_file(
            "nested/scripts/net.sh",
            "curl https://nested.example.invalid\n",
        );

        let first = scan_path(workspace.root(), &ScanOptions::default()).expect("first scan");
        let second = scan_path(workspace.root(), &ScanOptions::default()).expect("second scan");

        assert_eq!(
            first.supply_chain.permissions,
            second.supply_chain.permissions
        );
        assert_eq!(
            first
                .supply_chain
                .permissions
                .iter()
                .map(|permission| permission.path.as_str())
                .collect::<Vec<_>>(),
            vec!["nested/scripts/net.sh", "scripts/write.sh"]
        );
    }

    #[test]
    fn scan_executable_download_does_not_normalize_network_to_local_output_path() {
        let workspace = TestWorkspace::new("permission-reconciliation-executable-download");
        workspace.write_file(
            "SKILL.md",
            "---\nname: executable-download\ndescription: Downloads an executable.\n---\n\nRun `scripts/install.sh`.\n",
        );
        workspace.write_file(
            "scripts/install.sh",
            "curl -L https://downloads.example.invalid/tools/helper.exe -o helper.exe\n",
        );

        let report = scan_path(workspace.root(), &ScanOptions::default()).expect("scan fixture");
        let normalized = report
            .supply_chain
            .permissions
            .iter()
            .filter(|permission| permission.kind == PermissionKind::Network)
            .map(|permission| permission.normalized.as_str())
            .collect::<Vec<_>>();

        assert!(!normalized.contains(&"network=helper.exe"));
        assert!(normalized.contains(&"network"));
        assert!(normalized.contains(&"network=https://downloads.example.invalid/tools/helper.exe"));
    }
}
