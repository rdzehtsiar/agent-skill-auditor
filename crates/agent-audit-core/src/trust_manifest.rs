// SPDX-License-Identifier: Apache-2.0

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use serde::Deserialize;

use crate::error::{AuditError, AuditResult};
use crate::model::{
    EvidenceConfidence, ExecutableArtifact, ExecutableKind, PermissionEvidence,
    PermissionEvidenceKind, PermissionKind, RemoteDependency, RemoteDependencyKind,
    SupplyChainInventory, SupplyChainSourceKind, TrustManifest, TrustManifestDeclaredDependencies,
    TrustManifestDiagnostic, TrustManifestDiagnosticKind, TrustManifestFormat,
    TrustManifestPackageDependency, TrustManifestPermissions, TrustManifestProvenance,
    TrustManifestSkill,
};
use crate::PackageManagerKind;

const TRUST_MANIFEST_FILENAMES: &[&str] = &[
    "agent-audit.trust.yaml",
    ".agent-audit.trust.yaml",
    "agent-audit.yaml",
];

pub fn inventory_trust_manifest(
    scan_root: &Path,
    skill_root: &Path,
) -> AuditResult<SupplyChainInventory> {
    let Some(manifest_path) = find_trust_manifest(skill_root) else {
        return Ok(SupplyChainInventory::default());
    };
    let content = std::fs::read_to_string(&manifest_path).map_err(|source| AuditError::Read {
        path: manifest_path.clone(),
        source,
    })?;
    if filename(&manifest_path) == "agent-audit.yaml" && !looks_like_trust_manifest(&content) {
        return Ok(SupplyChainInventory::default());
    }
    let display_path = display_path(scan_root, &manifest_path);

    Ok(parse_trust_manifest(
        display_path,
        filename(&manifest_path),
        &content,
    ))
}

fn find_trust_manifest(skill_root: &Path) -> Option<std::path::PathBuf> {
    TRUST_MANIFEST_FILENAMES
        .iter()
        .map(|filename| skill_root.join(filename))
        .find(|path| path.is_file())
}

fn looks_like_trust_manifest(content: &str) -> bool {
    let Ok(serde_yaml::Value::Mapping(mapping)) =
        serde_yaml::from_str::<serde_yaml::Value>(content)
    else {
        return true;
    };

    [
        "skill",
        "provenance",
        "permissions",
        "declared_dependencies",
    ]
    .iter()
    .any(|key| mapping.contains_key(serde_yaml::Value::String((*key).to_owned())))
}

fn parse_trust_manifest(path: String, filename: String, content: &str) -> SupplyChainInventory {
    let key_lines = yaml_key_lines(content);
    let mut inventory = SupplyChainInventory::default();

    let value = match serde_yaml::from_str::<serde_yaml::Value>(content) {
        Ok(value) => value,
        Err(error) => {
            inventory.trust_manifests.push(invalid_trust_manifest(
                path.clone(),
                filename,
                "invalid-yaml".to_owned(),
                parse_error_diagnostic(path, error),
            ));
            return inventory;
        }
    };

    if !matches!(value, serde_yaml::Value::Mapping(_)) {
        inventory.trust_manifests.push(invalid_trust_manifest(
            path.clone(),
            filename,
            "invalid-schema".to_owned(),
            schema_error_diagnostic(
                path,
                Some(1),
                "Trust manifest must be a YAML mapping with documented agent-audit fields."
                    .to_owned(),
            ),
        ));
        return inventory;
    }

    let unknown_field_diagnostics = unknown_field_diagnostics(&path, &value, &key_lines);
    let raw = match serde_yaml::from_value::<RawTrustManifest>(value) {
        Ok(raw) => raw,
        Err(error) => {
            inventory.trust_manifests.push(invalid_trust_manifest(
                path.clone(),
                filename,
                "invalid-schema".to_owned(),
                schema_error_diagnostic(
                    path,
                    error.location().map(|location| location.line()),
                    format!(
                        "Invalid trust manifest schema: {error}. Use documented scalar and sequence types for trust manifest fields."
                    ),
                ),
            ));
            return inventory;
        }
    };

    let manifest =
        normalized_trust_manifest(path.clone(), filename, raw, unknown_field_diagnostics);
    extend_inventory_from_manifest(&mut inventory, &manifest, &key_lines);
    inventory.trust_manifests.push(manifest);
    inventory.sort_deterministically();
    inventory
}

fn invalid_trust_manifest(
    path: String,
    filename: String,
    normalized: String,
    diagnostic: TrustManifestDiagnostic,
) -> TrustManifest {
    TrustManifest {
        path,
        line: Some(1),
        source: SupplyChainSourceKind::TrustManifest,
        format: TrustManifestFormat::AgentAudit,
        normalized,
        raw: Some(filename),
        confidence: EvidenceConfidence::High,
        valid: Some(false),
        diagnostics: vec![diagnostic],
        skill: None,
        provenance: None,
        permissions: None,
        declared_dependencies: TrustManifestDeclaredDependencies::default(),
    }
}

fn normalized_trust_manifest(
    path: String,
    filename: String,
    raw: RawTrustManifest,
    mut diagnostics: Vec<TrustManifestDiagnostic>,
) -> TrustManifest {
    diagnostics.sort();

    let skill = raw.skill.map(|skill| TrustManifestSkill {
        name: skill.name,
        version: skill.version,
    });
    let provenance = raw.provenance.map(|provenance| TrustManifestProvenance {
        source: provenance.source,
        commit: provenance.commit,
        signed: provenance.signed,
    });
    let permissions = raw.permissions.map(|permissions| TrustManifestPermissions {
        network: permissions.network,
        filesystem_write: permissions.filesystem_write,
        secrets: sorted_strings(permissions.secrets),
    });
    let declared_dependencies = TrustManifestDeclaredDependencies {
        commands: sorted_strings(raw.declared_dependencies.commands),
        packages: sorted_packages(raw.declared_dependencies.packages),
    };
    let normalized = normalized_manifest_name(skill.as_ref());

    TrustManifest {
        path,
        line: Some(1),
        source: SupplyChainSourceKind::TrustManifest,
        format: TrustManifestFormat::AgentAudit,
        normalized,
        raw: Some(filename),
        confidence: EvidenceConfidence::High,
        valid: Some(true),
        diagnostics,
        skill,
        provenance,
        permissions,
        declared_dependencies,
    }
}

fn extend_inventory_from_manifest(
    inventory: &mut SupplyChainInventory,
    manifest: &TrustManifest,
    key_lines: &BTreeMap<String, usize>,
) {
    if let Some(permissions) = &manifest.permissions {
        inventory
            .permissions
            .extend(permission_evidence(manifest, permissions, key_lines));
    }
    inventory
        .remote_dependencies
        .extend(package_dependency_evidence(manifest, key_lines));
    inventory
        .executables
        .extend(command_dependency_evidence(manifest, key_lines));
}

fn permission_evidence(
    manifest: &TrustManifest,
    permissions: &TrustManifestPermissions,
    key_lines: &BTreeMap<String, usize>,
) -> Vec<PermissionEvidence> {
    let mut evidence = Vec::new();

    if let Some(network) = permissions.network {
        evidence.push(PermissionEvidence {
            path: manifest.path.clone(),
            line: key_lines.get("permissions.network").copied(),
            source: SupplyChainSourceKind::TrustManifest,
            kind: PermissionKind::Network,
            evidence: PermissionEvidenceKind::Declared,
            normalized: format!("network={network}"),
            raw: Some(format!("network: {network}")),
            confidence: EvidenceConfidence::High,
        });
    }
    if let Some(filesystem_write) = &permissions.filesystem_write {
        evidence.push(PermissionEvidence {
            path: manifest.path.clone(),
            line: key_lines.get("permissions.filesystem_write").copied(),
            source: SupplyChainSourceKind::TrustManifest,
            kind: PermissionKind::FilesystemWrite,
            evidence: PermissionEvidenceKind::Declared,
            normalized: format!("filesystem_write={filesystem_write}"),
            raw: Some(format!("filesystem_write: {filesystem_write}")),
            confidence: EvidenceConfidence::High,
        });
    }
    for secret in &permissions.secrets {
        evidence.push(PermissionEvidence {
            path: manifest.path.clone(),
            line: key_lines
                .get("permissions.secrets[]")
                .copied()
                .or_else(|| key_lines.get("permissions.secrets").copied()),
            source: SupplyChainSourceKind::TrustManifest,
            kind: PermissionKind::Secrets,
            evidence: PermissionEvidenceKind::Declared,
            normalized: format!("secrets={secret}"),
            raw: Some(secret.clone()),
            confidence: EvidenceConfidence::High,
        });
    }

    evidence.sort();
    evidence
}

fn package_dependency_evidence(
    manifest: &TrustManifest,
    key_lines: &BTreeMap<String, usize>,
) -> Vec<RemoteDependency> {
    let mut dependencies = manifest
        .declared_dependencies
        .packages
        .iter()
        .filter_map(|package| {
            let ecosystem = package.ecosystem.as_deref()?;
            let name = package.name.as_deref()?;
            let version = package.version.as_deref();
            let package_manager = package_manager_kind(ecosystem);
            Some(RemoteDependency {
                path: manifest.path.clone(),
                line: key_lines
                    .get("declared_dependencies.packages.name")
                    .copied()
                    .or_else(|| key_lines.get("declared_dependencies.packages").copied()),
                source: SupplyChainSourceKind::TrustManifest,
                kind: RemoteDependencyKind::Package,
                package_manager: Some(package_manager),
                name: Some(name.to_owned()),
                version: version.map(str::to_owned),
                normalized: normalized_package_dependency(ecosystem, name, version),
                raw: Some(raw_package_dependency(name, version)),
                confidence: EvidenceConfidence::High,
                pinned: Some(version.is_some_and(|version| !version.trim().is_empty())),
            })
        })
        .collect::<Vec<_>>();
    dependencies.sort();
    dependencies
}

fn command_dependency_evidence(
    manifest: &TrustManifest,
    key_lines: &BTreeMap<String, usize>,
) -> Vec<ExecutableArtifact> {
    let mut commands = manifest
        .declared_dependencies
        .commands
        .iter()
        .map(|command| ExecutableArtifact {
            path: manifest.path.clone(),
            line: key_lines
                .get("declared_dependencies.commands[]")
                .copied()
                .or_else(|| key_lines.get("declared_dependencies.commands").copied()),
            source: SupplyChainSourceKind::TrustManifest,
            kind: ExecutableKind::Command,
            language: None,
            reason: "declared trust manifest command dependency".to_owned(),
            referenced: false,
            normalized: command.clone(),
            raw: Some(command.clone()),
            confidence: EvidenceConfidence::High,
        })
        .collect::<Vec<_>>();
    commands.sort();
    commands
}

fn normalized_manifest_name(skill: Option<&TrustManifestSkill>) -> String {
    let Some(skill) = skill else {
        return "agent-audit".to_owned();
    };
    match (skill.name.as_deref(), skill.version.as_deref()) {
        (Some(name), Some(version)) if !name.is_empty() && !version.is_empty() => {
            format!("{name}@{version}")
        }
        (Some(name), _) if !name.is_empty() => name.to_owned(),
        (_, Some(version)) if !version.is_empty() => format!("agent-audit@{version}"),
        _ => "agent-audit".to_owned(),
    }
}

fn normalized_package_dependency(ecosystem: &str, name: &str, version: Option<&str>) -> String {
    match version {
        Some(version) if !version.is_empty() => format!("{ecosystem}:{name}@{version}"),
        _ => format!("{ecosystem}:{name}"),
    }
}

fn raw_package_dependency(name: &str, version: Option<&str>) -> String {
    match version {
        Some(version) if !version.is_empty() => format!("{name} {version}"),
        _ => name.to_owned(),
    }
}

fn package_manager_kind(ecosystem: &str) -> PackageManagerKind {
    match ecosystem.trim().to_ascii_lowercase().as_str() {
        "npm" => PackageManagerKind::Npm,
        "yarn" => PackageManagerKind::Yarn,
        "pnpm" => PackageManagerKind::Pnpm,
        "pip" | "pypi" => PackageManagerKind::Pip,
        "poetry" => PackageManagerKind::Poetry,
        "uv" => PackageManagerKind::Uv,
        "cargo" | "crates.io" => PackageManagerKind::Cargo,
        "go" => PackageManagerKind::Go,
        "gem" | "rubygems" => PackageManagerKind::Gem,
        "composer" => PackageManagerKind::Composer,
        _ => PackageManagerKind::Unknown,
    }
}

fn parse_error_diagnostic(path: String, error: serde_yaml::Error) -> TrustManifestDiagnostic {
    TrustManifestDiagnostic {
        path,
        line: error.location().map(|location| location.line()),
        kind: TrustManifestDiagnosticKind::ParseError,
        message: format!(
            "Invalid trust manifest YAML: {error}. Fix the YAML syntax or remove the manifest until it can be parsed."
        ),
        field: None,
    }
}

fn schema_error_diagnostic(
    path: String,
    line: Option<usize>,
    message: String,
) -> TrustManifestDiagnostic {
    TrustManifestDiagnostic {
        path,
        line,
        kind: TrustManifestDiagnosticKind::SchemaError,
        message,
        field: None,
    }
}

fn unknown_field_diagnostics(
    path: &str,
    value: &serde_yaml::Value,
    key_lines: &BTreeMap<String, usize>,
) -> Vec<TrustManifestDiagnostic> {
    let mut unknown_fields = BTreeSet::new();
    collect_unknown_fields(
        value,
        "",
        KnownTrustManifestShape::Root,
        &mut unknown_fields,
    );

    unknown_fields
        .into_iter()
        .map(|field| TrustManifestDiagnostic {
            path: path.to_owned(),
            line: key_lines.get(&field).copied(),
            kind: TrustManifestDiagnosticKind::UnknownField,
            message: format!(
                "Unknown trust manifest field `{field}`. Remove it or move it to documented metadata before relying on this report."
            ),
            field: Some(field),
        })
        .collect()
}

#[derive(Clone, Copy)]
enum KnownTrustManifestShape {
    Root,
    Skill,
    Provenance,
    Permissions,
    DeclaredDependencies,
    PackageDependency,
    Leaf,
}

fn collect_unknown_fields(
    value: &serde_yaml::Value,
    prefix: &str,
    shape: KnownTrustManifestShape,
    unknown_fields: &mut BTreeSet<String>,
) {
    let serde_yaml::Value::Mapping(mapping) = value else {
        return;
    };

    for (key, nested_value) in mapping {
        let Some(key) = key.as_str() else {
            continue;
        };
        let field_path = if prefix.is_empty() {
            key.to_owned()
        } else {
            format!("{prefix}.{key}")
        };
        match next_shape(shape, key) {
            Some(next_shape) => {
                collect_unknown_fields(nested_value, &field_path, next_shape, unknown_fields)
            }
            None => {
                unknown_fields.insert(field_path);
            }
        }
    }

    if matches!(shape, KnownTrustManifestShape::DeclaredDependencies) {
        if let Some(packages) = mapping
            .get(serde_yaml::Value::String("packages".to_owned()))
            .and_then(serde_yaml::Value::as_sequence)
        {
            for package in packages {
                collect_unknown_fields(
                    package,
                    &format!("{prefix}.packages"),
                    KnownTrustManifestShape::PackageDependency,
                    unknown_fields,
                );
            }
        }
    }
}

fn next_shape(shape: KnownTrustManifestShape, key: &str) -> Option<KnownTrustManifestShape> {
    match shape {
        KnownTrustManifestShape::Root => match key {
            "skill" => Some(KnownTrustManifestShape::Skill),
            "provenance" => Some(KnownTrustManifestShape::Provenance),
            "permissions" => Some(KnownTrustManifestShape::Permissions),
            "declared_dependencies" => Some(KnownTrustManifestShape::DeclaredDependencies),
            _ => None,
        },
        KnownTrustManifestShape::Skill => match key {
            "name" | "version" => Some(KnownTrustManifestShape::Leaf),
            _ => None,
        },
        KnownTrustManifestShape::Provenance => match key {
            "source" | "commit" | "signed" => Some(KnownTrustManifestShape::Leaf),
            _ => None,
        },
        KnownTrustManifestShape::Permissions => match key {
            "network" | "filesystem_write" | "secrets" => Some(KnownTrustManifestShape::Leaf),
            _ => None,
        },
        KnownTrustManifestShape::DeclaredDependencies => match key {
            "commands" => Some(KnownTrustManifestShape::Leaf),
            "packages" => Some(KnownTrustManifestShape::Leaf),
            _ => None,
        },
        KnownTrustManifestShape::PackageDependency => match key {
            "ecosystem" | "name" | "version" => Some(KnownTrustManifestShape::Leaf),
            _ => None,
        },
        KnownTrustManifestShape::Leaf => Some(KnownTrustManifestShape::Leaf),
    }
}

fn yaml_key_lines(content: &str) -> BTreeMap<String, usize> {
    let mut lines = BTreeMap::new();
    let mut stack: Vec<(usize, String)> = Vec::new();

    for (index, line) in content.lines().enumerate() {
        let trimmed = line.trim_start();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }

        let indent = line.len() - trimmed.len();
        while stack
            .last()
            .is_some_and(|(stack_indent, _)| *stack_indent >= indent)
        {
            stack.pop();
        }

        if let Some(item) = trimmed.strip_prefix("- ") {
            if let Some((_, parent)) = stack.last() {
                lines.entry(format!("{parent}[]")).or_insert(index + 1);
            }
            if !item.contains(':') {
                continue;
            }
        }

        let mapping_text = trimmed.strip_prefix("- ").unwrap_or(trimmed);
        let Some((key, value)) = mapping_text.split_once(':') else {
            continue;
        };
        let key = key.trim().trim_matches(['"', '\'']);
        if key.is_empty() {
            continue;
        }

        let path = match stack.last() {
            Some((_, parent)) => format!("{parent}.{key}"),
            None => key.to_owned(),
        };
        lines.insert(path.clone(), index + 1);

        if value.trim().is_empty() && !trimmed.starts_with("- ") {
            stack.push((indent, path));
        }
    }

    lines
}

fn sorted_strings(values: Vec<String>) -> Vec<String> {
    values
        .into_iter()
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn sorted_packages(
    values: Vec<RawTrustManifestPackageDependency>,
) -> Vec<TrustManifestPackageDependency> {
    let mut packages = values
        .into_iter()
        .map(|package| TrustManifestPackageDependency {
            ecosystem: package.ecosystem.map(trim_non_empty).flatten(),
            name: package.name.map(trim_non_empty).flatten(),
            version: package.version.map(trim_non_empty).flatten(),
        })
        .collect::<Vec<_>>();
    packages.sort();
    packages
}

fn trim_non_empty(value: String) -> Option<String> {
    let value = value.trim().to_owned();
    (!value.is_empty()).then_some(value)
}

fn display_path(root: &Path, path: &Path) -> String {
    path.strip_prefix(root)
        .unwrap_or(path)
        .to_string_lossy()
        .replace('\\', "/")
}

fn filename(path: &Path) -> String {
    path.file_name()
        .map(|filename| filename.to_string_lossy().into_owned())
        .unwrap_or_else(|| path.to_string_lossy().replace('\\', "/"))
}

#[derive(Debug, Default, Deserialize)]
struct RawTrustManifest {
    #[serde(default)]
    skill: Option<RawTrustManifestSkill>,
    #[serde(default)]
    provenance: Option<RawTrustManifestProvenance>,
    #[serde(default)]
    permissions: Option<RawTrustManifestPermissions>,
    #[serde(default)]
    declared_dependencies: RawTrustManifestDeclaredDependencies,
}

#[derive(Debug, Deserialize)]
struct RawTrustManifestSkill {
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    version: Option<String>,
}

#[derive(Debug, Deserialize)]
struct RawTrustManifestProvenance {
    #[serde(default)]
    source: Option<String>,
    #[serde(default)]
    commit: Option<String>,
    #[serde(default)]
    signed: Option<bool>,
}

#[derive(Debug, Deserialize)]
struct RawTrustManifestPermissions {
    #[serde(default)]
    network: Option<bool>,
    #[serde(default)]
    filesystem_write: Option<String>,
    #[serde(default)]
    secrets: Vec<String>,
}

#[derive(Debug, Default, Deserialize)]
struct RawTrustManifestDeclaredDependencies {
    #[serde(default)]
    commands: Vec<String>,
    #[serde(default)]
    packages: Vec<RawTrustManifestPackageDependency>,
}

#[derive(Debug, Deserialize)]
struct RawTrustManifestPackageDependency {
    #[serde(default)]
    ecosystem: Option<String>,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    version: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scan::{scan_path, ScanOptions};
    use crate::test_support::TestWorkspace;

    #[test]
    fn valid_fixture_populates_trust_manifest_inventory() {
        let fixture_root = supply_fixture_root();
        let skill_root = fixture_root.join("trust-manifest-valid");
        let inventory =
            inventory_trust_manifest(&fixture_root, &skill_root).expect("inventory trust manifest");

        assert_eq!(inventory.trust_manifests.len(), 1);
        let manifest = &inventory.trust_manifests[0];
        assert_eq!(manifest.path, "trust-manifest-valid/agent-audit.trust.yaml");
        assert_eq!(manifest.valid, Some(true));
        assert!(manifest.diagnostics.is_empty());
        assert_eq!(manifest.normalized, "trust-manifest-valid@0.2.1");
        assert_eq!(
            manifest.skill,
            Some(TrustManifestSkill {
                name: Some("trust-manifest-valid".to_owned()),
                version: Some("0.2.1".to_owned()),
            })
        );
        assert_eq!(
            manifest.provenance,
            Some(TrustManifestProvenance {
                source: Some("github.com/example/trust-manifest-valid".to_owned()),
                commit: Some("0123456789abcdef0123456789abcdef01234567".to_owned()),
                signed: Some(false),
            })
        );
        assert_eq!(
            manifest.permissions,
            Some(TrustManifestPermissions {
                network: Some(false),
                filesystem_write: Some("repo-only".to_owned()),
                secrets: vec!["EXAMPLE_TOKEN".to_owned()],
            })
        );
        assert_eq!(
            manifest.declared_dependencies,
            TrustManifestDeclaredDependencies {
                commands: vec!["git".to_owned()],
                packages: vec![TrustManifestPackageDependency {
                    ecosystem: Some("npm".to_owned()),
                    name: Some("prettier".to_owned()),
                    version: Some("3.2.5".to_owned()),
                }],
            }
        );
        assert_eq!(inventory.remote_dependencies.len(), 1);
        assert_eq!(
            inventory.remote_dependencies[0].normalized,
            "npm:prettier@3.2.5"
        );
        assert_eq!(inventory.permissions.len(), 3);
        assert_eq!(inventory.executables.len(), 1);
        assert_eq!(inventory.executables[0].normalized, "git");
    }

    #[test]
    fn invalid_fixture_records_parse_diagnostic_without_panicking() {
        let fixture_root = supply_fixture_root();
        let skill_root = fixture_root.join("trust-manifest-invalid");
        let inventory =
            inventory_trust_manifest(&fixture_root, &skill_root).expect("inventory trust manifest");

        assert_eq!(inventory.trust_manifests.len(), 1);
        let manifest = &inventory.trust_manifests[0];
        assert_eq!(manifest.valid, Some(false));
        assert_eq!(manifest.normalized, "invalid-yaml");
        assert_eq!(manifest.diagnostics.len(), 1);
        assert_eq!(
            manifest.diagnostics[0].kind,
            TrustManifestDiagnosticKind::ParseError
        );
        assert!(manifest.diagnostics[0]
            .message
            .contains("Invalid trust manifest YAML"));
    }

    #[test]
    fn scan_reports_unknown_trust_manifest_fields_deterministically() {
        let workspace = TestWorkspace::new("scan-trust-manifest-unknown-fields");
        workspace.write_file("SKILL.md", "# Unknown Fields\n\nUseful skill.\n");
        workspace.write_file(
            "agent-audit.trust.yaml",
            r#"
provenance:
  signed: true
  attestation: local
skill:
  name: unknown-fields
declared_dependencies:
  packages:
    - ecosystem: npm
      name: prettier
      checksum: sha256:abc
x-extra: value
"#,
        );

        let report = scan_path(workspace.root(), &ScanOptions::default()).expect("scan path");
        let diagnostics = &report.supply_chain.trust_manifests[0].diagnostics;

        assert_eq!(
            diagnostics
                .iter()
                .map(|diagnostic| (
                    diagnostic.field.as_deref(),
                    diagnostic.line,
                    diagnostic.kind
                ))
                .collect::<Vec<_>>(),
            vec![
                (
                    Some("provenance.attestation"),
                    Some(4),
                    TrustManifestDiagnosticKind::UnknownField
                ),
                (
                    Some("declared_dependencies.packages.checksum"),
                    Some(11),
                    TrustManifestDiagnosticKind::UnknownField
                ),
                (
                    Some("x-extra"),
                    Some(12),
                    TrustManifestDiagnosticKind::UnknownField
                ),
            ]
        );
        assert_eq!(report.supply_chain.trust_manifests[0].valid, Some(true));
    }

    #[test]
    fn trust_manifest_filename_precedence_is_deterministic() {
        let workspace = TestWorkspace::new("trust-manifest-filename-precedence");
        workspace.write_file(
            "agent-audit.yaml",
            r#"
skill:
  name: fallback-config
"#,
        );
        workspace.write_file(
            ".agent-audit.trust.yaml",
            r#"
skill:
  name: dotfile-manifest
"#,
        );
        workspace.write_file(
            "agent-audit.trust.yaml",
            r#"
skill:
  name: canonical-manifest
"#,
        );

        let inventory = inventory_trust_manifest(workspace.root(), workspace.root())
            .expect("inventory trust manifest");

        assert_eq!(inventory.trust_manifests.len(), 1);
        let manifest = &inventory.trust_manifests[0];
        assert_eq!(manifest.path, "agent-audit.trust.yaml");
        assert_eq!(manifest.normalized, "canonical-manifest");

        let workspace = TestWorkspace::new("trust-manifest-dotfile-precedence");
        workspace.write_file(
            "agent-audit.yaml",
            r#"
skill:
  name: fallback-config
"#,
        );
        workspace.write_file(
            ".agent-audit.trust.yaml",
            r#"
skill:
  name: dotfile-manifest
"#,
        );

        let inventory = inventory_trust_manifest(workspace.root(), workspace.root())
            .expect("inventory trust manifest");

        assert_eq!(inventory.trust_manifests.len(), 1);
        let manifest = &inventory.trust_manifests[0];
        assert_eq!(manifest.path, ".agent-audit.trust.yaml");
        assert_eq!(manifest.normalized, "dotfile-manifest");
    }

    #[test]
    fn missing_trust_manifest_is_not_reported() {
        let workspace = TestWorkspace::new("scan-trust-manifest-missing");
        workspace.write_file("SKILL.md", "# Missing Trust Manifest\n\nUseful skill.\n");

        let report = scan_path(workspace.root(), &ScanOptions::default()).expect("scan path");

        assert!(report.supply_chain.trust_manifests.is_empty());
        assert!(report
            .supply_chain
            .trust_manifests
            .iter()
            .flat_map(|manifest| manifest.diagnostics.iter())
            .next()
            .is_none());
        assert!(report.findings.is_empty());
    }

    fn supply_fixture_root() -> std::path::PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .join("fixtures/supply-chain")
    }
}
