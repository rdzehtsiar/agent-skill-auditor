// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeSet;
use std::path::Path;

use agent_audit_security::{
    classify_security_artifact, read_security_artifact_bytes, SecurityArtifactReadPolicy,
    SecurityLanguage,
};

use crate::error::{AuditError, AuditResult};
use crate::model::{
    BinaryArtifact, BinaryArtifactKind, ChecksumAlgorithm, ChecksumEvidence, EvidenceConfidence,
    ExecutableArtifact, ExecutableKind, SkillGraph, SkillManifest, SupplyChainInventory,
    SupplyChainSourceKind,
};
use crate::path_utils::{collect_skill_package_files, display_path};

const OPAQUE_ASSET_SIZE_THRESHOLD_BYTES: u64 = 256 * 1024;
const CONTENT_SNIFF_BYTES: usize = 8192;
const CHECKSUM_READ_BYTES: usize = 64 * 1024;

pub fn inventory_package_artifacts(
    scan_root: &Path,
    skill_root: &Path,
    manifest: &SkillManifest,
    graph: &SkillGraph,
) -> AuditResult<SupplyChainInventory> {
    let mut inventory = SupplyChainInventory::default();
    let referenced = referenced_files(manifest, graph);
    let mut files = Vec::new();
    collect_skill_package_files(skill_root, skill_root, &mut files, &|_| true)?;
    files.sort();

    for path in &files {
        let metadata = std::fs::symlink_metadata(path).map_err(|source| AuditError::Metadata {
            path: path.clone(),
            source,
        })?;
        if !metadata.is_file() {
            continue;
        }

        let package_relative = display_path(skill_root, path);
        let display = display_path(scan_root, path);
        let is_referenced = referenced.contains(&package_relative);
        let read = read_security_artifact_bytes(
            path,
            &display,
            SecurityArtifactReadPolicy {
                max_bytes: CONTENT_SNIFF_BYTES,
            },
        )
        .map_err(|error| security_read_error(path, error))?;
        let classification =
            classify_security_artifact(&display, &read.bytes, executable_bit(&metadata));

        if let Some(executable) = executable_artifact(
            &display,
            &package_relative,
            &read.bytes,
            classification.as_ref(),
            is_referenced,
        ) {
            inventory.executables.push(executable);
        }

        if let Some(binary) = binary_artifact(
            &display,
            &package_relative,
            &read.bytes,
            metadata.len(),
            is_referenced,
        ) {
            inventory.binaries.push(binary);
        }

        if is_checksum_file(&package_relative) {
            inventory.checksums.extend(checksum_evidence(
                scan_root,
                skill_root,
                path,
                &display,
                &package_relative,
            )?);
        }
    }

    inventory.sort_deterministically();
    Ok(inventory)
}

fn referenced_files(manifest: &SkillManifest, graph: &SkillGraph) -> BTreeSet<String> {
    let mut referenced = BTreeSet::new();

    for reference in graph
        .references
        .iter()
        .filter(|reference| reference.exists == Some(true))
    {
        if let Some(path) =
            normalize_package_relative_path(strip_query_and_fragment(&reference.target))
        {
            referenced.insert(path);
        }
    }

    for link in &manifest.links {
        if let Some(path) = normalize_package_relative_path(strip_query_and_fragment(&link.target))
        {
            referenced.insert(path);
        }
    }

    for inline_code in &manifest.inline_code {
        if !looks_like_local_file_reference(inline_code) {
            continue;
        }
        if let Some(path) = normalize_package_relative_path(strip_query_and_fragment(inline_code)) {
            referenced.insert(path);
        }
    }

    referenced
}

fn executable_artifact(
    display: &str,
    package_relative: &str,
    content_prefix: &[u8],
    classification: Option<&agent_audit_security::SecurityArtifactClassification>,
    referenced: bool,
) -> Option<ExecutableArtifact> {
    let extension = extension(package_relative);
    let (kind, reason, confidence) = if executable_binary_extension(extension) {
        (
            ExecutableKind::Binary,
            format!("executable extension .{}", extension?),
            EvidenceConfidence::High,
        )
    } else if script_extension(extension) {
        (
            ExecutableKind::Script,
            format!("script extension .{}", extension?),
            EvidenceConfidence::High,
        )
    } else if has_shebang(content_prefix) {
        (
            ExecutableKind::Script,
            "shebang".to_owned(),
            EvidenceConfidence::High,
        )
    } else if classification
        .map(|classification| classification.executable)
        .unwrap_or(false)
    {
        (
            ExecutableKind::Unknown,
            "executable bit".to_owned(),
            EvidenceConfidence::Medium,
        )
    } else {
        return None;
    };

    Some(ExecutableArtifact {
        path: display.to_owned(),
        line: None,
        source: SupplyChainSourceKind::Filesystem,
        kind,
        language: classification.and_then(language_label).map(str::to_owned),
        reason,
        referenced,
        normalized: display.to_owned(),
        raw: Some(package_relative.to_owned()),
        confidence,
    })
}

fn binary_artifact(
    display: &str,
    package_relative: &str,
    content_prefix: &[u8],
    size_bytes: u64,
    referenced: bool,
) -> Option<BinaryArtifact> {
    let extension = extension(package_relative);
    let (kind, confidence) = if executable_binary_extension(extension) {
        (BinaryArtifactKind::Executable, EvidenceConfidence::High)
    } else if archive_extension(extension) {
        (BinaryArtifactKind::Archive, EvidenceConfidence::High)
    } else if extension.is_some_and(|extension| extension.eq_ignore_ascii_case("wasm")) {
        (BinaryArtifactKind::Wasm, EvidenceConfidence::High)
    } else if extension.is_some_and(|extension| extension.eq_ignore_ascii_case("jar")) {
        (BinaryArtifactKind::Jar, EvidenceConfidence::High)
    } else if extension.is_some_and(|extension| extension.eq_ignore_ascii_case("bin"))
        || looks_binary(content_prefix)
        || (opaque_asset_extension(extension) && size_bytes >= OPAQUE_ASSET_SIZE_THRESHOLD_BYTES)
    {
        (BinaryArtifactKind::OpaqueAsset, EvidenceConfidence::Medium)
    } else {
        return None;
    };

    Some(BinaryArtifact {
        path: display.to_owned(),
        line: None,
        source: SupplyChainSourceKind::Filesystem,
        kind,
        size_bytes,
        referenced,
        normalized: display.to_owned(),
        raw: Some(package_relative.to_owned()),
        confidence,
    })
}

fn checksum_evidence(
    scan_root: &Path,
    skill_root: &Path,
    path: &Path,
    display: &str,
    package_relative: &str,
) -> AuditResult<Vec<ChecksumEvidence>> {
    let mut evidence = Vec::new();
    let read = read_security_artifact_bytes(
        path,
        display,
        SecurityArtifactReadPolicy {
            max_bytes: CHECKSUM_READ_BYTES,
        },
    )
    .map_err(|error| security_read_error(path, error))?;
    let Some(content) = read.utf8_text() else {
        return Ok(evidence);
    };

    for (index, line) in content.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let Some(parsed) = parse_sha256_line(package_relative, trimmed) else {
            continue;
        };
        let target_path = parsed
            .target
            .as_deref()
            .and_then(|target| resolve_checksum_target(scan_root, skill_root, path, target));
        evidence.push(ChecksumEvidence {
            path: display.to_owned(),
            line: Some(index + 1),
            source: SupplyChainSourceKind::Filesystem,
            algorithm: ChecksumAlgorithm::Sha256,
            digest: parsed.digest.clone(),
            target_path,
            normalized: format!("sha256:{}", parsed.digest),
            raw: Some(trimmed.to_owned()),
            confidence: EvidenceConfidence::High,
        });
    }

    Ok(evidence)
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ParsedChecksum {
    digest: String,
    target: Option<String>,
}

fn parse_sha256_line(sidecar_path: &str, line: &str) -> Option<ParsedChecksum> {
    if let Some(parsed) = parse_openssl_sha256_line(line) {
        return Some(parsed);
    }

    let mut parts = line.split_whitespace();
    let digest = parts.next()?;
    if !is_sha256_digest(digest) {
        return None;
    }
    let target = parts
        .next()
        .map(|value| value.trim_start_matches('*').to_owned())
        .or_else(|| sidecar_implied_target(sidecar_path));

    Some(ParsedChecksum {
        digest: digest.to_ascii_lowercase(),
        target,
    })
}

fn parse_openssl_sha256_line(line: &str) -> Option<ParsedChecksum> {
    let rest = line.strip_prefix("SHA256(")?;
    let (target, digest) = rest.split_once(")= ")?;
    if !is_sha256_digest(digest) {
        return None;
    }
    Some(ParsedChecksum {
        digest: digest.to_ascii_lowercase(),
        target: Some(target.to_owned()),
    })
}

fn sidecar_implied_target(sidecar_path: &str) -> Option<String> {
    sidecar_path
        .strip_suffix(".sha256")
        .filter(|target| !target.is_empty())
        .map(str::to_owned)
}

fn resolve_checksum_target(
    scan_root: &Path,
    skill_root: &Path,
    sidecar_path: &Path,
    target: &str,
) -> Option<String> {
    let target = normalize_package_relative_path(strip_query_and_fragment(target))?;
    let sidecar_parent = sidecar_path.parent().unwrap_or(skill_root);
    let candidate = if target.contains('/') {
        skill_root.join(&target)
    } else {
        sidecar_parent.join(&target)
    };
    if !candidate.is_file()
        || !candidate.starts_with(skill_root)
        || is_inside_nested_skill(skill_root, &candidate)
    {
        return None;
    }
    Some(display_path(scan_root, &candidate))
}

fn is_checksum_file(package_relative: &str) -> bool {
    let Some(name) = package_relative.rsplit('/').next() else {
        return false;
    };
    matches!(name, "SHA256SUMS" | "SHA256SUMS.txt" | "checksums.txt") || name.ends_with(".sha256")
}

fn is_sha256_digest(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn extension(path: &str) -> Option<&str> {
    path.rsplit('/').next()?.rsplit_once('.')?.1.into()
}

fn executable_binary_extension(extension: Option<&str>) -> bool {
    extension.is_some_and(|extension| {
        ["exe", "dll", "so", "dylib"]
            .iter()
            .any(|expected| extension.eq_ignore_ascii_case(expected))
    })
}

fn script_extension(extension: Option<&str>) -> bool {
    extension.is_some_and(|extension| {
        [
            "sh", "bash", "zsh", "fish", "ps1", "bat", "cmd", "py", "js", "ts", "rb",
        ]
        .iter()
        .any(|expected| extension.eq_ignore_ascii_case(expected))
    })
}

fn archive_extension(extension: Option<&str>) -> bool {
    extension.is_some_and(|extension| {
        ["zip", "tar", "gz", "tgz", "7z", "rar", "xz", "bz2"]
            .iter()
            .any(|expected| extension.eq_ignore_ascii_case(expected))
    })
}

fn opaque_asset_extension(extension: Option<&str>) -> bool {
    extension.is_some_and(|extension| {
        ["png", "jpg", "jpeg", "pdf"]
            .iter()
            .any(|expected| extension.eq_ignore_ascii_case(expected))
    })
}

fn has_shebang(content: &[u8]) -> bool {
    content.starts_with(b"#!")
}

fn looks_binary(content: &[u8]) -> bool {
    content.contains(&0) || std::str::from_utf8(content).is_err()
}

fn looks_like_local_file_reference(value: &str) -> bool {
    let value = strip_query_and_fragment(value);
    if value.chars().any(char::is_whitespace) {
        return false;
    }
    value.contains('/')
        || value
            .rsplit('/')
            .next()
            .is_some_and(|name| name.contains('.'))
}

fn is_inside_nested_skill(skill_root: &Path, path: &Path) -> bool {
    let mut current = path.parent();
    while let Some(directory) = current {
        if directory == skill_root {
            return false;
        }
        if directory.join("SKILL.md").is_file() {
            return true;
        }
        current = directory.parent();
    }
    false
}

fn language_label(
    classification: &agent_audit_security::SecurityArtifactClassification,
) -> Option<&'static str> {
    match classification.language {
        SecurityLanguage::Shell => Some("shell"),
        SecurityLanguage::Binary => Some("binary"),
        SecurityLanguage::JavaScript => Some("javascript"),
        SecurityLanguage::Json => Some("json"),
        SecurityLanguage::Ruby => Some("ruby"),
        SecurityLanguage::Go => Some("go"),
        SecurityLanguage::Rust => Some("rust"),
        SecurityLanguage::Python => Some("python"),
        SecurityLanguage::TypeScript => Some("typescript"),
        SecurityLanguage::Yaml => Some("yaml"),
        SecurityLanguage::Unknown => None,
    }
}

fn normalize_package_relative_path(path: &str) -> Option<String> {
    let normalized = path.replace('\\', "/");
    if normalized.is_empty()
        || normalized == "."
        || normalized.starts_with('/')
        || has_windows_prefix(&normalized)
        || has_uri_scheme(&normalized)
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

    (!components.is_empty()).then(|| components.join("/"))
}

fn strip_query_and_fragment(path: &str) -> &str {
    path.split(['?', '#']).next().unwrap_or(path)
}

fn has_uri_scheme(path: &str) -> bool {
    let Some((scheme, _)) = path.split_once(':') else {
        return false;
    };
    !scheme.is_empty()
        && scheme
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'-' | b'.'))
}

fn has_windows_prefix(path: &str) -> bool {
    let bytes = path.as_bytes();
    bytes.len() >= 2 && bytes[1] == b':' && bytes[0].is_ascii_alphabetic()
}

fn security_read_error(
    path: &Path,
    error: agent_audit_security::SecurityArtifactReadError,
) -> AuditError {
    let kind = match &error {
        agent_audit_security::SecurityArtifactReadError::OpenFailed { kind, .. }
        | agent_audit_security::SecurityArtifactReadError::ReadFailed { kind, .. } => *kind,
        agent_audit_security::SecurityArtifactReadError::InvalidDisplayPath { .. }
        | agent_audit_security::SecurityArtifactReadError::NotFile { .. } => {
            std::io::ErrorKind::InvalidData
        }
    };
    AuditError::Read {
        path: path.to_path_buf(),
        source: std::io::Error::new(kind, error),
    }
}

#[cfg(unix)]
fn executable_bit(metadata: &std::fs::Metadata) -> bool {
    use std::os::unix::fs::PermissionsExt;

    metadata.permissions().mode() & 0o111 != 0
}

#[cfg(not(unix))]
fn executable_bit(_metadata: &std::fs::Metadata) -> bool {
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parse::parse_skill_manifest;
    use crate::scan::{scan_path, ScanOptions};
    use crate::test_support::TestWorkspace;

    #[test]
    fn inventories_referenced_executable_artifact() {
        let workspace = TestWorkspace::new("referenced-executable-artifact");
        workspace.write_file(
            "SKILL.md",
            "---\nname: executable\ndescription: Uses a script.\n---\n\nRun [check](scripts/check.sh).\n",
        );
        workspace.write_file("scripts/check.sh", "#!/usr/bin/env bash\necho ok\n");

        let report = scan_path(workspace.root(), &ScanOptions::default()).expect("scan fixture");

        assert_eq!(report.supply_chain.executables.len(), 1);
        let executable = &report.supply_chain.executables[0];
        assert_eq!(executable.path, "scripts/check.sh");
        assert_eq!(executable.kind, ExecutableKind::Script);
        assert_eq!(executable.language.as_deref(), Some("shell"));
        assert!(executable.referenced);
    }

    #[test]
    fn inventories_unreferenced_binary_and_archive_artifacts() {
        let workspace = TestWorkspace::new("binary-archive-artifacts");
        workspace.write_file(
            "SKILL.md",
            "---\nname: binary\ndescription: Has opaque artifacts.\n---\n",
        );
        workspace.write_file("bin/helper.exe", "MZ\x00\x01");
        workspace.write_file("assets/archive.zip", "PK\x03\x04");

        let report = scan_path(workspace.root(), &ScanOptions::default()).expect("scan fixture");
        let binaries = report
            .supply_chain
            .binaries
            .iter()
            .map(|binary| (&binary.path, binary.kind, binary.referenced))
            .collect::<Vec<_>>();

        assert_eq!(
            binaries,
            vec![
                (
                    &"assets/archive.zip".to_owned(),
                    BinaryArtifactKind::Archive,
                    false
                ),
                (
                    &"bin/helper.exe".to_owned(),
                    BinaryArtifactKind::Executable,
                    false
                ),
            ]
        );
    }

    #[test]
    fn parses_checksum_sidecar_and_links_existing_target() {
        let workspace = TestWorkspace::new("checksum-sidecar");
        workspace.write_file(
            "SKILL.md",
            "---\nname: checksums\ndescription: Has checksum evidence.\n---\n",
        );
        workspace.write_file("scripts/check.sh", "echo ok\n");
        workspace.write_file(
            "checksums.txt",
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef  scripts/check.sh\n",
        );

        let report = scan_path(workspace.root(), &ScanOptions::default()).expect("scan fixture");

        assert_eq!(report.supply_chain.checksums.len(), 1);
        let checksum = &report.supply_chain.checksums[0];
        assert_eq!(checksum.path, "checksums.txt");
        assert_eq!(checksum.line, Some(1));
        assert_eq!(checksum.target_path.as_deref(), Some("scripts/check.sh"));
        assert_eq!(
            checksum.digest,
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        );
    }

    #[test]
    fn missing_checksum_sidecar_leaves_checksum_inventory_empty() {
        let workspace = TestWorkspace::new("missing-checksum-sidecar");
        workspace.write_file(
            "SKILL.md",
            "---\nname: missing-checksum\ndescription: Has no checksum evidence.\n---\n",
        );
        workspace.write_file("assets/tool.bin", "\u{0}\u{1}\u{2}");

        let report = scan_path(workspace.root(), &ScanOptions::default()).expect("scan fixture");

        assert!(report.supply_chain.checksums.is_empty());
        assert_eq!(report.supply_chain.binaries.len(), 1);
    }

    #[test]
    fn malformed_checksum_lines_are_ignored() {
        let workspace = TestWorkspace::new("malformed-checksums");
        workspace.write_file(
            "SKILL.md",
            "---\nname: malformed-checksums\ndescription: Has malformed checksums.\n---\n",
        );
        workspace.write_file("assets/tool.bin", "\u{0}\u{1}\u{2}");
        workspace.write_file(
            "checksums.txt",
            "\
not-a-digest assets/tool.bin
0123456789abcdef assets/tool.bin
SHA256(tool.bin)= not-a-digest
",
        );

        let report = scan_path(workspace.root(), &ScanOptions::default()).expect("scan fixture");

        assert!(report.supply_chain.checksums.is_empty());
    }

    #[test]
    fn package_inventory_stops_at_nested_skill_boundary() {
        let workspace = TestWorkspace::new("nested-skill-boundary");
        workspace.write_file(
            "SKILL.md",
            "---\nname: outer\ndescription: Outer skill.\n---\n",
        );
        workspace.write_file(
            "nested/SKILL.md",
            "---\nname: inner\ndescription: Inner skill.\n---\n",
        );
        workspace.write_file("nested/bin/inner.exe", "MZ\x00\x01");

        let report = scan_path(workspace.root(), &ScanOptions::default()).expect("scan fixture");
        let binary_paths = report
            .supply_chain
            .binaries
            .iter()
            .map(|binary| binary.path.as_str())
            .collect::<Vec<_>>();

        assert_eq!(binary_paths, vec!["nested/bin/inner.exe"]);
    }

    #[test]
    fn direct_package_inventory_stops_at_nested_skill_boundary() {
        let workspace = TestWorkspace::new("direct-nested-skill-boundary");
        workspace.write_file(
            "SKILL.md",
            "---\nname: outer\ndescription: Outer skill.\n---\n",
        );
        workspace.write_file("bin/outer.exe", "MZ\x00\x01");
        workspace.write_file(
            "nested/SKILL.md",
            "---\nname: inner\ndescription: Inner skill.\n---\n",
        );
        workspace.write_file("nested/bin/inner.exe", "MZ\x00\x01");

        let content =
            std::fs::read_to_string(workspace.root().join("SKILL.md")).expect("read manifest");
        let manifest = parse_skill_manifest(&workspace.root().join("SKILL.md"), &content)
            .expect("parse manifest");
        let graph = SkillGraph {
            references: Vec::new(),
            artifacts: Vec::new(),
            files: Vec::new(),
        };

        let inventory =
            inventory_package_artifacts(workspace.root(), workspace.root(), &manifest, &graph)
                .expect("inventory artifacts");

        assert_eq!(
            inventory
                .binaries
                .iter()
                .map(|binary| binary.path.as_str())
                .collect::<Vec<_>>(),
            vec!["bin/outer.exe"]
        );
    }

    #[test]
    fn inventory_order_is_deterministic() {
        let workspace = TestWorkspace::new("artifact-ordering");
        workspace.write_file(
            "SKILL.md",
            "---\nname: ordering\ndescription: Sorts artifacts.\n---\n",
        );
        workspace.write_file("z/helper.exe", "MZ\x00\x01");
        workspace.write_file("a/archive.zip", "PK\x03\x04");
        workspace.write_file("m/tool.bin", "\u{0}\u{1}\u{2}");

        let first = scan_path(workspace.root(), &ScanOptions::default()).expect("first scan");
        let second = scan_path(workspace.root(), &ScanOptions::default()).expect("second scan");

        assert_eq!(first.supply_chain.binaries, second.supply_chain.binaries);
        assert_eq!(
            first
                .supply_chain
                .binaries
                .iter()
                .map(|binary| binary.path.as_str())
                .collect::<Vec<_>>(),
            vec!["a/archive.zip", "m/tool.bin", "z/helper.exe"]
        );
    }

    #[test]
    fn checksum_line_parsing_supports_common_formats() {
        assert_eq!(
            parse_sha256_line(
                "checksums.txt",
                "ABCDEFabcdef0123456789abcdef0123456789abcdef0123456789abcdef0123 *tool.exe"
            ),
            Some(ParsedChecksum {
                digest: "abcdefabcdef0123456789abcdef0123456789abcdef0123456789abcdef0123"
                    .to_owned(),
                target: Some("tool.exe".to_owned()),
            })
        );
        assert_eq!(
            parse_sha256_line(
                "tool.exe.sha256",
                "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
            ),
            Some(ParsedChecksum {
                digest: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
                    .to_owned(),
                target: Some("tool.exe".to_owned()),
            })
        );
        assert_eq!(
            parse_sha256_line(
                "SHA256SUMS",
                "SHA256(tool.exe)= 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
            ),
            Some(ParsedChecksum {
                digest: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
                    .to_owned(),
                target: Some("tool.exe".to_owned()),
            })
        );
    }

    #[test]
    fn direct_inventory_handles_invalid_utf8_binary_without_panic() {
        let workspace = TestWorkspace::new("invalid-utf8-binary");
        workspace.write_file(
            "SKILL.md",
            "---\nname: invalid-utf8\ndescription: Has invalid UTF-8.\n---\n",
        );
        workspace.create_dir("assets");
        std::fs::write(workspace.root().join("assets/blob.dat"), [0xff, 0xfe, 0xfd])
            .expect("write binary bytes");
        let content =
            std::fs::read_to_string(workspace.root().join("SKILL.md")).expect("read manifest");
        let manifest = parse_skill_manifest(&workspace.root().join("SKILL.md"), &content)
            .expect("parse manifest");
        let graph = SkillGraph {
            references: Vec::new(),
            artifacts: vec!["assets".to_owned()],
            files: vec![crate::model::SkillFile {
                path: "assets/blob.dat".to_owned(),
                artifact: crate::model::SkillArtifactKind::Assets,
                kind: crate::model::SkillFileKind::File,
                size_bytes: 3,
                readonly: false,
            }],
        };

        let inventory =
            inventory_package_artifacts(workspace.root(), workspace.root(), &manifest, &graph)
                .expect("inventory artifacts");

        assert_eq!(inventory.binaries.len(), 1);
        assert_eq!(inventory.binaries[0].path, "assets/blob.dat");
    }
}
