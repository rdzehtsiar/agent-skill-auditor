// SPDX-License-Identifier: Apache-2.0

use std::path::{Path, PathBuf};

use crate::model::{
    EvidenceConfidence, LicenseEvidence, LicenseScope, SkillManifest, SupplyChainInventory,
    SupplyChainSourceKind,
};

const LICENSE_FILENAMES: &[&str] = &["LICENSE", "LICENSE.md", "LICENSE.txt", "COPYING", "NOTICE"];
const FRONTMATTER_LICENSE_FIELDS: &[&str] = &["license"];

pub fn inventory_license_files(scan_root: &Path, skill_root: &Path) -> SupplyChainInventory {
    let mut inventory = SupplyChainInventory::default();

    if scan_root != skill_root {
        inventory.licenses.extend(license_file_evidence(
            scan_root,
            scan_root,
            LicenseScope::Repository,
        ));
    }
    inventory.licenses.extend(license_file_evidence(
        scan_root,
        skill_root,
        LicenseScope::Skill,
    ));

    inventory.sort_deterministically();
    inventory
}

pub fn inventory_manifest_license(
    manifest_path: &str,
    manifest: &SkillManifest,
    frontmatter_key_lines: &std::collections::BTreeMap<String, usize>,
) -> SupplyChainInventory {
    let mut inventory = SupplyChainInventory::default();

    for field in FRONTMATTER_LICENSE_FIELDS {
        let Some(value) = manifest.frontmatter.get(*field).and_then(scalar_string) else {
            continue;
        };
        let Some(normalized) = normalize_declared_license(value) else {
            continue;
        };
        inventory.licenses.push(LicenseEvidence {
            path: manifest_path.to_owned(),
            line: frontmatter_key_lines.get(*field).copied(),
            source: SupplyChainSourceKind::Frontmatter,
            scope: LicenseScope::Skill,
            normalized,
            raw: Some(format!("{field}: {value}")),
            confidence: EvidenceConfidence::High,
        });
    }

    inventory.sort_deterministically();
    inventory
}

fn license_file_evidence(
    scan_root: &Path,
    directory: &Path,
    scope: LicenseScope,
) -> Vec<LicenseEvidence> {
    let mut evidence = LICENSE_FILENAMES
        .iter()
        .filter_map(|filename| {
            let path = directory.join(filename);
            path.is_file()
                .then(|| license_evidence_for_file(scan_root, path, *filename, scope))
        })
        .collect::<Vec<_>>();
    evidence.sort();
    evidence
}

fn license_evidence_for_file(
    scan_root: &Path,
    path: PathBuf,
    filename: &str,
    scope: LicenseScope,
) -> LicenseEvidence {
    let text = std::fs::read_to_string(&path).unwrap_or_default();
    let (normalized, confidence) = normalize_license_text(&text);

    LicenseEvidence {
        path: display_path(scan_root, &path),
        line: None,
        source: SupplyChainSourceKind::Filesystem,
        scope,
        normalized,
        raw: Some(filename.to_owned()),
        confidence,
    }
}

fn normalize_license_text(text: &str) -> (String, EvidenceConfidence) {
    let normalized = text.to_ascii_lowercase();

    if normalized.contains("apache license")
        && (normalized.contains("version 2.0") || normalized.contains("license 2.0"))
    {
        return ("Apache-2.0".to_owned(), EvidenceConfidence::Medium);
    }
    if normalized.contains("mit license") {
        return ("MIT".to_owned(), EvidenceConfidence::Medium);
    }
    if normalized.contains("bsd 3-clause") || normalized.contains("redistribution and use") {
        return ("BSD".to_owned(), EvidenceConfidence::Low);
    }

    ("unknown".to_owned(), EvidenceConfidence::Low)
}

fn normalize_declared_license(value: &str) -> Option<String> {
    let value = value.trim();
    if value.is_empty() || !is_spdx_like(value) {
        return None;
    }

    Some(value.to_owned())
}

fn is_spdx_like(value: &str) -> bool {
    value.chars().all(|character| {
        character.is_ascii_alphanumeric() || matches!(character, '-' | '.' | '+' | '(' | ')' | ' ')
    }) && value
        .split_ascii_whitespace()
        .all(|token| !token.is_empty())
}

fn scalar_string(value: &serde_yaml::Value) -> Option<&str> {
    match value {
        serde_yaml::Value::String(value) => Some(value.as_str()),
        _ => None,
    }
}

fn display_path(root: &Path, path: &Path) -> String {
    path.strip_prefix(root)
        .unwrap_or(path)
        .to_string_lossy()
        .replace('\\', "/")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scan::{scan_path, ScanOptions};
    use crate::test_support::TestWorkspace;

    #[test]
    fn scan_inventories_repository_license_for_nested_skill() {
        let workspace = TestWorkspace::new("license-repo-only");
        workspace.write_file("LICENSE.txt", "Apache License 2.0 fixture text.\n");
        workspace.write_file(
            "skills/review/SKILL.md",
            "# Review\n\nReview pull requests.\n",
        );

        let report = scan_path(workspace.root(), &ScanOptions::default()).expect("scan path");

        assert_eq!(
            license_projection(&report.supply_chain.licenses),
            vec![(
                "LICENSE.txt",
                None,
                SupplyChainSourceKind::Filesystem,
                LicenseScope::Repository,
                "Apache-2.0",
                Some("LICENSE.txt"),
                EvidenceConfidence::Medium,
            )]
        );
    }

    #[test]
    fn scan_inventories_skill_license_for_root_skill() {
        let workspace = TestWorkspace::new("license-skill-only");
        workspace.write_file("LICENSE", "MIT License\n");
        workspace.write_file("SKILL.md", "# Root Skill\n\nUseful skill.\n");

        let report = scan_path(workspace.root(), &ScanOptions::default()).expect("scan path");

        assert_eq!(
            license_projection(&report.supply_chain.licenses),
            vec![(
                "LICENSE",
                None,
                SupplyChainSourceKind::Filesystem,
                LicenseScope::Skill,
                "MIT",
                Some("LICENSE"),
                EvidenceConfidence::Medium,
            )]
        );
    }

    #[test]
    fn scan_inventories_repository_skill_and_frontmatter_licenses() {
        let workspace = TestWorkspace::new("license-both-present");
        workspace.write_file("LICENSE.txt", "Apache License 2.0 fixture text.\n");
        workspace.write_file("skills/review/LICENSE.md", "MIT License\n");
        workspace.write_file(
            "skills/review/SKILL.md",
            r#"---
name: review
description: Review fixture.
license: MIT
---

# Review
"#,
        );

        let report = scan_path(workspace.root(), &ScanOptions::default()).expect("scan path");

        assert_eq!(
            license_projection(&report.supply_chain.licenses),
            vec![
                (
                    "LICENSE.txt",
                    None,
                    SupplyChainSourceKind::Filesystem,
                    LicenseScope::Repository,
                    "Apache-2.0",
                    Some("LICENSE.txt"),
                    EvidenceConfidence::Medium,
                ),
                (
                    "skills/review/LICENSE.md",
                    None,
                    SupplyChainSourceKind::Filesystem,
                    LicenseScope::Skill,
                    "MIT",
                    Some("LICENSE.md"),
                    EvidenceConfidence::Medium,
                ),
                (
                    "skills/review/SKILL.md",
                    Some(4),
                    SupplyChainSourceKind::Frontmatter,
                    LicenseScope::Skill,
                    "MIT",
                    Some("license: MIT"),
                    EvidenceConfidence::High,
                ),
            ]
        );
    }

    #[test]
    fn scan_keeps_missing_license_evidence_empty_without_findings() {
        let workspace = TestWorkspace::new("license-missing");
        workspace.write_file("skill/SKILL.md", "# Missing License\n\nUseful skill.\n");

        let report = scan_path(workspace.root(), &ScanOptions::default()).expect("scan path");

        assert!(report.supply_chain.licenses.is_empty());
        assert!(report.findings.is_empty());
    }

    #[test]
    fn scan_orders_license_evidence_deterministically() {
        let workspace = TestWorkspace::new("license-ordering");
        workspace.write_file("COPYING", "Unknown license text.\n");
        workspace.write_file("LICENSE", "Apache License 2.0 fixture text.\n");
        workspace.write_file("skills/zeta/LICENSE.txt", "MIT License\n");
        workspace.write_file("skills/zeta/NOTICE", "Notice text.\n");
        workspace.write_file(
            "skills/zeta/SKILL.md",
            r#"---
name: zeta
description: Zeta fixture.
license: Zlib
---
"#,
        );

        let report = scan_path(workspace.root(), &ScanOptions::default()).expect("scan path");

        assert_eq!(
            report
                .supply_chain
                .licenses
                .iter()
                .map(|license| (
                    license.path.as_str(),
                    license.scope,
                    license.source,
                    license.normalized.as_str(),
                ))
                .collect::<Vec<_>>(),
            vec![
                (
                    "COPYING",
                    LicenseScope::Repository,
                    SupplyChainSourceKind::Filesystem,
                    "unknown",
                ),
                (
                    "LICENSE",
                    LicenseScope::Repository,
                    SupplyChainSourceKind::Filesystem,
                    "Apache-2.0",
                ),
                (
                    "skills/zeta/LICENSE.txt",
                    LicenseScope::Skill,
                    SupplyChainSourceKind::Filesystem,
                    "MIT",
                ),
                (
                    "skills/zeta/NOTICE",
                    LicenseScope::Skill,
                    SupplyChainSourceKind::Filesystem,
                    "unknown",
                ),
                (
                    "skills/zeta/SKILL.md",
                    LicenseScope::Skill,
                    SupplyChainSourceKind::Frontmatter,
                    "Zlib",
                ),
            ]
        );
    }

    type LicenseProjection<'a> = (
        &'a str,
        Option<usize>,
        SupplyChainSourceKind,
        LicenseScope,
        &'a str,
        Option<&'a str>,
        EvidenceConfidence,
    );

    fn license_projection(licenses: &[LicenseEvidence]) -> Vec<LicenseProjection<'_>> {
        licenses
            .iter()
            .map(|license| {
                (
                    license.path.as_str(),
                    license.line,
                    license.source,
                    license.scope,
                    license.normalized.as_str(),
                    license.raw.as_deref(),
                    license.confidence,
                )
            })
            .collect()
    }
}
