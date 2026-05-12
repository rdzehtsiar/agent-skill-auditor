// SPDX-License-Identifier: Apache-2.0

use crate::model::{
    BinaryArtifact, BinaryArtifactKind, ChecksumEvidence, ExternalUrl, ExternalUrlKind,
    OfflineReadiness, OfflineReadinessScore, OfflineReadinessStatus, PermissionEvidenceKind,
    PermissionKind, RemoteDependency, RemoteDependencyKind, SkillPackage, SupplyChainInventory,
    SupplyChainSourceKind,
};

const UNPINNED_REMOTE_DEDUCTION: u8 = 15;
const UNPINNED_PACKAGE_DEDUCTION: u8 = 10;
const INSTALL_WITHOUT_LOCKFILE_DEDUCTION: u8 = 20;
const DOWNLOADED_EXECUTABLE_NO_CHECKSUM_DEDUCTION: u8 = 25;
const BINARY_EXECUTABLE_NO_PROVENANCE_DEDUCTION: u8 = 20;
const INVALID_TRUST_MANIFEST_DEDUCTION: u8 = 20;
const PERMISSION_CONFLICT_DEDUCTION: u8 = 20;
const MISSING_LICENSE_DEDUCTION: u8 = 5;

pub fn populate_offline_readiness(inventory: &mut SupplyChainInventory, packages: &[SkillPackage]) {
    inventory.offline_readiness = packages
        .iter()
        .map(|package| offline_readiness_for_package(inventory, package, packages))
        .collect();
    inventory.sort_deterministically();
    inventory.offline_readiness.dedup();
}

fn offline_readiness_for_package(
    inventory: &SupplyChainInventory,
    package: &SkillPackage,
    packages: &[SkillPackage],
) -> OfflineReadiness {
    let scope = PackageScope::new(package, packages);
    let mut deductions = Vec::new();

    add_invalid_trust_manifest_deductions(inventory, &scope, &mut deductions);
    add_permission_conflict_deductions(inventory, &scope, &mut deductions);
    add_download_checksum_deductions(inventory, &scope, &mut deductions);
    add_binary_provenance_deductions(inventory, &scope, &mut deductions);
    add_install_lockfile_deductions(inventory, &scope, &mut deductions);
    add_unpinned_dependency_deductions(inventory, &scope, &mut deductions);
    add_unpinned_url_deductions(inventory, &scope, &mut deductions);
    add_license_deductions(inventory, &scope, &mut deductions);

    deductions.sort();
    deductions.dedup_by(|left, right| left.reason == right.reason);

    let deduction_total = deductions.iter().fold(0u8, |total, deduction| {
        total.saturating_add(deduction.points)
    });
    let score_value = 100u8.saturating_sub(deduction_total);
    let mut reasons = deductions
        .iter()
        .map(|deduction| deduction.reason.clone())
        .collect::<Vec<_>>();
    if reasons.is_empty() {
        reasons.push("local package evidence has no remote or install blockers".to_owned());
    }

    OfflineReadiness {
        path: package.manifest_path.clone(),
        status: status_for_score(score_value),
        score: OfflineReadinessScore::new(score_value),
        reasons,
    }
}

fn add_invalid_trust_manifest_deductions(
    inventory: &SupplyChainInventory,
    scope: &PackageScope<'_>,
    deductions: &mut Vec<Deduction>,
) {
    let count = inventory
        .trust_manifests
        .iter()
        .filter(|manifest| scope.contains(&manifest.path))
        .filter(|manifest| manifest.valid == Some(false))
        .count();
    if count > 0 {
        deductions.push(Deduction::new(
            0,
            INVALID_TRUST_MANIFEST_DEDUCTION,
            format!("{count} invalid trust manifest"),
        ));
    }
}

fn add_permission_conflict_deductions(
    inventory: &SupplyChainInventory,
    scope: &PackageScope<'_>,
    deductions: &mut Vec<Deduction>,
) {
    let declares_network_false = inventory
        .permissions
        .iter()
        .filter(|permission| scope.contains(&permission.path))
        .any(|permission| {
            permission.kind == PermissionKind::Network
                && permission.evidence == PermissionEvidenceKind::Declared
                && permission.normalized == "network=false"
        });
    let observes_network = inventory
        .permissions
        .iter()
        .filter(|permission| scope.contains(&permission.path))
        .any(|permission| {
            permission.kind == PermissionKind::Network
                && permission.evidence == PermissionEvidenceKind::Observed
        });

    if declares_network_false && observes_network {
        deductions.push(Deduction::new(
            1,
            PERMISSION_CONFLICT_DEDUCTION,
            "observed network access conflicts with trust manifest network=false",
        ));
    }
}

fn add_download_checksum_deductions(
    inventory: &SupplyChainInventory,
    scope: &PackageScope<'_>,
    deductions: &mut Vec<Deduction>,
) {
    let count = inventory
        .remote_dependencies
        .iter()
        .filter(|dependency| scope.contains(&dependency.path))
        .filter(|dependency| dependency.kind == RemoteDependencyKind::Artifact)
        .filter(|dependency| downloaded_executable_name(dependency.name.as_deref()))
        .filter(|dependency| !has_checksum_for_name(&dependency.name, &inventory.checksums, scope))
        .count();
    if count > 0 {
        deductions.push(Deduction::new(
            2,
            DOWNLOADED_EXECUTABLE_NO_CHECKSUM_DEDUCTION,
            format!("{count} downloaded executable artifact lacks checksum evidence"),
        ));
    }
}

fn add_binary_provenance_deductions(
    inventory: &SupplyChainInventory,
    scope: &PackageScope<'_>,
    deductions: &mut Vec<Deduction>,
) {
    let count = inventory
        .binaries
        .iter()
        .filter(|binary| scope.contains(&binary.path))
        .filter(|binary| binary.kind == BinaryArtifactKind::Executable)
        .filter(|binary| !has_binary_provenance(binary, inventory, scope))
        .count();
    if count > 0 {
        deductions.push(Deduction::new(
            3,
            BINARY_EXECUTABLE_NO_PROVENANCE_DEDUCTION,
            format!("{count} binary executable lacks local checksum or provenance evidence"),
        ));
    }
}

fn add_install_lockfile_deductions(
    inventory: &SupplyChainInventory,
    scope: &PackageScope<'_>,
    deductions: &mut Vec<Deduction>,
) {
    let count = inventory
        .package_managers
        .iter()
        .filter(|manager| scope.contains(&manager.path))
        .filter(|manager| manager.source == SupplyChainSourceKind::Script)
        .filter(|manager| {
            !inventory.lockfiles.iter().any(|lockfile| {
                scope.contains(&lockfile.path) && lockfile.manager == manager.manager
            })
        })
        .count();
    if count > 0 {
        deductions.push(Deduction::new(
            4,
            INSTALL_WITHOUT_LOCKFILE_DEDUCTION,
            format!("{count} package install command has no matching lockfile"),
        ));
    }
}

fn add_unpinned_dependency_deductions(
    inventory: &SupplyChainInventory,
    scope: &PackageScope<'_>,
    deductions: &mut Vec<Deduction>,
) {
    let unpinned_packages = inventory
        .remote_dependencies
        .iter()
        .filter(|dependency| scope.contains(&dependency.path))
        .filter(|dependency| dependency.kind == RemoteDependencyKind::Package)
        .filter(|dependency| dependency.pinned == Some(false))
        .count();
    if unpinned_packages > 0 {
        deductions.push(Deduction::new(
            5,
            UNPINNED_PACKAGE_DEDUCTION,
            format!("{unpinned_packages} unpinned package dependencies"),
        ));
    }

    let unpinned_remote_dependencies = inventory
        .remote_dependencies
        .iter()
        .filter(|dependency| scope.contains(&dependency.path))
        .filter(|dependency| dependency.kind != RemoteDependencyKind::Package)
        .filter(|dependency| {
            !(dependency.kind == RemoteDependencyKind::Artifact
                && downloaded_executable_name(dependency.name.as_deref())
                && !has_checksum_for_name(&dependency.name, &inventory.checksums, scope))
        })
        .filter(|dependency| dependency.pinned == Some(false))
        .count();
    if unpinned_remote_dependencies > 0 {
        deductions.push(Deduction::new(
            6,
            UNPINNED_REMOTE_DEDUCTION,
            format!("{unpinned_remote_dependencies} unpinned remote dependencies"),
        ));
    }
}

fn add_unpinned_url_deductions(
    inventory: &SupplyChainInventory,
    scope: &PackageScope<'_>,
    deductions: &mut Vec<Deduction>,
) {
    let count = inventory
        .external_urls
        .iter()
        .filter(|url| scope.contains(&url.path))
        .filter(|url| url.pinned == Some(false))
        .filter(|url| !url_has_remote_dependency(url, &inventory.remote_dependencies, scope))
        .count();
    if count > 0 {
        deductions.push(Deduction::new(
            7,
            UNPINNED_REMOTE_DEDUCTION,
            format!("{count} unpinned external URLs"),
        ));
    }
}

fn add_license_deductions(
    inventory: &SupplyChainInventory,
    scope: &PackageScope<'_>,
    deductions: &mut Vec<Deduction>,
) {
    let has_license = inventory
        .licenses
        .iter()
        .any(|license| scope.contains(&license.path));
    if !has_license {
        deductions.push(Deduction::new(
            8,
            MISSING_LICENSE_DEDUCTION,
            "no local license evidence found",
        ));
    }
}

fn status_for_score(score: u8) -> OfflineReadinessStatus {
    match score {
        90..=100 => OfflineReadinessStatus::Ready,
        50..=89 => OfflineReadinessStatus::Partial,
        0..=49 => OfflineReadinessStatus::NotReady,
        _ => OfflineReadinessStatus::Unknown,
    }
}

fn downloaded_executable_name(name: Option<&str>) -> bool {
    name.and_then(|name| name.rsplit('.').next())
        .is_some_and(|extension| {
            matches!(
                extension.to_ascii_lowercase().as_str(),
                "exe" | "dll" | "so" | "dylib" | "bin" | "msi" | "appimage"
            )
        })
}

fn has_binary_provenance(
    binary: &BinaryArtifact,
    inventory: &SupplyChainInventory,
    scope: &PackageScope<'_>,
) -> bool {
    has_checksum_for_path(&binary.path, &binary.raw, &inventory.checksums, scope)
        || inventory
            .trust_manifests
            .iter()
            .filter(|manifest| scope.contains(&manifest.path))
            .any(|manifest| {
                manifest.valid == Some(true)
                    && manifest.provenance.as_ref().is_some_and(|provenance| {
                        provenance
                            .commit
                            .as_deref()
                            .is_some_and(|commit| commit.len() == 40)
                    })
            })
}

fn has_checksum_for_name(
    name: &Option<String>,
    checksums: &[ChecksumEvidence],
    scope: &PackageScope<'_>,
) -> bool {
    name.as_deref().is_some_and(|name| {
        checksums
            .iter()
            .filter(|checksum| scope.contains(&checksum.path))
            .any(|checksum| {
                checksum
                    .target_path
                    .as_deref()
                    .is_some_and(|target| target.ends_with(name))
            })
    })
}

fn has_checksum_for_path(
    path: &str,
    raw: &Option<String>,
    checksums: &[ChecksumEvidence],
    scope: &PackageScope<'_>,
) -> bool {
    checksums
        .iter()
        .filter(|checksum| scope.contains(&checksum.path))
        .any(|checksum| {
            checksum.target_path.as_deref().is_some_and(|target| {
                target == path || raw.as_deref().is_some_and(|raw| target.ends_with(raw))
            })
        })
}

fn url_has_remote_dependency(
    url: &ExternalUrl,
    dependencies: &[RemoteDependency],
    scope: &PackageScope<'_>,
) -> bool {
    dependencies.iter().any(|dependency| {
        scope.contains(&dependency.path)
            && dependency.path == url.path
            && dependency.line == url.line
            && remote_dependency_kind_matches_url_kind(dependency.kind, url.kind)
    })
}

fn remote_dependency_kind_matches_url_kind(
    dependency_kind: RemoteDependencyKind,
    url_kind: ExternalUrlKind,
) -> bool {
    matches!(
        (dependency_kind, url_kind),
        (
            RemoteDependencyKind::Artifact,
            ExternalUrlKind::DownloadedArtifact
        ) | (RemoteDependencyKind::Script, ExternalUrlKind::RemoteScript)
            | (RemoteDependencyKind::Script, ExternalUrlKind::GithubRaw)
            | (
                RemoteDependencyKind::Package,
                ExternalUrlKind::PackageRegistry
            )
    )
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct Deduction {
    priority: u8,
    points: u8,
    reason: String,
}

impl Deduction {
    fn new(priority: u8, points: u8, reason: impl Into<String>) -> Self {
        Self {
            priority,
            points,
            reason: reason.into(),
        }
    }
}

struct PackageScope<'a> {
    root: &'a str,
    manifest_path: &'a str,
    nested_roots: Vec<&'a str>,
}

impl<'a> PackageScope<'a> {
    fn new(package: &'a SkillPackage, packages: &'a [SkillPackage]) -> Self {
        let root = package.root.trim_matches('/');
        let mut nested_roots = nested_package_roots(package, packages, root);
        nested_roots.sort();
        nested_roots.dedup();

        Self {
            root,
            manifest_path: &package.manifest_path,
            nested_roots,
        }
    }

    fn contains(&self, path: &str) -> bool {
        (path == self.manifest_path
            || self.root.is_empty()
            || path == self.root
            || path
                .strip_prefix(self.root)
                .is_some_and(|remainder| remainder.starts_with('/')))
            && !self
                .nested_roots
                .iter()
                .any(|nested_root| path_is_inside_root(path, nested_root))
    }
}

fn nested_package_roots<'a>(
    package: &'a SkillPackage,
    packages: &'a [SkillPackage],
    root: &str,
) -> Vec<&'a str> {
    packages
        .iter()
        .filter_map(|candidate| nested_package_root(package, candidate, root))
        .collect()
}

fn nested_package_root<'a>(
    package: &SkillPackage,
    candidate: &'a SkillPackage,
    root: &str,
) -> Option<&'a str> {
    if candidate.manifest_path == package.manifest_path {
        return None;
    }

    let candidate_root = candidate.root.trim_matches('/');
    (!candidate_root.is_empty() && path_is_inside_root(candidate_root, root))
        .then_some(candidate_root)
}

fn path_is_inside_root(path: &str, root: &str) -> bool {
    root.is_empty()
        || path == root
        || path
            .strip_prefix(root)
            .is_some_and(|remainder| remainder.starts_with('/'))
}

#[cfg(test)]
mod tests {
    use crate::scan::{scan_path, ScanOptions};
    use crate::test_support::TestWorkspace;

    #[test]
    fn all_local_package_scores_ready() {
        let workspace = TestWorkspace::new("offline-ready-score");
        workspace.write_file(
            "SKILL.md",
            "---\nname: ready\ndescription: Local only.\nlicense: Apache-2.0\n---\n\nSee [check](scripts/check.sh).\n",
        );
        workspace.write_file("LICENSE.txt", "Apache-2.0\n");
        workspace.write_file("scripts/check.sh", "#!/usr/bin/env sh\necho ok\n");

        let report = scan_path(workspace.root(), &ScanOptions::default()).expect("scan fixture");
        let readiness = &report.supply_chain.offline_readiness[0];

        assert_eq!(
            readiness.status,
            crate::model::OfflineReadinessStatus::Ready
        );
        assert_eq!(readiness.score.map(u8::from), Some(100));
    }

    #[test]
    fn unpinned_remote_lowers_score() {
        let workspace = TestWorkspace::new("offline-unpinned-remote");
        workspace.write_file(
            "SKILL.md",
            "---\nname: remote\ndescription: Mutable URL.\n---\n\nRun [install](https://raw.githubusercontent.com/example/skill/main/install.sh).\n",
        );

        let report = scan_path(workspace.root(), &ScanOptions::default()).expect("scan fixture");
        let readiness = &report.supply_chain.offline_readiness[0];

        assert_eq!(readiness.score.map(u8::from), Some(80));
        assert_eq!(
            readiness.status,
            crate::model::OfflineReadinessStatus::Partial
        );
        assert!(readiness
            .reasons
            .contains(&"1 unpinned remote dependencies".to_owned()));
    }

    #[test]
    fn package_install_without_lockfile_lowers_score() {
        let workspace = TestWorkspace::new("offline-install-no-lockfile");
        workspace.write_file(
            "SKILL.md",
            "---\nname: install\ndescription: Installs a package.\n---\n\nSee [install](scripts/install.sh).\n",
        );
        workspace.write_file("scripts/install.sh", "npm install prettier@3.2.5\n");

        let report = scan_path(workspace.root(), &ScanOptions::default()).expect("scan fixture");
        let readiness = &report.supply_chain.offline_readiness[0];

        assert_eq!(readiness.score.map(u8::from), Some(75));
        assert!(readiness
            .reasons
            .contains(&"1 package install command has no matching lockfile".to_owned()));
    }

    #[test]
    fn invalid_trust_manifest_and_missing_checksum_lower_score() {
        let workspace = TestWorkspace::new("offline-invalid-trust-download");
        workspace.write_file(
            "SKILL.md",
            "---\nname: invalid-trust\ndescription: Downloads a tool.\n---\n\nSee [install](scripts/install.sh).\n",
        );
        workspace.write_file("agent-audit.trust.yaml", "skill:\n  name: [broken\n");
        workspace.write_file(
            "scripts/install.sh",
            "curl -L https://downloads.example.invalid/helper.exe -o helper.exe\n",
        );

        let report = scan_path(workspace.root(), &ScanOptions::default()).expect("scan fixture");
        let readiness = &report.supply_chain.offline_readiness[0];

        assert_eq!(readiness.score.map(u8::from), Some(50));
        assert_eq!(
            readiness.status,
            crate::model::OfflineReadinessStatus::Partial
        );
        assert!(readiness
            .reasons
            .contains(&"1 invalid trust manifest".to_owned()));
        assert!(readiness
            .reasons
            .contains(&"1 downloaded executable artifact lacks checksum evidence".to_owned()));
    }

    #[test]
    fn score_is_deterministic_and_bounded() {
        let workspace = TestWorkspace::new("offline-score-bounds");
        workspace.write_file(
            "SKILL.md",
            "---\nname: bounds\ndescription: Many blockers.\n---\n\nhttps://raw.githubusercontent.com/example/skill/main/install.sh\n",
        );
        workspace.write_file("agent-audit.trust.yaml", "skill:\n  name: [broken\n");
        workspace.write_file("scripts/a.sh", "npm install one@latest\n");
        workspace.write_file(
            "scripts/b.sh",
            "curl -L https://downloads.example.invalid/tool.exe -o tool.exe\n",
        );
        workspace.write_file("bin/helper.exe", "MZ\x00\x01");

        let first = scan_path(workspace.root(), &ScanOptions::default()).expect("first scan");
        let second = scan_path(workspace.root(), &ScanOptions::default()).expect("second scan");

        assert_eq!(
            first.supply_chain.offline_readiness,
            second.supply_chain.offline_readiness
        );
        assert_eq!(
            first.supply_chain.offline_readiness[0].score.map(u8::from),
            Some(0)
        );
        assert_eq!(
            first.supply_chain.offline_readiness[0].status,
            crate::model::OfflineReadinessStatus::NotReady
        );
    }

    #[test]
    fn root_package_readiness_excludes_nested_skill_evidence() {
        let workspace = TestWorkspace::new("offline-root-excludes-nested");
        workspace.write_file(
            "SKILL.md",
            "---\nname: root\ndescription: Root skill.\nlicense: Apache-2.0\n---\n\nLocal root skill.\n",
        );
        workspace.write_file("LICENSE.txt", "Apache-2.0\n");
        workspace.write_file(
            "nested/SKILL.md",
            "---\nname: nested\ndescription: Nested skill.\n---\n\nSee [install](scripts/install.sh).\n",
        );
        workspace.write_file("nested/scripts/install.sh", "npm install left-pad@latest\n");

        let report = scan_path(workspace.root(), &ScanOptions::default()).expect("scan fixture");
        let root_readiness = report
            .supply_chain
            .offline_readiness
            .iter()
            .find(|readiness| readiness.path == "SKILL.md")
            .expect("root readiness");
        let nested_readiness = report
            .supply_chain
            .offline_readiness
            .iter()
            .find(|readiness| readiness.path == "nested/SKILL.md")
            .expect("nested readiness");

        assert_eq!(root_readiness.score.map(u8::from), Some(100));
        assert_eq!(
            root_readiness.status,
            crate::model::OfflineReadinessStatus::Ready
        );
        assert_eq!(
            root_readiness.reasons,
            vec!["local package evidence has no remote or install blockers"]
        );
        assert!(nested_readiness.score.map(u8::from).unwrap_or(100) < 100);
        assert!(nested_readiness
            .reasons
            .contains(&"1 package install command has no matching lockfile".to_owned()));
    }
}
