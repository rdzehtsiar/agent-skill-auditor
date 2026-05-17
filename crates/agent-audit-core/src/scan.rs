// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeMap;
use std::path::Path;

use crate::artifact_inventory::inventory_package_artifacts;
use crate::config::{AuditConfig, ConfigIgnoreEntry};
use crate::discovery::discover_skill_manifests;
use crate::error::{AuditError, AuditResult};
use crate::license_inventory::{inventory_license_files, inventory_manifest_license};
use crate::model::{
    build_ecosystem_patterns, build_external_url_domain_summaries, build_finding_groups,
    finding_suppression_match_keys, populate_finding_fingerprints, AuditMetadata,
    BinaryArtifactKind, CompatibilityMatrix, DependencyManifestPinningKind, ExternalUrlKind,
    FindingConfidence, LicenseScope, PackageManagerKind, PermissionEvidenceKind, PermissionKind,
    RemoteDependencyKind, ScanReport, ScanSummary, SkillArtifactKind, SkillCompatibilityRow,
    SkillFile, SkillFileKind, SkillFinding, SkillGraph, SkillManifest, SkillPackage,
    SkillReference, SupplyChainInventory, SupplyChainSourceKind, SuppressedFinding,
    SuppressionMatch, TrustManifest, TrustManifestDiagnostic, TrustManifestDiagnosticKind,
};
use crate::offline_readiness::populate_offline_readiness;
use crate::package_inventory::{
    inventory_package_files, inventory_package_installs_from_scripts,
    inventory_package_installs_from_signals,
};
use crate::parse::parse_skill_manifest;
use crate::path_utils::{display_path, sorted_directory_entries};
use crate::permission_reconciliation::{
    inventory_manifest_permissions_and_tools, reconcile_observed_permissions,
};
use crate::trust_manifest::inventory_trust_manifest;
use crate::url_inventory::{dedup_url_inventory, inventory_manifest_urls, inventory_script_urls};
use agent_audit_hosts::{
    profile_by_id, CompatibilityStatus, ProfileCompatibilityResult, HOST_PROFILES,
};
use agent_audit_rules::{
    active_rule_metadata, evaluate_package_install_rules_for_mode,
    evaluate_security_signal_rules_for_mode, evaluate_structural_rules_for_mode,
    evaluate_supply_chain_rules_for_mode, rule_counts_as_broken_reference,
    rule_counts_as_invalid_manifest, EvaluatedRuleFinding, RuleCategory as RegistryCategory,
    RuleDependencyManifestPinningKind, RuleExecutionMode, RuleFrontmatterFieldFact, RuleId,
    RuleMalformedFrontmatterFact, RuleManifestFacts, RulePackageDependencyManifestFact,
    RulePackageFacts, RulePackageFileFact, RulePackageInstallContext, RuleParsedManifestFacts,
    RuleReferenceFact, RuleSeverity as RegistrySeverity, RuleSupplyChainBinaryFact,
    RuleSupplyChainBinaryKind, RuleSupplyChainChecksumFact, RuleSupplyChainDependencyManifestFact,
    RuleSupplyChainFacts, RuleSupplyChainLicenseFact, RuleSupplyChainLicenseScope,
    RuleSupplyChainLockfileFact, RuleSupplyChainPackageFact, RuleSupplyChainPackageManagerFact,
    RuleSupplyChainPackageManagerKind, RuleSupplyChainPermissionEvidenceKind,
    RuleSupplyChainPermissionFact, RuleSupplyChainPermissionKind,
    RuleSupplyChainRemoteDependencyFact, RuleSupplyChainRemoteDependencyKind,
    RuleSupplyChainSourceKind, RuleSupplyChainTrustManifestDiagnosticFact,
    RuleSupplyChainTrustManifestDiagnosticKind, RuleSupplyChainTrustManifestFact,
    RuleSupplyChainUrlFact, RuleSupplyChainUrlKind,
};
use agent_audit_security::{
    analyze_instruction_security_text, classify_security_artifact, javascript_security_analyzer,
    path_target::{has_uri_scheme, has_windows_prefix, strip_query_and_fragment},
    python_security_analyzer, read_security_artifact_bytes, shell_security_analyzer,
    SecurityAnalyzer, SecurityAnalyzerArtifactInput, SecurityAnalyzerContent,
    SecurityAnalyzerInput, SecurityAnalyzerPackageContext,
    SecurityArtifactKind as SecurityScanArtifactKind, SecurityArtifactReadError,
    SecurityArtifactReadPolicy, SecurityDeclaredPermission, SecurityDeclaredTool, SecurityLanguage,
};

const UTF8_BOM: &str = "\u{feff}";
const COMPATIBILITY_FAIL_RULES: &[&str] = &["SKILL001", "SKILL002", "SKILL041"];
const COMPATIBILITY_BASELINE_WARN_RULES: &[&str] = &["SKILL010", "SKILL020", "SKILL030"];
const COMPATIBILITY_FINDING_RULE: &str = "SKILL050";
const UNKNOWN_FRONTMATTER_RULE: &str = "SKILL040";

#[derive(Debug, Clone)]
pub struct ScanOptions {
    pub max_manifest_bytes: u64,
    pub config: Option<AuditConfig>,
}

impl Default for ScanOptions {
    fn default() -> Self {
        Self {
            max_manifest_bytes: 256 * 1024,
            config: None,
        }
    }
}

pub fn scan_path(root: &Path, options: &ScanOptions) -> AuditResult<ScanReport> {
    let manifests = discover_skill_manifests(root)?;
    let profiles = selected_profiles(options.config.as_ref());
    let rule_mode = selected_rule_execution_mode(options.config.as_ref());
    let mut packages = Vec::new();
    let mut package_facts = Vec::new();
    let mut package_install_contexts = Vec::new();
    let mut security_signals = Vec::new();
    let mut supply_chain = SupplyChainInventory::default();

    for manifest_path in manifests {
        let metadata =
            std::fs::metadata(&manifest_path).map_err(|source| AuditError::Metadata {
                path: manifest_path.clone(),
                source,
            })?;
        let skill_root = manifest_path.parent().unwrap_or(root);
        let manifest_display = display_path(root, &manifest_path);
        merge_supply_chain_inventory(
            &mut supply_chain,
            inventory_trust_manifest(root, skill_root)?,
        );
        merge_supply_chain_inventory(&mut supply_chain, inventory_license_files(root, skill_root));
        let package_file_inventory = inventory_package_files(root, skill_root)?;
        merge_supply_chain_inventory(&mut supply_chain, package_file_inventory.clone());

        if metadata.len() > options.max_manifest_bytes {
            package_facts.push(RulePackageFacts {
                manifest_path: manifest_display.clone(),
                manifest: RuleManifestFacts::UnreadOversized,
            });
            packages.push(SkillPackage {
                root: display_path(root, skill_root),
                manifest_path: manifest_display,
                manifest: empty_skill_manifest(),
                graph: empty_skill_graph(),
            });
            continue;
        }

        let content =
            std::fs::read_to_string(&manifest_path).map_err(|source| AuditError::Read {
                path: manifest_path.clone(),
                source,
            })?;
        security_signals.extend(analyze_instruction_security_text(
            &manifest_display,
            &content,
        ));
        let manifest = match parse_skill_manifest(&manifest_path, &content) {
            Ok(manifest) => manifest,
            Err(AuditError::Frontmatter { source, .. }) => {
                package_facts.push(RulePackageFacts {
                    manifest_path: manifest_display.clone(),
                    manifest: RuleManifestFacts::MalformedFrontmatter(
                        RuleMalformedFrontmatterFact {
                            line: source.location().map(|location| location.line() + 1),
                            parse_message: source.to_string(),
                        },
                    ),
                });
                packages.push(SkillPackage {
                    root: display_path(root, skill_root),
                    manifest_path: manifest_display,
                    manifest: empty_skill_manifest(),
                    graph: empty_skill_graph(),
                });
                continue;
            }
            Err(AuditError::FrontmatterDelimiter { line, message, .. }) => {
                package_facts.push(RulePackageFacts {
                    manifest_path: manifest_display.clone(),
                    manifest: RuleManifestFacts::MalformedFrontmatter(
                        RuleMalformedFrontmatterFact {
                            line: Some(line),
                            parse_message: message,
                        },
                    ),
                });
                packages.push(SkillPackage {
                    root: display_path(root, skill_root),
                    manifest_path: manifest_display,
                    manifest: empty_skill_manifest(),
                    graph: empty_skill_graph(),
                });
                continue;
            }
            Err(error) => return Err(error),
        };
        let frontmatter_key_lines = frontmatter_key_lines(&content);
        let mut graph = SkillGraph {
            references: resolve_references(skill_root, &manifest.links),
            artifacts: discover_artifacts(skill_root),
            files: inventory_artifact_files(skill_root)?,
        };
        graph
            .references
            .sort_by(|left, right| left.target.cmp(&right.target));
        security_signals.extend(analyze_package_security_artifacts(
            root,
            skill_root,
            &manifest_display,
            &manifest,
            &graph,
        )?);
        merge_supply_chain_inventory(
            &mut supply_chain,
            inventory_manifest_urls(&manifest_display, &manifest, &frontmatter_key_lines),
        );
        merge_supply_chain_inventory(
            &mut supply_chain,
            inventory_manifest_license(&manifest_display, &manifest, &frontmatter_key_lines),
        );
        merge_supply_chain_inventory(
            &mut supply_chain,
            inventory_manifest_permissions_and_tools(
                &manifest_display,
                &manifest,
                frontmatter_key_lines.get("permissions").copied(),
                frontmatter_key_lines.get("tools").copied(),
            ),
        );
        merge_supply_chain_inventory(
            &mut supply_chain,
            inventory_script_artifact_urls(root, skill_root, &graph)?,
        );
        merge_supply_chain_inventory(
            &mut supply_chain,
            inventory_package_installs_from_scripts(root, skill_root, &graph)?,
        );
        merge_supply_chain_inventory(
            &mut supply_chain,
            inventory_package_artifacts(root, skill_root, &manifest, &graph)?,
        );

        let frontmatter_fields = manifest
            .frontmatter
            .keys()
            .filter(|field| !is_profile_accepted_frontmatter_field(&profiles, field))
            .map(|field| RuleFrontmatterFieldFact {
                name: field.clone(),
                line: frontmatter_key_lines.get(field.as_str()).copied(),
            })
            .collect();

        package_facts.push(RulePackageFacts {
            manifest_path: manifest_display.clone(),
            manifest: RuleManifestFacts::Parsed(RuleParsedManifestFacts {
                name: manifest.name.clone(),
                description: manifest.description.clone(),
                frontmatter_fields,
                references: graph
                    .references
                    .iter()
                    .map(|reference| RuleReferenceFact {
                        target: reference.target.clone(),
                        line: reference.line,
                        exists: reference.exists,
                    })
                    .collect(),
                oversized: content.len() as u64 > options.max_manifest_bytes,
            }),
        });
        package_install_contexts.push(package_install_context(
            root,
            skill_root,
            &manifest_display,
            &graph,
            &package_file_inventory,
        )?);

        packages.push(SkillPackage {
            root: display_path(root, skill_root),
            manifest_path: manifest_display,
            manifest,
            graph,
        });
    }

    let mut findings = evaluate_structural_rules_for_mode(&package_facts, rule_mode)
        .into_iter()
        .map(skill_finding_from_evaluated_rule)
        .collect::<Vec<_>>();
    findings.extend(
        evaluate_security_signal_rules_for_mode(&security_signals, rule_mode)
            .into_iter()
            .map(skill_finding_from_evaluated_rule),
    );
    findings.extend(
        evaluate_package_install_rules_for_mode(
            &security_signals,
            &package_install_contexts,
            rule_mode,
        )
        .into_iter()
        .map(skill_finding_from_evaluated_rule),
    );
    merge_supply_chain_inventory(
        &mut supply_chain,
        inventory_package_installs_from_signals(&security_signals),
    );
    reconcile_observed_permissions(&mut supply_chain, &security_signals);
    populate_offline_readiness(&mut supply_chain, &packages);
    supply_chain.external_url_domains =
        build_external_url_domain_summaries(&packages, &supply_chain.external_urls);
    findings.extend(
        evaluate_supply_chain_rules_for_mode(
            &supply_chain_rule_facts(options.config.as_ref(), &packages, &supply_chain),
            rule_mode,
        )
        .into_iter()
        .map(skill_finding_from_evaluated_rule),
    );
    findings.extend(evaluate_compatibility_findings(
        &packages,
        options.config.as_ref(),
    ));
    sort_skill_findings(&mut findings);
    populate_finding_fingerprints(&mut findings);
    let (findings, suppressed_findings) = apply_suppressions(findings, options.config.as_ref());

    let invalid_manifest_count = findings
        .iter()
        .filter(|finding| rule_counts_as_invalid_manifest(&finding.rule_id))
        .count();
    let broken_reference_count = findings
        .iter()
        .filter(|finding| rule_counts_as_broken_reference(&finding.rule_id))
        .count();
    let actual_secret_evidence_count = actual_secret_evidence_count(&findings, &supply_chain);
    let prompt_secret_exposure_count = prompt_secret_exposure_count(&findings);

    let compatibility =
        compatibility_matrix_for_packages(&packages, &findings, options.config.as_ref());
    let finding_groups = build_finding_groups(&packages, &findings, &compatibility);
    let patterns = build_ecosystem_patterns(&packages, &findings, &finding_groups, &supply_chain);

    Ok(ScanReport {
        audit: AuditMetadata::default().with_selected_profiles(compatibility.profiles.clone()),
        summary: ScanSummary {
            package_count: packages.len(),
            finding_count: findings.len(),
            suppressed_finding_count: suppressed_findings.len(),
            invalid_manifest_count,
            broken_reference_count,
            actual_secret_evidence_count,
            prompt_secret_exposure_count,
        },
        packages,
        findings,
        finding_groups,
        patterns,
        suppressed_findings,
        supply_chain,
        compatibility,
    })
}

fn actual_secret_evidence_count(
    findings: &[SkillFinding],
    supply_chain: &SupplyChainInventory,
) -> usize {
    findings
        .iter()
        .filter(|finding| is_actual_secret_evidence_finding(finding))
        .count()
        + supply_chain
            .permissions
            .iter()
            .filter(|permission| permission.kind == PermissionKind::Secrets)
            .count()
}

fn prompt_secret_exposure_count(findings: &[SkillFinding]) -> usize {
    findings
        .iter()
        .filter(|finding| is_prompt_secret_exposure_finding(finding))
        .count()
}

fn is_actual_secret_evidence_finding(finding: &SkillFinding) -> bool {
    finding.rule_id == "SEC002"
        || (finding.rule_id == "SEC003"
            && (contains_secret_signal_word(&finding.title)
                || contains_secret_signal_word(&finding.message)
                || contains_secret_signal_word(&finding.rationale)))
}

fn is_prompt_secret_exposure_finding(finding: &SkillFinding) -> bool {
    matches!(finding.rule_id.as_str(), "SEC011" | "SEC012")
        && (contains_secret_signal_word(&finding.title)
            || contains_secret_signal_word(&finding.message)
            || contains_secret_signal_word(&finding.rationale))
}

fn contains_secret_signal_word(value: &str) -> bool {
    let value = value.to_ascii_lowercase();
    value.contains("secret") || value.contains("credential") || value.contains("token")
}

fn merge_supply_chain_inventory(
    target: &mut SupplyChainInventory,
    mut source: SupplyChainInventory,
) {
    target.licenses.append(&mut source.licenses);
    target.trust_manifests.append(&mut source.trust_manifests);
    target.external_urls.append(&mut source.external_urls);
    target
        .external_url_domains
        .append(&mut source.external_url_domains);
    target
        .remote_dependencies
        .append(&mut source.remote_dependencies);
    target
        .dependency_manifests
        .append(&mut source.dependency_manifests);
    target.package_managers.append(&mut source.package_managers);
    target.lockfiles.append(&mut source.lockfiles);
    target.executables.append(&mut source.executables);
    target.binaries.append(&mut source.binaries);
    target.checksums.append(&mut source.checksums);
    target.permissions.append(&mut source.permissions);
    target
        .offline_readiness
        .append(&mut source.offline_readiness);
    dedup_url_inventory(target);
    dedup_supply_chain_inventory(target);
}

fn dedup_supply_chain_inventory(inventory: &mut SupplyChainInventory) {
    inventory.sort_deterministically();
    inventory.licenses.dedup();
    inventory.trust_manifests.dedup();
    inventory.external_urls.dedup();
    inventory.external_url_domains.dedup();
    inventory.remote_dependencies.dedup();
    inventory.dependency_manifests.dedup();
    inventory.package_managers.dedup();
    inventory.lockfiles.dedup();
    inventory.executables.dedup();
    inventory.binaries.dedup();
    inventory.checksums.dedup();
    inventory.permissions.dedup();
    inventory.offline_readiness.dedup();
}

fn supply_chain_rule_facts(
    _config: Option<&AuditConfig>,
    packages: &[SkillPackage],
    inventory: &SupplyChainInventory,
) -> RuleSupplyChainFacts {
    RuleSupplyChainFacts {
        packages: packages
            .iter()
            .map(|package| RuleSupplyChainPackageFact {
                root: package.root.clone(),
                manifest_path: package.manifest_path.clone(),
            })
            .collect(),
        licenses: inventory
            .licenses
            .iter()
            .map(|license| RuleSupplyChainLicenseFact {
                path: license.path.clone(),
                line: license.line,
                scope: match license.scope {
                    LicenseScope::Repository => RuleSupplyChainLicenseScope::Repository,
                    LicenseScope::Skill => RuleSupplyChainLicenseScope::Skill,
                },
                normalized: license.normalized.clone(),
            })
            .collect(),
        trust_manifests: inventory
            .trust_manifests
            .iter()
            .map(rule_supply_chain_trust_manifest_fact)
            .collect(),
        external_urls: inventory
            .external_urls
            .iter()
            .map(|url| RuleSupplyChainUrlFact {
                path: url.path.clone(),
                line: url.line,
                kind: match url.kind {
                    ExternalUrlKind::GithubRaw => RuleSupplyChainUrlKind::GithubRaw,
                    ExternalUrlKind::RemoteScript => RuleSupplyChainUrlKind::RemoteScript,
                    ExternalUrlKind::DownloadedArtifact => {
                        RuleSupplyChainUrlKind::DownloadedArtifact
                    }
                    _ => RuleSupplyChainUrlKind::Other,
                },
                normalized: url.normalized.clone(),
                pinned: url.pinned,
            })
            .collect(),
        remote_dependencies: inventory
            .remote_dependencies
            .iter()
            .map(|dependency| RuleSupplyChainRemoteDependencyFact {
                path: dependency.path.clone(),
                line: dependency.line,
                kind: match dependency.kind {
                    RemoteDependencyKind::Package => RuleSupplyChainRemoteDependencyKind::Package,
                    RemoteDependencyKind::Script => RuleSupplyChainRemoteDependencyKind::Script,
                    RemoteDependencyKind::Artifact => RuleSupplyChainRemoteDependencyKind::Artifact,
                    _ => RuleSupplyChainRemoteDependencyKind::Other,
                },
                package_manager: dependency.package_manager.map(rule_package_manager_kind),
                name: dependency.name.clone(),
                version: dependency.version.clone(),
                normalized: dependency.normalized.clone(),
                pinned: dependency.pinned,
            })
            .collect(),
        dependency_manifests: inventory
            .dependency_manifests
            .iter()
            .map(|manifest| RuleSupplyChainDependencyManifestFact {
                path: manifest.path.clone(),
                manager: rule_package_manager_kind(manifest.manager),
                pinning: rule_dependency_manifest_pinning(manifest.pinning),
            })
            .collect(),
        package_managers: inventory
            .package_managers
            .iter()
            .map(|manager| RuleSupplyChainPackageManagerFact {
                path: manager.path.clone(),
                line: manager.line,
                source: match manager.source {
                    SupplyChainSourceKind::Script => RuleSupplyChainSourceKind::Script,
                    _ => RuleSupplyChainSourceKind::Other,
                },
                manager: rule_package_manager_kind(manager.manager),
                raw: manager.raw.clone(),
            })
            .collect(),
        lockfiles: inventory
            .lockfiles
            .iter()
            .map(|lockfile| RuleSupplyChainLockfileFact {
                path: lockfile.path.clone(),
                manager: rule_package_manager_kind(lockfile.manager),
            })
            .collect(),
        binaries: inventory
            .binaries
            .iter()
            .map(|binary| RuleSupplyChainBinaryFact {
                path: binary.path.clone(),
                line: binary.line,
                kind: match binary.kind {
                    BinaryArtifactKind::Executable => RuleSupplyChainBinaryKind::Executable,
                    _ => RuleSupplyChainBinaryKind::Other,
                },
                raw: binary.raw.clone(),
            })
            .collect(),
        checksums: inventory
            .checksums
            .iter()
            .map(|checksum| RuleSupplyChainChecksumFact {
                path: checksum.path.clone(),
                target_path: checksum.target_path.clone(),
            })
            .collect(),
        permissions: inventory
            .permissions
            .iter()
            .map(|permission| RuleSupplyChainPermissionFact {
                path: permission.path.clone(),
                line: permission.line,
                kind: match permission.kind {
                    PermissionKind::Network => RuleSupplyChainPermissionKind::Network,
                    _ => RuleSupplyChainPermissionKind::Other,
                },
                evidence: match permission.evidence {
                    PermissionEvidenceKind::Declared => {
                        RuleSupplyChainPermissionEvidenceKind::Declared
                    }
                    PermissionEvidenceKind::Observed => {
                        RuleSupplyChainPermissionEvidenceKind::Observed
                    }
                },
                normalized: permission.normalized.clone(),
            })
            .collect(),
    }
}

fn rule_supply_chain_trust_manifest_fact(
    manifest: &TrustManifest,
) -> RuleSupplyChainTrustManifestFact {
    RuleSupplyChainTrustManifestFact {
        path: manifest.path.clone(),
        line: manifest.line,
        valid: manifest.valid,
        has_pinned_provenance: trust_manifest_has_pinned_provenance(manifest),
        diagnostics: manifest
            .diagnostics
            .iter()
            .map(rule_supply_chain_trust_manifest_diagnostic_fact)
            .collect(),
    }
}

fn trust_manifest_has_pinned_provenance(manifest: &TrustManifest) -> bool {
    manifest.provenance.as_ref().is_some_and(|provenance| {
        provenance
            .commit
            .as_deref()
            .is_some_and(|commit| commit.len() == 40)
    })
}

fn rule_supply_chain_trust_manifest_diagnostic_fact(
    diagnostic: &TrustManifestDiagnostic,
) -> RuleSupplyChainTrustManifestDiagnosticFact {
    RuleSupplyChainTrustManifestDiagnosticFact {
        path: diagnostic.path.clone(),
        line: diagnostic.line,
        kind: rule_trust_manifest_diagnostic_kind(diagnostic.kind),
        message: diagnostic.message.clone(),
        field: diagnostic.field.clone(),
    }
}

fn rule_trust_manifest_diagnostic_kind(
    kind: TrustManifestDiagnosticKind,
) -> RuleSupplyChainTrustManifestDiagnosticKind {
    match kind {
        TrustManifestDiagnosticKind::ParseError => {
            RuleSupplyChainTrustManifestDiagnosticKind::ParseError
        }
        TrustManifestDiagnosticKind::SchemaError => {
            RuleSupplyChainTrustManifestDiagnosticKind::SchemaError
        }
        TrustManifestDiagnosticKind::UnknownField => {
            RuleSupplyChainTrustManifestDiagnosticKind::UnknownField
        }
    }
}

fn rule_package_manager_kind(manager: PackageManagerKind) -> RuleSupplyChainPackageManagerKind {
    match manager {
        PackageManagerKind::Npm => RuleSupplyChainPackageManagerKind::Npm,
        PackageManagerKind::Yarn => RuleSupplyChainPackageManagerKind::Yarn,
        PackageManagerKind::Pnpm => RuleSupplyChainPackageManagerKind::Pnpm,
        PackageManagerKind::Pip => RuleSupplyChainPackageManagerKind::Pip,
        PackageManagerKind::Poetry => RuleSupplyChainPackageManagerKind::Poetry,
        PackageManagerKind::Uv => RuleSupplyChainPackageManagerKind::Uv,
        PackageManagerKind::Cargo => RuleSupplyChainPackageManagerKind::Cargo,
        PackageManagerKind::Go => RuleSupplyChainPackageManagerKind::Go,
        PackageManagerKind::Gem => RuleSupplyChainPackageManagerKind::Gem,
        PackageManagerKind::Composer => RuleSupplyChainPackageManagerKind::Composer,
        PackageManagerKind::Unknown => RuleSupplyChainPackageManagerKind::Unknown,
    }
}

fn rule_dependency_manifest_pinning(
    pinning: DependencyManifestPinningKind,
) -> RuleDependencyManifestPinningKind {
    match pinning {
        DependencyManifestPinningKind::ExactPinned => {
            RuleDependencyManifestPinningKind::ExactPinned
        }
        DependencyManifestPinningKind::RangeBased => RuleDependencyManifestPinningKind::RangeBased,
        DependencyManifestPinningKind::Unknown => RuleDependencyManifestPinningKind::Unknown,
    }
}

fn compatibility_matrix_for_packages(
    packages: &[SkillPackage],
    findings: &[SkillFinding],
    config: Option<&AuditConfig>,
) -> CompatibilityMatrix {
    let profiles = selected_profiles(config);
    let matrix = packages
        .iter()
        .map(|package| SkillCompatibilityRow {
            path: package.manifest_path.clone(),
            name: package.manifest.name.clone(),
            profiles: profiles
                .iter()
                .map(|profile| compatibility_for_profile(profile, package, findings))
                .collect(),
        })
        .collect();

    CompatibilityMatrix { profiles, matrix }
}

fn compatibility_for_profile(
    profile: &str,
    package: &SkillPackage,
    findings: &[SkillFinding],
) -> ProfileCompatibilityResult {
    match profile {
        "agent-skills-spec" => evaluate_baseline_structural_profile(profile, package, findings),
        "claude-code" => evaluate_claude_code_profile(profile, package, findings),
        "codex" => evaluate_codex_profile(profile, package, findings),
        "github-copilot" => evaluate_github_copilot_profile(profile, package, findings),
        "vscode-copilot" => evaluate_vscode_copilot_profile(profile, package, findings),
        "generic" => evaluate_baseline_structural_profile(profile, package, findings),
        _ => ProfileCompatibilityResult {
            profile: profile.to_owned(),
            status: CompatibilityStatus::Untested,
            finding_ids: Vec::new(),
        },
    }
}

fn evaluate_claude_code_profile(
    profile: &str,
    package: &SkillPackage,
    findings: &[SkillFinding],
) -> ProfileCompatibilityResult {
    evaluate_host_profile(
        HostProfileEvaluation {
            profile,
            compatibility_message_prefix: "Claude Code ",
            has_unknown_frontmatter_field: has_claude_unknown_frontmatter_field(package),
            has_matrix_warning: !is_claude_preferred_manifest_path(&package.manifest_path)
                || has_script_reference_or_artifact(package),
        },
        package,
        findings,
    )
}

fn evaluate_codex_profile(
    profile: &str,
    package: &SkillPackage,
    findings: &[SkillFinding],
) -> ProfileCompatibilityResult {
    evaluate_host_profile(
        HostProfileEvaluation {
            profile,
            compatibility_message_prefix: "Codex ",
            has_unknown_frontmatter_field: has_codex_unknown_frontmatter_field(package),
            has_matrix_warning: !is_codex_preferred_manifest_path(&package.manifest_path)
                || has_script_reference_or_artifact(package)
                || has_permission_metadata(package),
        },
        package,
        findings,
    )
}

fn evaluate_github_copilot_profile(
    profile: &str,
    package: &SkillPackage,
    findings: &[SkillFinding],
) -> ProfileCompatibilityResult {
    evaluate_host_profile(
        HostProfileEvaluation {
            profile,
            compatibility_message_prefix: "GitHub Copilot ",
            has_unknown_frontmatter_field: has_github_copilot_unknown_frontmatter_field(package),
            has_matrix_warning: !is_github_copilot_preferred_manifest_path(&package.manifest_path)
                || has_script_reference_or_artifact(package)
                || has_permission_metadata(package),
        },
        package,
        findings,
    )
}

fn evaluate_vscode_copilot_profile(
    profile: &str,
    package: &SkillPackage,
    findings: &[SkillFinding],
) -> ProfileCompatibilityResult {
    evaluate_host_profile(
        HostProfileEvaluation {
            profile,
            compatibility_message_prefix: "VS Code Copilot ",
            has_unknown_frontmatter_field: has_vscode_copilot_unknown_frontmatter_field(package),
            has_matrix_warning: !is_vscode_copilot_preferred_manifest_path(&package.manifest_path)
                || has_script_reference_or_artifact(package)
                || has_permission_metadata(package),
        },
        package,
        findings,
    )
}

fn evaluate_baseline_structural_profile(
    profile: &str,
    package: &SkillPackage,
    findings: &[SkillFinding],
) -> ProfileCompatibilityResult {
    const WARN_RULES: &[&str] = &["SKILL010", "SKILL020", "SKILL030", "SKILL040"];

    let finding_ids = compatibility_finding_ids_for_package(
        &package.manifest_path,
        findings,
        COMPATIBILITY_FAIL_RULES.iter().chain(WARN_RULES),
    );
    let status = compatibility_status(&finding_ids, false);

    ProfileCompatibilityResult {
        profile: profile.to_owned(),
        status,
        finding_ids,
    }
}

struct HostProfileEvaluation<'a> {
    profile: &'a str,
    compatibility_message_prefix: &'a str,
    has_unknown_frontmatter_field: bool,
    has_matrix_warning: bool,
}

fn evaluate_host_profile(
    evaluation: HostProfileEvaluation<'_>,
    package: &SkillPackage,
    findings: &[SkillFinding],
) -> ProfileCompatibilityResult {
    let rule_order = host_profile_rule_order(evaluation.has_unknown_frontmatter_field);
    let finding_ids = compatibility_finding_ids_for_package_matching(
        &package.manifest_path,
        findings,
        rule_order.iter(),
        |finding| {
            finding.rule_id != COMPATIBILITY_FINDING_RULE
                || finding
                    .message
                    .starts_with(evaluation.compatibility_message_prefix)
        },
    );

    ProfileCompatibilityResult {
        profile: evaluation.profile.to_owned(),
        status: compatibility_status(&finding_ids, evaluation.has_matrix_warning),
        finding_ids,
    }
}

fn host_profile_rule_order(include_unknown_frontmatter_rule: bool) -> Vec<&'static str> {
    let mut rule_order = COMPATIBILITY_FAIL_RULES
        .iter()
        .chain(COMPATIBILITY_BASELINE_WARN_RULES)
        .copied()
        .chain([COMPATIBILITY_FINDING_RULE])
        .collect::<Vec<_>>();

    if include_unknown_frontmatter_rule {
        rule_order.push(UNKNOWN_FRONTMATTER_RULE);
    }

    rule_order.sort_unstable();
    rule_order.dedup();
    rule_order
}

fn compatibility_status(finding_ids: &[String], has_matrix_warning: bool) -> CompatibilityStatus {
    if has_compatibility_failure(finding_ids) {
        CompatibilityStatus::Fail
    } else if !finding_ids.is_empty() {
        CompatibilityStatus::Warn
    } else if has_matrix_warning {
        CompatibilityStatus::Unknown
    } else {
        CompatibilityStatus::Pass
    }
}

fn has_compatibility_failure(finding_ids: &[String]) -> bool {
    finding_ids
        .iter()
        .any(|rule_id| COMPATIBILITY_FAIL_RULES.contains(&rule_id.as_str()))
}

fn compatibility_finding_ids_for_package<'a>(
    manifest_path: &str,
    findings: &[SkillFinding],
    rule_order: impl Iterator<Item = &'a &'a str>,
) -> Vec<String> {
    compatibility_finding_ids_for_package_matching(manifest_path, findings, rule_order, |_| true)
}

fn compatibility_finding_ids_for_package_matching<'a>(
    manifest_path: &str,
    findings: &[SkillFinding],
    rule_order: impl Iterator<Item = &'a &'a str>,
    include_finding: impl Fn(&SkillFinding) -> bool,
) -> Vec<String> {
    rule_order
        .filter(|rule_id| {
            findings.iter().any(|finding| {
                finding.rule_id == **rule_id
                    && finding.location.path == manifest_path
                    && include_finding(finding)
            })
        })
        .map(|rule_id| (*rule_id).to_owned())
        .collect()
}

fn evaluate_compatibility_findings(
    packages: &[SkillPackage],
    config: Option<&AuditConfig>,
) -> Vec<SkillFinding> {
    let profiles = selected_profiles(config);
    let include_claude = profiles.iter().any(|profile| profile == "claude-code");
    let include_codex = profiles.iter().any(|profile| profile == "codex");
    let include_github_copilot = profiles.iter().any(|profile| profile == "github-copilot");
    let include_vscode_copilot = profiles.iter().any(|profile| profile == "vscode-copilot");

    let mut findings = Vec::new();
    if include_claude {
        findings.extend(
            packages
                .iter()
                .filter(|package| is_claude_preferred_manifest_path(&package.manifest_path))
                .flat_map(claude_code_metadata_findings),
        );
    }
    if include_codex {
        findings.extend(
            packages
                .iter()
                .filter(|package| is_codex_preferred_manifest_path(&package.manifest_path))
                .flat_map(codex_metadata_findings),
        );
    }
    if include_github_copilot {
        findings.extend(
            packages
                .iter()
                .filter(|package| is_github_copilot_preferred_manifest_path(&package.manifest_path))
                .flat_map(github_copilot_metadata_findings),
        );
    }
    if include_vscode_copilot {
        findings.extend(
            packages
                .iter()
                .filter(|package| is_vscode_copilot_preferred_manifest_path(&package.manifest_path))
                .flat_map(vscode_copilot_metadata_findings),
        );
    }

    findings
}

fn claude_code_metadata_findings(package: &SkillPackage) -> Vec<SkillFinding> {
    const IGNORED_FIELDS: &[&str] = &["permissions", "tools"];

    package
        .manifest
        .frontmatter
        .keys()
        .filter(|field| IGNORED_FIELDS.contains(&field.as_str()))
        .map(|field| {
            compatibility_finding(
                "SKILL050",
                format!(
                    "Claude Code is likely to ignore the `{field}` frontmatter field; use `allowed-tools` for Claude tool allowlists or move advisory metadata into the Markdown body."
                ),
                package.manifest_path.clone(),
                Some(1),
            )
        })
        .collect()
}

fn codex_metadata_findings(package: &SkillPackage) -> Vec<SkillFinding> {
    ignored_frontmatter_findings(package, "codex", |field| {
        format!(
                "Codex is likely to ignore the `{field}` frontmatter field; document Codex tool or permission expectations with portable `tools` metadata or in the Markdown body."
            )
    })
}

fn github_copilot_metadata_findings(package: &SkillPackage) -> Vec<SkillFinding> {
    ignored_frontmatter_findings(package, "github-copilot", |field| {
        format!(
                "GitHub Copilot is likely to ignore the `{field}` frontmatter field; document GitHub Copilot tool expectations with portable `tools` metadata or in the Markdown body."
            )
    })
}

fn vscode_copilot_metadata_findings(package: &SkillPackage) -> Vec<SkillFinding> {
    ignored_frontmatter_findings(package, "vscode-copilot", |field| {
        format!(
                "VS Code Copilot is likely to ignore the `{field}` frontmatter field; document VS Code Copilot tool expectations with portable `tools` metadata or in the Markdown body."
            )
    })
}

fn ignored_frontmatter_findings(
    package: &SkillPackage,
    profile: &str,
    message_for_field: impl Fn(&str) -> String,
) -> Vec<SkillFinding> {
    let ignored_fields = profile_by_id(profile)
        .unwrap_or_else(|| panic!("{profile} profile definition must exist"))
        .known_ignored_fields;

    package
        .manifest
        .frontmatter
        .keys()
        .filter(|field| is_ignored_frontmatter_field(ignored_fields, field))
        .map(|field| {
            compatibility_finding(
                COMPATIBILITY_FINDING_RULE,
                message_for_field(field),
                package.manifest_path.clone(),
                Some(1),
            )
        })
        .collect()
}

fn is_ignored_frontmatter_field(
    ignored_fields: &[agent_audit_hosts::ManifestField],
    field: &str,
) -> bool {
    ignored_fields
        .iter()
        .any(|ignored_field| ignored_field.name == field)
}

fn compatibility_finding(
    rule_id: &str,
    message: String,
    path: String,
    line: Option<usize>,
) -> SkillFinding {
    let metadata = active_rule_metadata(rule_id)
        .expect("compatibility finding must have active registry metadata");

    SkillFinding {
        rule_id: metadata.id.as_str().to_owned(),
        fingerprint: String::new(),
        severity: severity_from_metadata(metadata.severity),
        confidence: FindingConfidence::Medium,
        category: category_from_metadata(metadata.category),
        title: metadata.title.to_owned(),
        message,
        location: crate::model::FindingLocation { path, line },
        rationale: metadata.rationale.to_owned(),
        remediation: metadata.remediation.to_owned(),
        suppression: metadata.suppression_guidance.to_owned(),
    }
}

fn sort_skill_findings(findings: &mut [SkillFinding]) {
    findings.sort_by(|left, right| {
        left.location
            .path
            .cmp(&right.location.path)
            .then(left.location.line.cmp(&right.location.line))
            .then(left.rule_id.cmp(&right.rule_id))
            .then(left.message.cmp(&right.message))
    });
}

fn has_claude_unknown_frontmatter_field(package: &SkillPackage) -> bool {
    const ACCEPTED_FIELDS: &[&str] = &["allowed-tools", "description", "name"];
    const KNOWN_IGNORED_FIELDS: &[&str] = &["permissions", "tools"];

    package.manifest.frontmatter.keys().any(|field| {
        !ACCEPTED_FIELDS.contains(&field.as_str())
            && !KNOWN_IGNORED_FIELDS.contains(&field.as_str())
    })
}

fn has_codex_unknown_frontmatter_field(package: &SkillPackage) -> bool {
    has_unknown_profile_frontmatter_field(package, "codex", &["permissions"])
}

fn has_github_copilot_unknown_frontmatter_field(package: &SkillPackage) -> bool {
    has_unknown_profile_frontmatter_field(package, "github-copilot", &[])
}

fn has_vscode_copilot_unknown_frontmatter_field(package: &SkillPackage) -> bool {
    has_unknown_profile_frontmatter_field(package, "vscode-copilot", &[])
}

fn has_unknown_profile_frontmatter_field(
    package: &SkillPackage,
    profile: &str,
    additionally_known_fields: &[&str],
) -> bool {
    let profile =
        profile_by_id(profile).unwrap_or_else(|| panic!("{profile} profile definition must exist"));

    package.manifest.frontmatter.keys().any(|field| {
        !is_known_profile_frontmatter_field(profile, field)
            && !additionally_known_fields.contains(&field.as_str())
    })
}

fn is_known_profile_frontmatter_field(
    profile: &agent_audit_hosts::HostProfile,
    field: &str,
) -> bool {
    profile
        .required_fields
        .iter()
        .chain(profile.accepted_optional_fields)
        .chain(profile.known_ignored_fields)
        .any(|known_field| known_field.name == field)
}

fn is_profile_accepted_frontmatter_field(profiles: &[String], field: &str) -> bool {
    is_claude_accepted_frontmatter_field(profiles, field)
}

fn is_claude_accepted_frontmatter_field(profiles: &[String], field: &str) -> bool {
    field == "allowed-tools" && profiles.iter().any(|profile| profile == "claude-code")
}

fn is_claude_preferred_manifest_path(path: &str) -> bool {
    is_direct_skill_manifest_under(path, ".claude/skills/")
}

fn is_codex_preferred_manifest_path(path: &str) -> bool {
    is_direct_skill_manifest_under(path, ".agents/skills/")
}

fn is_github_copilot_preferred_manifest_path(path: &str) -> bool {
    is_direct_skill_manifest_under(path, ".github/skills/")
}

fn is_vscode_copilot_preferred_manifest_path(path: &str) -> bool {
    is_direct_skill_manifest_under(path, ".github/skills/")
}

fn is_direct_skill_manifest_under(path: &str, prefix: &str) -> bool {
    let path = normalize_report_path(path);
    let Some(skill_path) = path.strip_prefix(prefix) else {
        return false;
    };
    let Some(skill_name) = skill_path.strip_suffix("/SKILL.md") else {
        return false;
    };

    !skill_name.is_empty() && !skill_name.contains('/')
}

fn has_permission_metadata(package: &SkillPackage) -> bool {
    package.manifest.frontmatter.contains_key("permissions")
}

fn has_script_reference_or_artifact(package: &SkillPackage) -> bool {
    package
        .graph
        .references
        .iter()
        .any(|reference| normalize_report_path(&reference.target).starts_with("scripts/"))
        || package
            .graph
            .files
            .iter()
            .any(|file| file.artifact == SkillArtifactKind::Scripts)
        || package
            .graph
            .artifacts
            .iter()
            .any(|artifact| artifact == "scripts")
}

fn selected_profiles(config: Option<&AuditConfig>) -> Vec<String> {
    match config {
        Some(config) if !config.profiles.is_empty() => config.profiles.clone(),
        _ => HOST_PROFILES
            .iter()
            .map(|profile| (*profile).to_owned())
            .collect(),
    }
}

fn selected_rule_execution_mode(config: Option<&AuditConfig>) -> RuleExecutionMode {
    config.map_or(RuleExecutionMode::Default, |config| config.rule_mode)
}

fn skill_finding_from_evaluated_rule(finding: EvaluatedRuleFinding) -> SkillFinding {
    let metadata = active_rule_metadata(finding.rule_id.as_str())
        .expect("evaluated structural rule must have active registry metadata");

    SkillFinding {
        rule_id: metadata.id.as_str().to_owned(),
        fingerprint: String::new(),
        severity: severity_from_metadata(metadata.severity),
        confidence: finding_confidence_from_rule_id(finding.rule_id),
        category: category_from_metadata(metadata.category),
        title: metadata.title.to_owned(),
        message: finding.message,
        location: crate::model::FindingLocation {
            path: finding.location.path,
            line: finding.location.line,
        },
        rationale: metadata.rationale.to_owned(),
        remediation: metadata.remediation.to_owned(),
        suppression: metadata.suppression_guidance.to_owned(),
    }
}

fn finding_confidence_from_rule_id(rule_id: RuleId) -> FindingConfidence {
    match rule_id {
        RuleId::Sec001
        | RuleId::Skill001
        | RuleId::Skill002
        | RuleId::Skill010
        | RuleId::Skill020
        | RuleId::Skill030
        | RuleId::Skill041
        | RuleId::Supply012 => FindingConfidence::High,
        RuleId::Sec011 | RuleId::Sec012 | RuleId::Skill040 => FindingConfidence::Medium,
        RuleId::Sec002
        | RuleId::Sec003
        | RuleId::Sec007
        | RuleId::Sec009
        | RuleId::Skill050
        | RuleId::Supply001
        | RuleId::Supply002
        | RuleId::Supply003
        | RuleId::Supply004
        | RuleId::Supply005
        | RuleId::Supply006
        | RuleId::Supply007
        | RuleId::Supply009
        | RuleId::Supply011 => FindingConfidence::Medium,
        RuleId::Sec004 | RuleId::Sec005 | RuleId::Sec006 | RuleId::Sec008 | RuleId::Sec010 => {
            FindingConfidence::Medium
        }
    }
}

fn severity_from_metadata(severity: RegistrySeverity) -> crate::model::Severity {
    match severity {
        RegistrySeverity::Info => crate::model::Severity::Info,
        RegistrySeverity::Low => crate::model::Severity::Low,
        RegistrySeverity::Medium => crate::model::Severity::Medium,
        RegistrySeverity::High => crate::model::Severity::High,
        RegistrySeverity::Critical => crate::model::Severity::Critical,
    }
}

fn category_from_metadata(category: RegistryCategory) -> crate::model::FindingCategory {
    match category {
        RegistryCategory::Spec => crate::model::FindingCategory::Spec,
        RegistryCategory::Compatibility => crate::model::FindingCategory::Compatibility,
        RegistryCategory::Security => crate::model::FindingCategory::Security,
        RegistryCategory::Quality => crate::model::FindingCategory::Quality,
        RegistryCategory::Portability => crate::model::FindingCategory::Portability,
        RegistryCategory::Reproducibility => crate::model::FindingCategory::Reproducibility,
    }
}

fn apply_suppressions(
    findings: Vec<SkillFinding>,
    config: Option<&AuditConfig>,
) -> (Vec<SkillFinding>, Vec<SuppressedFinding>) {
    let Some(config) = config else {
        return (findings, Vec::new());
    };

    let mut unsuppressed = Vec::new();
    let mut suppressed = Vec::new();

    for finding in findings {
        match matching_ignore_entry(&finding, &config.ignore) {
            Some(entry) => suppressed.push(SuppressedFinding {
                finding,
                suppression: SuppressionMatch {
                    matched_rule: entry.rule.clone(),
                    matched_path: entry.path.clone(),
                    matched_match: entry.match_value.clone(),
                    reason: entry.reason.clone(),
                },
            }),
            None => unsuppressed.push(finding),
        }
    }

    (unsuppressed, suppressed)
}

fn matching_ignore_entry<'a>(
    finding: &SkillFinding,
    entries: &'a [ConfigIgnoreEntry],
) -> Option<&'a ConfigIgnoreEntry> {
    let finding_path = normalize_report_path(&finding.location.path);
    let match_keys = finding_suppression_match_keys(finding);

    entries.iter().find(|entry| {
        if entry.rule != finding.rule_id {
            return false;
        }
        let path_matches = entry
            .path
            .as_deref()
            .is_none_or(|path| path == finding_path);
        let evidence_matches = entry
            .match_value
            .as_deref()
            .is_none_or(|match_value| match_keys.contains(match_value));

        path_matches && evidence_matches
    })
}

fn normalize_report_path(path: &str) -> String {
    path.replace('\\', "/")
}

fn resolve_references(skill_root: &Path, references: &[SkillReference]) -> Vec<SkillReference> {
    references
        .iter()
        .filter_map(|reference| resolve_reference(skill_root, reference))
        .collect()
}

fn resolve_reference(skill_root: &Path, reference: &SkillReference) -> Option<SkillReference> {
    let mut resolved = reference.clone();
    match relative_probe_target(&reference.target)? {
        RelativeProbeTarget::Safe(target) => {
            resolved.exists = Some(path_exists_without_symlink_dirs(skill_root, target));
        }
        RelativeProbeTarget::Unsafe => {
            resolved.exists = Some(false);
        }
    }
    Some(resolved)
}

enum RelativeProbeTarget<'a> {
    Safe(&'a str),
    Unsafe,
}

fn relative_probe_target(target: &str) -> Option<RelativeProbeTarget<'_>> {
    let target = strip_query_and_fragment(target);

    if target.is_empty() {
        return None;
    }
    if has_windows_prefix(target) || is_absolute_path_target(target) || has_parent_component(target)
    {
        return Some(RelativeProbeTarget::Unsafe);
    }
    if has_uri_scheme(target) {
        return None;
    }

    Some(RelativeProbeTarget::Safe(target))
}

fn is_absolute_path_target(target: &str) -> bool {
    target.starts_with('/') || target.starts_with('\\') || Path::new(target).is_absolute()
}

fn has_parent_component(target: &str) -> bool {
    target.split(['/', '\\']).any(|component| component == "..")
}

fn path_exists_without_symlink_dirs(skill_root: &Path, target: &str) -> bool {
    let components = target
        .split(['/', '\\'])
        .filter(|component| !component.is_empty() && *component != ".")
        .collect::<Vec<_>>();

    if components.is_empty() {
        return false;
    }

    let mut current = skill_root.to_path_buf();
    for (index, component) in components.iter().enumerate() {
        current.push(component);
        let Ok(metadata) = std::fs::symlink_metadata(&current) else {
            return false;
        };
        let is_final = index + 1 == components.len();
        if metadata.file_type().is_symlink() {
            return is_final;
        }
        if !is_final && !metadata.is_dir() {
            return false;
        }
    }

    true
}

fn discover_artifacts(skill_root: &Path) -> Vec<String> {
    ["scripts", "references", "assets"]
        .iter()
        .map(|name| skill_root.join(name))
        .filter(|path| {
            std::fs::symlink_metadata(path)
                .map(|metadata| metadata.file_type().is_dir())
                .unwrap_or(false)
        })
        .map(|path| display_path(skill_root, &path))
        .collect()
}

fn inventory_artifact_files(skill_root: &Path) -> AuditResult<Vec<SkillFile>> {
    let mut files = Vec::new();

    for (name, artifact) in [
        ("scripts", SkillArtifactKind::Scripts),
        ("references", SkillArtifactKind::References),
        ("assets", SkillArtifactKind::Assets),
    ] {
        let artifact_root = skill_root.join(name);
        let metadata =
            match std::fs::symlink_metadata(&artifact_root).map_err(|source| AuditError::Metadata {
                path: artifact_root.clone(),
                source,
            }) {
                Ok(metadata) => metadata,
                Err(AuditError::Metadata { source, .. })
                    if source.kind() == std::io::ErrorKind::NotFound =>
                {
                    continue;
                }
                Err(error) => return Err(error),
            };

        if metadata.is_dir() {
            inventory_directory(skill_root, &artifact_root, artifact, &mut files)?;
        }
    }

    files.sort_by(|left, right| {
        left.path
            .cmp(&right.path)
            .then(left.artifact.cmp(&right.artifact))
            .then(left.kind.cmp(&right.kind))
    });
    Ok(files)
}

fn inventory_directory(
    skill_root: &Path,
    directory: &Path,
    artifact: SkillArtifactKind,
    files: &mut Vec<SkillFile>,
) -> AuditResult<()> {
    for path in sorted_directory_entries(directory)? {
        let metadata = std::fs::symlink_metadata(&path).map_err(|source| AuditError::Metadata {
            path: path.clone(),
            source,
        })?;
        let kind = file_kind(&metadata);
        files.push(SkillFile {
            path: display_path(skill_root, &path),
            artifact,
            kind,
            size_bytes: if kind == SkillFileKind::Directory {
                0
            } else {
                metadata.len()
            },
            readonly: metadata.permissions().readonly(),
        });

        if kind == SkillFileKind::Directory {
            inventory_directory(skill_root, &path, artifact, files)?;
        }
    }

    Ok(())
}

fn file_kind(metadata: &std::fs::Metadata) -> SkillFileKind {
    let file_type = metadata.file_type();
    if file_type.is_symlink() {
        SkillFileKind::Symlink
    } else if file_type.is_file() {
        SkillFileKind::File
    } else if file_type.is_dir() {
        SkillFileKind::Directory
    } else {
        SkillFileKind::Other
    }
}

fn package_install_context(
    scan_root: &Path,
    skill_root: &Path,
    manifest_path: &str,
    graph: &SkillGraph,
    package_file_inventory: &SupplyChainInventory,
) -> AuditResult<RulePackageInstallContext> {
    let mut files = graph
        .files
        .iter()
        .filter(|file| file.kind == SkillFileKind::File)
        .map(|file| RulePackageFileFact {
            path: file.path.clone(),
        })
        .collect::<Vec<_>>();

    let mut root_entries = std::fs::read_dir(skill_root)
        .map_err(|source| AuditError::ReadDir {
            path: skill_root.to_path_buf(),
            source,
        })?
        .map(|entry| {
            entry.map_err(|source| AuditError::ReadDir {
                path: skill_root.to_path_buf(),
                source,
            })
        })
        .collect::<AuditResult<Vec<_>>>()?;
    root_entries.sort_by_key(|entry| entry.path());

    for entry in root_entries {
        let path = entry.path();
        let metadata = std::fs::symlink_metadata(&path).map_err(|source| AuditError::Metadata {
            path: path.clone(),
            source,
        })?;
        if metadata.is_file() {
            files.push(RulePackageFileFact {
                path: display_path(skill_root, &path),
            });
        }
    }

    files.sort_by(|left, right| left.path.cmp(&right.path));
    files.dedup_by(|left, right| left.path == right.path);

    Ok(RulePackageInstallContext {
        package_root: display_path(scan_root, skill_root),
        manifest_path: manifest_path.to_owned(),
        files,
        dependency_manifests: package_file_inventory
            .dependency_manifests
            .iter()
            .map(|manifest| RulePackageDependencyManifestFact {
                path: manifest.path.clone(),
                manager: rule_package_manager_kind(manifest.manager),
                pinning: rule_dependency_manifest_pinning(manifest.pinning),
            })
            .collect(),
    })
}

fn analyze_package_security_artifacts(
    scan_root: &Path,
    skill_root: &Path,
    manifest_path: &str,
    manifest: &SkillManifest,
    graph: &SkillGraph,
) -> AuditResult<Vec<agent_audit_security::SecuritySignal>> {
    let package_root = display_path(scan_root, skill_root);
    let declared_tools = manifest
        .declared_tools
        .iter()
        .map(|name| SecurityDeclaredTool { name: name.clone() })
        .collect::<Vec<_>>();
    let declared_permissions = manifest
        .declared_permissions
        .iter()
        .map(|name| SecurityDeclaredPermission { name: name.clone() })
        .collect::<Vec<_>>();
    let package = SecurityAnalyzerPackageContext {
        package_root: &package_root,
        manifest_path,
        declared_tools: &declared_tools,
        declared_permissions: &declared_permissions,
    };
    let mut signals = Vec::new();

    for file in graph
        .files
        .iter()
        .filter(|file| file.kind == SkillFileKind::File)
    {
        let artifact_path = skill_root.join(&file.path);
        let display = display_path(scan_root, &artifact_path);
        let read = read_security_artifact_bytes(
            &artifact_path,
            &display,
            SecurityArtifactReadPolicy::default(),
        )
        .map_err(|error| security_read_error(&artifact_path, error))?;
        let Some(classification) = classify_security_artifact(&display, &read.bytes, false) else {
            continue;
        };
        let Some(output) = analyze_classified_security_artifact(
            &package,
            &read,
            &classification,
            security_artifact_kind(file.artifact),
        ) else {
            continue;
        };
        signals.extend(output.signals);
    }

    signals.sort();
    signals.dedup();
    Ok(signals)
}

fn inventory_script_artifact_urls(
    scan_root: &Path,
    skill_root: &Path,
    graph: &SkillGraph,
) -> AuditResult<SupplyChainInventory> {
    let mut inventory = SupplyChainInventory::default();

    for file in graph.files.iter().filter(|file| {
        file.kind == SkillFileKind::File && file.artifact == SkillArtifactKind::Scripts
    }) {
        let artifact_path = skill_root.join(&file.path);
        let display = display_path(scan_root, &artifact_path);
        let read = read_security_artifact_bytes(
            &artifact_path,
            &display,
            SecurityArtifactReadPolicy::default(),
        )
        .map_err(|error| security_read_error(&artifact_path, error))?;
        let Some(text) = read.utf8_text() else {
            continue;
        };
        merge_supply_chain_inventory(&mut inventory, inventory_script_urls(&display, text));
    }

    Ok(inventory)
}

fn analyze_classified_security_artifact(
    package: &SecurityAnalyzerPackageContext<'_>,
    read: &agent_audit_security::SecurityArtifactRead,
    classification: &agent_audit_security::SecurityArtifactClassification,
    kind: SecurityScanArtifactKind,
) -> Option<agent_audit_security::SecurityAnalyzerOutput> {
    let input = SecurityAnalyzerInput {
        artifact: SecurityAnalyzerArtifactInput {
            path: &classification.path,
            kind,
            language: classification.language,
            classification_method: classification.method,
            classification_signals: &classification.signals,
            executable: classification.executable,
            size_bytes: read.metadata_size_bytes.unwrap_or(read.observed_size_bytes),
            content: SecurityAnalyzerContent::from_bytes(
                &read.bytes,
                read.status,
                SecurityArtifactReadPolicy::default().max_bytes,
            ),
        },
        package: *package,
    };

    match classification.language {
        SecurityLanguage::Shell => Some(shell_security_analyzer().analyze(&input)),
        SecurityLanguage::Python => Some(python_security_analyzer().analyze(&input)),
        SecurityLanguage::JavaScript | SecurityLanguage::TypeScript => {
            Some(javascript_security_analyzer().analyze(&input))
        }
        _ => None,
    }
}

fn security_artifact_kind(kind: SkillArtifactKind) -> SecurityScanArtifactKind {
    match kind {
        SkillArtifactKind::Scripts => SecurityScanArtifactKind::Script,
        SkillArtifactKind::References => SecurityScanArtifactKind::Reference,
        SkillArtifactKind::Assets => SecurityScanArtifactKind::Asset,
    }
}

fn security_read_error(path: &Path, error: SecurityArtifactReadError) -> AuditError {
    let kind = match &error {
        SecurityArtifactReadError::OpenFailed { kind, .. }
        | SecurityArtifactReadError::ReadFailed { kind, .. } => *kind,
        SecurityArtifactReadError::InvalidDisplayPath { .. }
        | SecurityArtifactReadError::NotFile { .. } => std::io::ErrorKind::InvalidData,
    };
    AuditError::Read {
        path: path.to_path_buf(),
        source: std::io::Error::new(kind, error),
    }
}

fn frontmatter_key_lines(content: &str) -> BTreeMap<String, usize> {
    let Some(frontmatter) = frontmatter_content(content) else {
        return BTreeMap::new();
    };

    frontmatter
        .lines()
        .enumerate()
        .filter_map(|(index, line)| top_level_frontmatter_key(line).map(|key| (key, index + 2)))
        .collect()
}

fn frontmatter_content(content: &str) -> Option<&str> {
    let content_after_bom = content.strip_prefix(UTF8_BOM).unwrap_or(content);
    let delimiter_offset = content.len() - content_after_bom.len();
    let after_opening_delimiter = content_after_bom.strip_prefix("---")?;
    let opening_line_ending_len = line_ending_len(after_opening_delimiter)?;
    let frontmatter_start = delimiter_offset + "---".len() + opening_line_ending_len;
    let mut line_start = frontmatter_start;

    while line_start <= content.len() {
        let line_end = content[line_start..]
            .find('\n')
            .map_or(content.len(), |offset| line_start + offset + 1);
        let line = &content[line_start..line_end];
        if trim_line_ending(line) == "---" {
            return Some(&content[frontmatter_start..line_start]);
        }
        if line_end == content.len() {
            break;
        }
        line_start = line_end;
    }

    None
}

fn line_ending_len(value: &str) -> Option<usize> {
    if value.starts_with("\r\n") {
        Some(2)
    } else if value.starts_with('\n') {
        Some(1)
    } else {
        None
    }
}

fn trim_line_ending(line: &str) -> &str {
    line.strip_suffix("\r\n")
        .or_else(|| line.strip_suffix('\n'))
        .unwrap_or(line)
}

fn top_level_frontmatter_key(line: &str) -> Option<String> {
    if line.is_empty()
        || line.starts_with(char::is_whitespace)
        || line.starts_with('#')
        || line.starts_with('-')
    {
        return None;
    }

    let (key, _value) = line.split_once(':')?;
    let key = key.trim().trim_matches(['"', '\'']);
    (!key.is_empty()).then(|| key.to_owned())
}

fn empty_skill_manifest() -> SkillManifest {
    SkillManifest {
        name: None,
        description: None,
        frontmatter: BTreeMap::new(),
        body: String::new(),
        headings: Vec::new(),
        links: Vec::new(),
        inline_code: Vec::new(),
        inline_code_locations: Vec::new(),
        code_blocks: Vec::new(),
        declared_tools: Vec::new(),
        declared_permissions: Vec::new(),
    }
}

fn empty_skill_graph() -> SkillGraph {
    SkillGraph {
        references: Vec::new(),
        artifacts: Vec::new(),
        files: Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::parse_audit_config;
    use crate::model::{
        ExternalUrlKind, FindingCategory, FindingConfidence, RemoteDependencyKind, Severity,
        SkillFinding, SupplyChainSourceKind,
    };
    use crate::test_support::TestWorkspace;
    use agent_audit_hosts::{CompatibilityStatus, HOST_PROFILES};
    use agent_audit_rules::{
        rule_metadata, RuleCategory as RegistryCategory, RuleId, RuleSeverity as RegistrySeverity,
        ACTIVE_RULE_IDS,
    };
    use std::io::ErrorKind;

    #[test]
    fn scan_reports_valid_manifest_with_references_and_artifacts() {
        let workspace = TestWorkspace::new("scan-valid");
        workspace.write_file(
            "SKILL.md",
            r#"---
name: valid-skill
description: Valid skill fixture.
---

# Valid Skill

Read [local guidance](references/guidance.md), [remote guidance](https://example.test),
and [heading](#valid-skill).
"#,
        );
        workspace.write_file("references/guidance.md", "# Guidance\n");
        workspace.create_dir("scripts");
        workspace.create_dir("assets");

        let report = scan_path(workspace.root(), &ScanOptions::default()).expect("scan path");

        assert_eq!(report.summary.package_count, 1);
        assert_eq!(report.summary.finding_count, 0);
        assert_eq!(report.summary.invalid_manifest_count, 0);
        assert_eq!(report.summary.broken_reference_count, 0);
        assert_eq!(report.packages[0].root, "");
        assert_eq!(report.packages[0].manifest_path, "SKILL.md");
        assert_eq!(
            report.packages[0]
                .graph
                .references
                .iter()
                .map(|reference| (&reference.target, reference.exists))
                .collect::<Vec<_>>(),
            vec![(&"references/guidance.md".to_owned(), Some(true))]
        );
        assert_eq!(
            report.packages[0].graph.artifacts,
            vec!["scripts", "references", "assets"]
        );
        assert_eq!(report.packages[0].graph.files.len(), 1);
        assert_eq!(
            report.packages[0].graph.files[0].path,
            "references/guidance.md"
        );
        assert_eq!(
            report.packages[0].graph.files[0].artifact,
            SkillArtifactKind::References
        );
        assert_eq!(report.packages[0].graph.files[0].kind, SkillFileKind::File);
        assert_eq!(report.packages[0].graph.files[0].size_bytes, 11);
    }

    #[test]
    fn scan_default_compatibility_matrix_uses_all_profiles_in_registry_order() {
        let workspace = TestWorkspace::new("scan-default-compatibility");
        workspace.write_file(
            "SKILL.md",
            r#"---
name: default-compatibility
description: Default compatibility fixture.
---

# Default Compatibility
"#,
        );

        let report = scan_path(workspace.root(), &ScanOptions::default()).expect("scan path");

        assert_eq!(report.compatibility.profiles, string_vec(HOST_PROFILES));
        assert_eq!(report.compatibility.matrix.len(), 1);
        assert_eq!(report.compatibility.matrix[0].path, "SKILL.md");
        assert_eq!(
            report.compatibility.matrix[0].name.as_deref(),
            Some("default-compatibility")
        );
        assert_eq!(
            compatibility_projection(&report.compatibility.matrix[0].profiles),
            vec![
                (
                    "agent-skills-spec",
                    CompatibilityStatus::Pass,
                    Vec::<&str>::new()
                ),
                (
                    "claude-code",
                    CompatibilityStatus::Unknown,
                    Vec::<&str>::new()
                ),
                ("codex", CompatibilityStatus::Unknown, Vec::<&str>::new()),
                (
                    "github-copilot",
                    CompatibilityStatus::Unknown,
                    Vec::<&str>::new()
                ),
                (
                    "vscode-copilot",
                    CompatibilityStatus::Unknown,
                    Vec::<&str>::new()
                ),
                ("generic", CompatibilityStatus::Pass, Vec::<&str>::new()),
            ]
        );
        assert_eq!(report.summary.finding_count, 0);
        assert_eq!(report.summary.suppressed_finding_count, 0);
    }

    #[test]
    fn scan_default_profiles_emit_claude_ignored_metadata_skill050() {
        let workspace = TestWorkspace::new("scan-default-claude-ignored-metadata");
        workspace.write_file(
            ".claude/skills/reviewer/SKILL.md",
            r#"---
name: reviewer
description: Reviews code changes.
tools:
  - shell
---

# Reviewer
"#,
        );

        let report = scan_path(workspace.root(), &ScanOptions::default()).expect("scan path");

        assert_eq!(
            report
                .findings
                .iter()
                .map(|finding| finding.rule_id.as_str())
                .collect::<Vec<_>>(),
            vec!["SKILL050"]
        );
        assert_eq!(
            ".claude/skills/reviewer/SKILL.md",
            report.findings[0].location.path
        );
        assert!(report.findings[0].message.contains("`tools`"));
        assert_eq!(
            compatibility_projection(&report.compatibility.matrix[0].profiles),
            vec![
                (
                    "agent-skills-spec",
                    CompatibilityStatus::Pass,
                    Vec::<&str>::new()
                ),
                ("claude-code", CompatibilityStatus::Warn, vec!["SKILL050"]),
                ("codex", CompatibilityStatus::Unknown, Vec::<&str>::new()),
                (
                    "github-copilot",
                    CompatibilityStatus::Unknown,
                    Vec::<&str>::new()
                ),
                (
                    "vscode-copilot",
                    CompatibilityStatus::Unknown,
                    Vec::<&str>::new()
                ),
                ("generic", CompatibilityStatus::Pass, Vec::<&str>::new()),
            ]
        );
    }

    #[test]
    fn scan_agent_skills_spec_warns_for_unsuppressed_baseline_warnings() {
        let workspace = TestWorkspace::new("scan-agent-spec-warn");
        workspace.write_file(
            "SKILL.md",
            r#"---
name: baseline-warn
description: Baseline warning fixture.
owner: platform
---

# Baseline Warning

Read [missing](references/missing.md).
"#,
        );

        let report = scan_path(workspace.root(), &ScanOptions::default()).expect("scan path");

        assert_eq!(
            report
                .findings
                .iter()
                .map(|finding| finding.rule_id.as_str())
                .collect::<Vec<_>>(),
            vec!["SKILL040", "SKILL010"]
        );
        assert_eq!(
            compatibility_projection(&report.compatibility.matrix[0].profiles),
            vec![
                (
                    "agent-skills-spec",
                    CompatibilityStatus::Warn,
                    vec!["SKILL010", "SKILL040"]
                ),
                (
                    "claude-code",
                    CompatibilityStatus::Warn,
                    vec!["SKILL010", "SKILL040"]
                ),
                (
                    "codex",
                    CompatibilityStatus::Warn,
                    vec!["SKILL010", "SKILL040"]
                ),
                (
                    "github-copilot",
                    CompatibilityStatus::Warn,
                    vec!["SKILL010", "SKILL040"]
                ),
                (
                    "vscode-copilot",
                    CompatibilityStatus::Warn,
                    vec!["SKILL010", "SKILL040"]
                ),
                (
                    "generic",
                    CompatibilityStatus::Warn,
                    vec!["SKILL010", "SKILL040"]
                ),
            ]
        );
    }

    #[test]
    fn scan_agent_skills_spec_fails_for_required_baseline_findings() {
        let workspace = TestWorkspace::new("scan-agent-spec-fail");
        workspace.write_file(
            "SKILL.md",
            r#"---
description: Missing name fixture.
owner: platform
---

This manifest intentionally has no heading fallback.
"#,
        );

        let report = scan_path(workspace.root(), &ScanOptions::default()).expect("scan path");

        assert_eq!(
            report
                .findings
                .iter()
                .map(|finding| finding.rule_id.as_str())
                .collect::<Vec<_>>(),
            vec!["SKILL001", "SKILL040"]
        );
        assert_eq!(
            compatibility_projection(&report.compatibility.matrix[0].profiles)[0],
            (
                "agent-skills-spec",
                CompatibilityStatus::Fail,
                vec!["SKILL001", "SKILL040"]
            )
        );
    }

    #[test]
    fn scan_claude_code_preferred_path_passes() {
        let workspace = TestWorkspace::new("scan-claude-preferred-pass");
        workspace.write_file(
            ".claude/skills/reviewer/SKILL.md",
            r#"---
name: reviewer
description: Reviews code changes.
---

# Reviewer
"#,
        );
        let config = parse_audit_config(
            r#"
profiles:
  - claude-code
"#,
        )
        .expect("valid config");

        let report = scan_path(
            workspace.root(),
            &ScanOptions {
                config: Some(config),
                ..ScanOptions::default()
            },
        )
        .expect("scan path");

        assert!(report.findings.is_empty());
        assert_eq!(
            compatibility_projection(&report.compatibility.matrix[0].profiles),
            vec![("claude-code", CompatibilityStatus::Pass, Vec::<&str>::new())]
        );
    }

    #[test]
    fn scan_claude_code_allowed_tools_does_not_report_skill040() {
        let workspace = TestWorkspace::new("scan-claude-allowed-tools-pass");
        workspace.write_file(
            ".claude/skills/reviewer/SKILL.md",
            r#"---
name: reviewer
description: Reviews code changes.
allowed-tools:
  - Bash(git diff:*)
---

# Reviewer
"#,
        );
        let config = parse_audit_config(
            r#"
profiles:
  - claude-code
"#,
        )
        .expect("valid config");

        let report = scan_path(
            workspace.root(),
            &ScanOptions {
                config: Some(config),
                ..ScanOptions::default()
            },
        )
        .expect("scan path");

        assert!(report.findings.is_empty());
        assert_eq!(
            compatibility_projection(&report.compatibility.matrix[0].profiles),
            vec![("claude-code", CompatibilityStatus::Pass, Vec::<&str>::new())]
        );
    }

    #[test]
    fn scan_claude_code_allowed_tools_on_root_skill_is_unknown_for_path_only() {
        let workspace = TestWorkspace::new("scan-claude-root-allowed-tools-path-warn");
        workspace.write_file(
            "SKILL.md",
            r#"---
name: reviewer
description: Reviews code changes.
allowed-tools:
  - Bash(git diff:*)
---

# Reviewer
"#,
        );
        let config = parse_audit_config(
            r#"
profiles:
  - claude-code
"#,
        )
        .expect("valid config");

        let report = scan_path(
            workspace.root(),
            &ScanOptions {
                config: Some(config),
                ..ScanOptions::default()
            },
        )
        .expect("scan path");

        assert!(report.findings.is_empty());
        assert_eq!(
            compatibility_projection(&report.compatibility.matrix[0].profiles),
            vec![(
                "claude-code",
                CompatibilityStatus::Unknown,
                Vec::<&str>::new()
            )]
        );
    }

    #[test]
    fn scan_claude_code_is_unknown_for_non_claude_path_without_finding_id() {
        let workspace = TestWorkspace::new("scan-claude-path-warn");
        workspace.write_file(
            "SKILL.md",
            r#"---
name: reviewer
description: Reviews code changes.
---

# Reviewer
"#,
        );
        let config = parse_audit_config(
            r#"
profiles:
  - claude-code
"#,
        )
        .expect("valid config");

        let report = scan_path(
            workspace.root(),
            &ScanOptions {
                config: Some(config),
                ..ScanOptions::default()
            },
        )
        .expect("scan path");

        assert!(report.findings.is_empty());
        assert_eq!(
            compatibility_projection(&report.compatibility.matrix[0].profiles),
            vec![(
                "claude-code",
                CompatibilityStatus::Unknown,
                Vec::<&str>::new()
            )]
        );
    }

    #[test]
    fn scan_claude_code_warns_for_ignored_metadata_with_skill050() {
        let workspace = TestWorkspace::new("scan-claude-ignored-metadata");
        workspace.write_file(
            ".claude/skills/reviewer/SKILL.md",
            r#"---
name: reviewer
description: Reviews code changes.
tools:
  - shell
---

# Reviewer
"#,
        );
        let config = parse_audit_config(
            r#"
profiles:
  - claude-code
"#,
        )
        .expect("valid config");

        let report = scan_path(
            workspace.root(),
            &ScanOptions {
                config: Some(config),
                ..ScanOptions::default()
            },
        )
        .expect("scan path");

        assert_eq!(report.findings.len(), 1);
        assert_eq!(report.findings[0].rule_id, "SKILL050");
        assert_eq!(report.findings[0].category, FindingCategory::Compatibility);
        assert_eq!(
            report.findings[0].location.path,
            ".claude/skills/reviewer/SKILL.md"
        );
        assert!(report.findings[0].message.contains("`tools`"));
        assert_eq!(
            compatibility_projection(&report.compatibility.matrix[0].profiles),
            vec![("claude-code", CompatibilityStatus::Warn, vec!["SKILL050"])]
        );
    }

    #[test]
    fn scan_claude_code_is_unknown_for_script_references_without_finding_id() {
        let workspace = TestWorkspace::new("scan-claude-script-warn");
        workspace.write_file(
            ".claude/skills/reviewer/SKILL.md",
            r#"---
name: reviewer
description: Reviews code changes.
---

# Reviewer

Run [check](scripts/check.sh) when explicitly requested.
"#,
        );
        workspace.write_file(".claude/skills/reviewer/scripts/check.sh", "echo check\n");
        let config = parse_audit_config(
            r#"
profiles:
  - claude-code
"#,
        )
        .expect("valid config");

        let report = scan_path(
            workspace.root(),
            &ScanOptions {
                config: Some(config),
                ..ScanOptions::default()
            },
        )
        .expect("scan path");

        assert!(report.findings.is_empty());
        assert_eq!(
            compatibility_projection(&report.compatibility.matrix[0].profiles),
            vec![(
                "claude-code",
                CompatibilityStatus::Unknown,
                Vec::<&str>::new()
            )]
        );
    }

    #[test]
    fn scan_claude_code_fails_for_baseline_required_findings() {
        let workspace = TestWorkspace::new("scan-claude-baseline-fail");
        workspace.write_file(
            ".claude/skills/reviewer/SKILL.md",
            r#"---
name: reviewer
---
"#,
        );
        let config = parse_audit_config(
            r#"
profiles:
  - claude-code
"#,
        )
        .expect("valid config");

        let report = scan_path(
            workspace.root(),
            &ScanOptions {
                config: Some(config),
                ..ScanOptions::default()
            },
        )
        .expect("scan path");

        assert_eq!(
            compatibility_projection(&report.compatibility.matrix[0].profiles),
            vec![("claude-code", CompatibilityStatus::Fail, vec!["SKILL002"])]
        );
    }

    #[test]
    fn scan_claude_code_ignores_suppressed_skill050() {
        let workspace = TestWorkspace::new("scan-claude-suppressed-skill050");
        workspace.write_file(
            ".claude/skills/reviewer/SKILL.md",
            r#"---
name: reviewer
description: Reviews code changes.
tools:
  - shell
---
"#,
        );
        let config = parse_audit_config(
            r#"
profiles:
  - claude-code

ignore:
  - rule: SKILL050
    path: .claude/skills/reviewer/SKILL.md
    reason: Claude wrapper translates portable tools metadata.
"#,
        )
        .expect("valid config");

        let report = scan_path(
            workspace.root(),
            &ScanOptions {
                config: Some(config),
                ..ScanOptions::default()
            },
        )
        .expect("scan path");

        assert!(report.findings.is_empty());
        assert_eq!(report.summary.suppressed_finding_count, 1);
        assert_eq!(
            compatibility_projection(&report.compatibility.matrix[0].profiles),
            vec![("claude-code", CompatibilityStatus::Pass, Vec::<&str>::new())]
        );
    }

    #[test]
    fn scan_explicit_config_profiles_preserves_claude_order() {
        let workspace = TestWorkspace::new("scan-claude-profile-order");
        workspace.write_file(
            ".claude/skills/reviewer/SKILL.md",
            r#"---
name: reviewer
description: Reviews code changes.
---
"#,
        );
        let config = parse_audit_config(
            r#"
profiles:
  - generic
  - claude-code
  - agent-skills-spec
"#,
        )
        .expect("valid config");

        let report = scan_path(
            workspace.root(),
            &ScanOptions {
                config: Some(config),
                ..ScanOptions::default()
            },
        )
        .expect("scan path");

        assert_eq!(
            report.compatibility.profiles,
            vec!["generic", "claude-code", "agent-skills-spec"]
        );
        assert_eq!(
            compatibility_projection(&report.compatibility.matrix[0].profiles),
            vec![
                ("generic", CompatibilityStatus::Pass, Vec::<&str>::new()),
                ("claude-code", CompatibilityStatus::Pass, Vec::<&str>::new()),
                (
                    "agent-skills-spec",
                    CompatibilityStatus::Pass,
                    Vec::<&str>::new()
                ),
            ]
        );
    }

    #[test]
    fn scan_codex_preferred_path_with_tools_passes() {
        let workspace = TestWorkspace::new("scan-codex-preferred-pass");
        workspace.write_file(
            ".agents/skills/reviewer/SKILL.md",
            r#"---
name: reviewer
description: Reviews code changes.
tools:
  - shell
---

# Reviewer
"#,
        );
        let config = parse_audit_config(
            r#"
profiles:
  - codex
"#,
        )
        .expect("valid config");

        let report = scan_path(
            workspace.root(),
            &ScanOptions {
                config: Some(config),
                ..ScanOptions::default()
            },
        )
        .expect("scan path");

        assert!(report.findings.is_empty());
        assert_eq!(
            compatibility_projection(&report.compatibility.matrix[0].profiles),
            vec![("codex", CompatibilityStatus::Pass, Vec::<&str>::new())]
        );
    }

    #[test]
    fn scan_codex_is_unknown_for_non_codex_path_without_finding_id() {
        let workspace = TestWorkspace::new("scan-codex-path-warn");
        workspace.write_file(
            "SKILL.md",
            r#"---
name: reviewer
description: Reviews code changes.
---

# Reviewer
"#,
        );
        let config = parse_audit_config(
            r#"
profiles:
  - codex
"#,
        )
        .expect("valid config");

        let report = scan_path(
            workspace.root(),
            &ScanOptions {
                config: Some(config),
                ..ScanOptions::default()
            },
        )
        .expect("scan path");

        assert!(report.findings.is_empty());
        assert_eq!(
            compatibility_projection(&report.compatibility.matrix[0].profiles),
            vec![("codex", CompatibilityStatus::Unknown, Vec::<&str>::new())]
        );
    }

    #[test]
    fn scan_codex_warns_for_ignored_allowed_tools_with_skill050() {
        let workspace = TestWorkspace::new("scan-codex-ignored-allowed-tools");
        workspace.write_file(
            ".agents/skills/reviewer/SKILL.md",
            r#"---
name: reviewer
description: Reviews code changes.
allowed-tools:
  - Bash(git diff:*)
---

# Reviewer
"#,
        );
        let config = parse_audit_config(
            r#"
profiles:
  - codex
"#,
        )
        .expect("valid config");

        let report = scan_path(
            workspace.root(),
            &ScanOptions {
                config: Some(config),
                ..ScanOptions::default()
            },
        )
        .expect("scan path");

        let mut rule_ids = report
            .findings
            .iter()
            .map(|finding| finding.rule_id.as_str())
            .collect::<Vec<_>>();
        rule_ids.sort_unstable();
        assert_eq!(rule_ids, vec!["SKILL040", "SKILL050"]);
        let codex_finding = report
            .findings
            .iter()
            .find(|finding| finding.rule_id == "SKILL050")
            .expect("Codex compatibility finding");
        assert_eq!(codex_finding.category, FindingCategory::Compatibility);
        assert_eq!(
            codex_finding.location.path,
            ".agents/skills/reviewer/SKILL.md"
        );
        assert!(codex_finding.message.contains("`allowed-tools`"));
        assert_eq!(
            compatibility_projection(&report.compatibility.matrix[0].profiles),
            vec![("codex", CompatibilityStatus::Warn, vec!["SKILL050"])]
        );
    }

    #[test]
    fn scan_combined_spec_and_codex_keeps_structural_allowed_tools_finding() {
        let workspace = TestWorkspace::new("scan-codex-combined-allowed-tools");
        workspace.write_file(
            ".agents/skills/reviewer/SKILL.md",
            r#"---
name: reviewer
description: Reviews code changes.
allowed-tools:
  - Bash(git diff:*)
---

# Reviewer
"#,
        );
        let config = parse_audit_config(
            r#"
profiles:
  - agent-skills-spec
  - codex
"#,
        )
        .expect("valid config");

        let report = scan_path(
            workspace.root(),
            &ScanOptions {
                config: Some(config),
                ..ScanOptions::default()
            },
        )
        .expect("scan path");

        let mut rule_ids = report
            .findings
            .iter()
            .map(|finding| finding.rule_id.as_str())
            .collect::<Vec<_>>();
        rule_ids.sort_unstable();
        assert_eq!(rule_ids, vec!["SKILL040", "SKILL050"]);
        assert!(report
            .findings
            .iter()
            .all(|finding| finding.message.contains("`allowed-tools`")));
        assert_eq!(
            compatibility_projection(&report.compatibility.matrix[0].profiles),
            vec![
                (
                    "agent-skills-spec",
                    CompatibilityStatus::Warn,
                    vec!["SKILL040"]
                ),
                ("codex", CompatibilityStatus::Warn, vec!["SKILL050"]),
            ]
        );
    }

    #[test]
    fn scan_codex_is_unknown_for_permissions_without_finding_id() {
        let workspace = TestWorkspace::new("scan-codex-permissions-warn");
        workspace.write_file(
            ".agents/skills/reviewer/SKILL.md",
            r#"---
name: reviewer
description: Reviews code changes.
permissions:
  - filesystem-read
---

# Reviewer
"#,
        );
        let config = parse_audit_config(
            r#"
profiles:
  - codex
"#,
        )
        .expect("valid config");

        let report = scan_path(
            workspace.root(),
            &ScanOptions {
                config: Some(config),
                ..ScanOptions::default()
            },
        )
        .expect("scan path");

        assert!(report.findings.is_empty());
        assert_eq!(
            compatibility_projection(&report.compatibility.matrix[0].profiles),
            vec![("codex", CompatibilityStatus::Unknown, Vec::<&str>::new())]
        );
    }

    #[test]
    fn scan_codex_is_unknown_for_script_references_without_finding_id() {
        let workspace = TestWorkspace::new("scan-codex-script-warn");
        workspace.write_file(
            ".agents/skills/reviewer/SKILL.md",
            r#"---
name: reviewer
description: Reviews code changes.
---

# Reviewer

Run [check](scripts/check.sh) when explicitly requested.
"#,
        );
        workspace.write_file(".agents/skills/reviewer/scripts/check.sh", "echo check\n");
        let config = parse_audit_config(
            r#"
profiles:
  - codex
"#,
        )
        .expect("valid config");

        let report = scan_path(
            workspace.root(),
            &ScanOptions {
                config: Some(config),
                ..ScanOptions::default()
            },
        )
        .expect("scan path");

        assert!(report.findings.is_empty());
        assert_eq!(
            compatibility_projection(&report.compatibility.matrix[0].profiles),
            vec![("codex", CompatibilityStatus::Unknown, Vec::<&str>::new())]
        );
    }

    #[test]
    fn scan_codex_fails_for_baseline_required_findings() {
        let workspace = TestWorkspace::new("scan-codex-baseline-fail");
        workspace.write_file(
            ".agents/skills/reviewer/SKILL.md",
            r#"---
name: reviewer
---
"#,
        );
        let config = parse_audit_config(
            r#"
profiles:
  - codex
"#,
        )
        .expect("valid config");

        let report = scan_path(
            workspace.root(),
            &ScanOptions {
                config: Some(config),
                ..ScanOptions::default()
            },
        )
        .expect("scan path");

        assert_eq!(
            compatibility_projection(&report.compatibility.matrix[0].profiles),
            vec![("codex", CompatibilityStatus::Fail, vec!["SKILL002"])]
        );
    }

    #[test]
    fn scan_codex_ignores_suppressed_skill050() {
        let workspace = TestWorkspace::new("scan-codex-suppressed-skill050");
        workspace.write_file(
            ".agents/skills/reviewer/SKILL.md",
            r#"---
name: reviewer
description: Reviews code changes.
allowed-tools:
  - Bash(git diff:*)
---
"#,
        );
        let config = parse_audit_config(
            r#"
profiles:
  - codex

ignore:
  - rule: SKILL050
    path: .agents/skills/reviewer/SKILL.md
    reason: Codex wrapper translates Claude-style tool metadata.
"#,
        )
        .expect("valid config");

        let report = scan_path(
            workspace.root(),
            &ScanOptions {
                config: Some(config),
                ..ScanOptions::default()
            },
        )
        .expect("scan path");

        assert_eq!(
            report
                .findings
                .iter()
                .map(|finding| finding.rule_id.as_str())
                .collect::<Vec<_>>(),
            vec!["SKILL040"]
        );
        assert_eq!(report.summary.suppressed_finding_count, 1);
        assert_eq!(
            compatibility_projection(&report.compatibility.matrix[0].profiles),
            vec![("codex", CompatibilityStatus::Pass, Vec::<&str>::new())]
        );
    }

    #[test]
    fn scan_github_copilot_preferred_path_with_tools_passes() {
        let workspace = TestWorkspace::new("scan-github-copilot-preferred-pass");
        workspace.write_file(
            ".github/skills/reviewer/SKILL.md",
            r#"---
name: reviewer
description: Reviews repository changes.
tools:
  - shell
---

# Reviewer
"#,
        );
        let config = parse_audit_config(
            r#"
profiles:
  - github-copilot
"#,
        )
        .expect("valid config");

        let report = scan_path(
            workspace.root(),
            &ScanOptions {
                config: Some(config),
                ..ScanOptions::default()
            },
        )
        .expect("scan path");

        assert!(report.findings.is_empty());
        assert_eq!(
            compatibility_projection(&report.compatibility.matrix[0].profiles),
            vec![(
                "github-copilot",
                CompatibilityStatus::Pass,
                Vec::<&str>::new()
            )]
        );
    }

    #[test]
    fn scan_github_copilot_is_unknown_for_permissions_without_finding_id() {
        let workspace = TestWorkspace::new("scan-github-copilot-permissions-warn");
        workspace.write_file(
            ".github/skills/reviewer/SKILL.md",
            r#"---
name: reviewer
description: Reviews repository changes.
permissions:
  network: false
---

# Reviewer
"#,
        );
        let config = parse_audit_config(
            r#"
profiles:
  - github-copilot
"#,
        )
        .expect("valid config");

        let report = scan_path(
            workspace.root(),
            &ScanOptions {
                config: Some(config),
                ..ScanOptions::default()
            },
        )
        .expect("scan path");

        assert!(report.findings.is_empty());
        assert_eq!(
            compatibility_projection(&report.compatibility.matrix[0].profiles),
            vec![(
                "github-copilot",
                CompatibilityStatus::Unknown,
                Vec::<&str>::new()
            )]
        );
    }

    #[test]
    fn scan_github_copilot_is_unknown_for_non_github_path_without_finding_id() {
        let workspace = TestWorkspace::new("scan-github-copilot-path-warn");
        workspace.write_file(
            "SKILL.md",
            r#"---
name: reviewer
description: Reviews repository changes.
---

# Reviewer
"#,
        );
        let config = parse_audit_config(
            r#"
profiles:
  - github-copilot
"#,
        )
        .expect("valid config");

        let report = scan_path(
            workspace.root(),
            &ScanOptions {
                config: Some(config),
                ..ScanOptions::default()
            },
        )
        .expect("scan path");

        assert!(report.findings.is_empty());
        assert_eq!(
            compatibility_projection(&report.compatibility.matrix[0].profiles),
            vec![(
                "github-copilot",
                CompatibilityStatus::Unknown,
                Vec::<&str>::new()
            )]
        );
    }

    #[test]
    fn scan_github_copilot_warns_for_ignored_allowed_tools_with_skill050() {
        let workspace = TestWorkspace::new("scan-github-copilot-ignored-allowed-tools");
        workspace.write_file(
            ".github/skills/reviewer/SKILL.md",
            r#"---
name: reviewer
description: Reviews repository changes.
allowed-tools:
  - Bash(git diff:*)
---

# Reviewer
"#,
        );
        let config = parse_audit_config(
            r#"
profiles:
  - github-copilot
"#,
        )
        .expect("valid config");

        let report = scan_path(
            workspace.root(),
            &ScanOptions {
                config: Some(config),
                ..ScanOptions::default()
            },
        )
        .expect("scan path");

        let mut rule_ids = report
            .findings
            .iter()
            .map(|finding| finding.rule_id.as_str())
            .collect::<Vec<_>>();
        rule_ids.sort_unstable();
        assert_eq!(rule_ids, vec!["SKILL040", "SKILL050"]);
        let github_copilot_finding = report
            .findings
            .iter()
            .find(|finding| finding.rule_id == "SKILL050")
            .expect("GitHub Copilot compatibility finding");
        assert_eq!(
            github_copilot_finding.category,
            FindingCategory::Compatibility
        );
        assert_eq!(
            github_copilot_finding.location.path,
            ".github/skills/reviewer/SKILL.md"
        );
        assert!(github_copilot_finding.message.contains("`allowed-tools`"));
        assert_eq!(
            compatibility_projection(&report.compatibility.matrix[0].profiles),
            vec![(
                "github-copilot",
                CompatibilityStatus::Warn,
                vec!["SKILL050"]
            )]
        );
    }

    #[test]
    fn scan_combined_spec_and_github_copilot_keeps_structural_allowed_tools_finding() {
        let workspace = TestWorkspace::new("scan-github-copilot-combined-allowed-tools");
        workspace.write_file(
            ".github/skills/reviewer/SKILL.md",
            r#"---
name: reviewer
description: Reviews repository changes.
allowed-tools:
  - Bash(git diff:*)
---

# Reviewer
"#,
        );
        let config = parse_audit_config(
            r#"
profiles:
  - agent-skills-spec
  - github-copilot
"#,
        )
        .expect("valid config");

        let report = scan_path(
            workspace.root(),
            &ScanOptions {
                config: Some(config),
                ..ScanOptions::default()
            },
        )
        .expect("scan path");

        let mut rule_ids = report
            .findings
            .iter()
            .map(|finding| finding.rule_id.as_str())
            .collect::<Vec<_>>();
        rule_ids.sort_unstable();
        assert_eq!(rule_ids, vec!["SKILL040", "SKILL050"]);
        assert!(report
            .findings
            .iter()
            .all(|finding| finding.message.contains("`allowed-tools`")));
        assert_eq!(
            compatibility_projection(&report.compatibility.matrix[0].profiles),
            vec![
                (
                    "agent-skills-spec",
                    CompatibilityStatus::Warn,
                    vec!["SKILL040"]
                ),
                (
                    "github-copilot",
                    CompatibilityStatus::Warn,
                    vec!["SKILL050"]
                ),
            ]
        );
    }

    #[test]
    fn scan_github_copilot_is_unknown_for_script_references_without_finding_id() {
        let workspace = TestWorkspace::new("scan-github-copilot-script-warn");
        workspace.write_file(
            ".github/skills/reviewer/SKILL.md",
            r#"---
name: reviewer
description: Reviews repository changes.
---

# Reviewer

Run [check](scripts/check.sh) when explicitly requested.
"#,
        );
        workspace.write_file(".github/skills/reviewer/scripts/check.sh", "echo check\n");
        let config = parse_audit_config(
            r#"
profiles:
  - github-copilot
"#,
        )
        .expect("valid config");

        let report = scan_path(
            workspace.root(),
            &ScanOptions {
                config: Some(config),
                ..ScanOptions::default()
            },
        )
        .expect("scan path");

        assert!(report.findings.is_empty());
        assert_eq!(
            compatibility_projection(&report.compatibility.matrix[0].profiles),
            vec![(
                "github-copilot",
                CompatibilityStatus::Unknown,
                Vec::<&str>::new()
            )]
        );
    }

    #[test]
    fn scan_github_copilot_fails_for_baseline_required_findings() {
        let workspace = TestWorkspace::new("scan-github-copilot-baseline-fail");
        workspace.write_file(
            ".github/skills/reviewer/SKILL.md",
            r#"---
name: reviewer
---
"#,
        );
        let config = parse_audit_config(
            r#"
profiles:
  - github-copilot
"#,
        )
        .expect("valid config");

        let report = scan_path(
            workspace.root(),
            &ScanOptions {
                config: Some(config),
                ..ScanOptions::default()
            },
        )
        .expect("scan path");

        assert_eq!(
            compatibility_projection(&report.compatibility.matrix[0].profiles),
            vec![(
                "github-copilot",
                CompatibilityStatus::Fail,
                vec!["SKILL002"]
            )]
        );
    }

    #[test]
    fn scan_github_copilot_ignores_suppressed_skill050() {
        let workspace = TestWorkspace::new("scan-github-copilot-suppressed-skill050");
        workspace.write_file(
            ".github/skills/reviewer/SKILL.md",
            r#"---
name: reviewer
description: Reviews repository changes.
allowed-tools:
  - Bash(git diff:*)
---
"#,
        );
        let config = parse_audit_config(
            r#"
profiles:
  - github-copilot

ignore:
  - rule: SKILL050
    path: .github/skills/reviewer/SKILL.md
    reason: Repository wrapper translates host-specific tool metadata.
"#,
        )
        .expect("valid config");

        let report = scan_path(
            workspace.root(),
            &ScanOptions {
                config: Some(config),
                ..ScanOptions::default()
            },
        )
        .expect("scan path");

        assert_eq!(
            report
                .findings
                .iter()
                .map(|finding| finding.rule_id.as_str())
                .collect::<Vec<_>>(),
            vec!["SKILL040"]
        );
        assert_eq!(report.summary.suppressed_finding_count, 1);
        assert_eq!(
            compatibility_projection(&report.compatibility.matrix[0].profiles),
            vec![(
                "github-copilot",
                CompatibilityStatus::Pass,
                Vec::<&str>::new()
            )]
        );
    }

    #[test]
    fn scan_vscode_copilot_preferred_path_with_tools_passes() {
        let workspace = TestWorkspace::new("scan-vscode-copilot-preferred-pass");
        workspace.write_file(
            ".github/skills/editor/SKILL.md",
            r#"---
name: editor
description: Reviews local workspace changes.
tools:
  - shell
---

# Editor
"#,
        );
        let config = parse_audit_config(
            r#"
profiles:
  - vscode-copilot
"#,
        )
        .expect("valid config");

        let report = scan_path(
            workspace.root(),
            &ScanOptions {
                config: Some(config),
                ..ScanOptions::default()
            },
        )
        .expect("scan path");

        assert!(report.findings.is_empty());
        assert_eq!(
            compatibility_projection(&report.compatibility.matrix[0].profiles),
            vec![(
                "vscode-copilot",
                CompatibilityStatus::Pass,
                Vec::<&str>::new()
            )]
        );
    }

    #[test]
    fn scan_vscode_copilot_is_unknown_for_permissions_without_finding_id() {
        let workspace = TestWorkspace::new("scan-vscode-copilot-permissions-warn");
        workspace.write_file(
            ".github/skills/editor/SKILL.md",
            r#"---
name: editor
description: Reviews local workspace changes.
permissions:
  network: false
---

# Editor
"#,
        );
        let config = parse_audit_config(
            r#"
profiles:
  - vscode-copilot
"#,
        )
        .expect("valid config");

        let report = scan_path(
            workspace.root(),
            &ScanOptions {
                config: Some(config),
                ..ScanOptions::default()
            },
        )
        .expect("scan path");

        assert!(report.findings.is_empty());
        assert_eq!(
            compatibility_projection(&report.compatibility.matrix[0].profiles),
            vec![(
                "vscode-copilot",
                CompatibilityStatus::Unknown,
                Vec::<&str>::new()
            )]
        );
    }

    #[test]
    fn scan_vscode_copilot_is_unknown_for_non_vscode_path_without_finding_id() {
        let workspace = TestWorkspace::new("scan-vscode-copilot-path-warn");
        workspace.write_file(
            "SKILL.md",
            r#"---
name: editor
description: Reviews local workspace changes.
---

# Editor
"#,
        );
        let config = parse_audit_config(
            r#"
profiles:
  - vscode-copilot
"#,
        )
        .expect("valid config");

        let report = scan_path(
            workspace.root(),
            &ScanOptions {
                config: Some(config),
                ..ScanOptions::default()
            },
        )
        .expect("scan path");

        assert!(report.findings.is_empty());
        assert_eq!(
            compatibility_projection(&report.compatibility.matrix[0].profiles),
            vec![(
                "vscode-copilot",
                CompatibilityStatus::Unknown,
                Vec::<&str>::new()
            )]
        );
    }

    #[test]
    fn scan_vscode_copilot_warns_for_ignored_allowed_tools_with_skill050() {
        let workspace = TestWorkspace::new("scan-vscode-copilot-ignored-allowed-tools");
        workspace.write_file(
            ".github/skills/editor/SKILL.md",
            r#"---
name: editor
description: Reviews local workspace changes.
allowed-tools:
  - Bash(code --version)
---

# Editor
"#,
        );
        let config = parse_audit_config(
            r#"
profiles:
  - vscode-copilot
"#,
        )
        .expect("valid config");

        let report = scan_path(
            workspace.root(),
            &ScanOptions {
                config: Some(config),
                ..ScanOptions::default()
            },
        )
        .expect("scan path");

        let mut rule_ids = report
            .findings
            .iter()
            .map(|finding| finding.rule_id.as_str())
            .collect::<Vec<_>>();
        rule_ids.sort_unstable();
        assert_eq!(rule_ids, vec!["SKILL040", "SKILL050"]);
        let vscode_copilot_finding = report
            .findings
            .iter()
            .find(|finding| finding.rule_id == "SKILL050")
            .expect("VS Code Copilot compatibility finding");
        assert_eq!(
            vscode_copilot_finding.category,
            FindingCategory::Compatibility
        );
        assert_eq!(
            vscode_copilot_finding.location.path,
            ".github/skills/editor/SKILL.md"
        );
        assert!(vscode_copilot_finding.message.contains("`allowed-tools`"));
        assert_eq!(
            compatibility_projection(&report.compatibility.matrix[0].profiles),
            vec![(
                "vscode-copilot",
                CompatibilityStatus::Warn,
                vec!["SKILL050"]
            )]
        );
    }

    #[test]
    fn scan_combined_spec_and_vscode_copilot_keeps_structural_allowed_tools_finding() {
        let workspace = TestWorkspace::new("scan-vscode-copilot-combined-allowed-tools");
        workspace.write_file(
            ".github/skills/editor/SKILL.md",
            r#"---
name: editor
description: Reviews local workspace changes.
allowed-tools:
  - Bash(code --version)
---

# Editor
"#,
        );
        let config = parse_audit_config(
            r#"
profiles:
  - agent-skills-spec
  - vscode-copilot
"#,
        )
        .expect("valid config");

        let report = scan_path(
            workspace.root(),
            &ScanOptions {
                config: Some(config),
                ..ScanOptions::default()
            },
        )
        .expect("scan path");

        let mut rule_ids = report
            .findings
            .iter()
            .map(|finding| finding.rule_id.as_str())
            .collect::<Vec<_>>();
        rule_ids.sort_unstable();
        assert_eq!(rule_ids, vec!["SKILL040", "SKILL050"]);
        assert!(report
            .findings
            .iter()
            .all(|finding| finding.message.contains("`allowed-tools`")));
        assert_eq!(
            compatibility_projection(&report.compatibility.matrix[0].profiles),
            vec![
                (
                    "agent-skills-spec",
                    CompatibilityStatus::Warn,
                    vec!["SKILL040"]
                ),
                (
                    "vscode-copilot",
                    CompatibilityStatus::Warn,
                    vec!["SKILL050"]
                ),
            ]
        );
    }

    #[test]
    fn scan_vscode_copilot_is_unknown_for_script_references_without_finding_id() {
        let workspace = TestWorkspace::new("scan-vscode-copilot-script-warn");
        workspace.write_file(
            ".github/skills/editor/SKILL.md",
            r#"---
name: editor
description: Reviews local workspace changes.
---

# Editor

Run [check](scripts/check.sh) when explicitly requested.
"#,
        );
        workspace.write_file(".github/skills/editor/scripts/check.sh", "echo check\n");
        let config = parse_audit_config(
            r#"
profiles:
  - vscode-copilot
"#,
        )
        .expect("valid config");

        let report = scan_path(
            workspace.root(),
            &ScanOptions {
                config: Some(config),
                ..ScanOptions::default()
            },
        )
        .expect("scan path");

        assert!(report.findings.is_empty());
        assert_eq!(
            compatibility_projection(&report.compatibility.matrix[0].profiles),
            vec![(
                "vscode-copilot",
                CompatibilityStatus::Unknown,
                Vec::<&str>::new()
            )]
        );
    }

    #[test]
    fn scan_vscode_copilot_fails_for_baseline_required_findings() {
        let workspace = TestWorkspace::new("scan-vscode-copilot-baseline-fail");
        workspace.write_file(
            ".github/skills/editor/SKILL.md",
            r#"---
name: editor
---
"#,
        );
        let config = parse_audit_config(
            r#"
profiles:
  - vscode-copilot
"#,
        )
        .expect("valid config");

        let report = scan_path(
            workspace.root(),
            &ScanOptions {
                config: Some(config),
                ..ScanOptions::default()
            },
        )
        .expect("scan path");

        assert_eq!(
            compatibility_projection(&report.compatibility.matrix[0].profiles),
            vec![(
                "vscode-copilot",
                CompatibilityStatus::Fail,
                vec!["SKILL002"]
            )]
        );
    }

    #[test]
    fn scan_vscode_copilot_ignores_suppressed_skill050() {
        let workspace = TestWorkspace::new("scan-vscode-copilot-suppressed-skill050");
        workspace.write_file(
            ".github/skills/editor/SKILL.md",
            r#"---
name: editor
description: Reviews local workspace changes.
allowed-tools:
  - Bash(code --version)
---
"#,
        );
        let config = parse_audit_config(
            r#"
profiles:
  - vscode-copilot

ignore:
  - rule: SKILL050
    path: .github/skills/editor/SKILL.md
    reason: Repository wrapper translates host-specific tool metadata.
"#,
        )
        .expect("valid config");

        let report = scan_path(
            workspace.root(),
            &ScanOptions {
                config: Some(config),
                ..ScanOptions::default()
            },
        )
        .expect("scan path");

        assert_eq!(
            report
                .findings
                .iter()
                .map(|finding| finding.rule_id.as_str())
                .collect::<Vec<_>>(),
            vec!["SKILL040"]
        );
        assert_eq!(report.summary.suppressed_finding_count, 1);
        assert_eq!(
            compatibility_projection(&report.compatibility.matrix[0].profiles),
            vec![(
                "vscode-copilot",
                CompatibilityStatus::Pass,
                Vec::<&str>::new()
            )]
        );
    }

    #[test]
    fn scan_copilot_profiles_keep_skill050_attribution_separate() {
        let workspace = TestWorkspace::new("scan-copilot-skill050-attribution");
        workspace.write_file(
            ".github/skills/editor/SKILL.md",
            r#"---
name: editor
description: Reviews local workspace changes.
allowed-tools:
  - Bash(git diff:*)
---
"#,
        );
        let config = parse_audit_config(
            r#"
profiles:
  - vscode-copilot
  - github-copilot
"#,
        )
        .expect("valid config");

        let report = scan_path(
            workspace.root(),
            &ScanOptions {
                config: Some(config),
                ..ScanOptions::default()
            },
        )
        .expect("scan path");

        assert_eq!(
            report.compatibility.profiles,
            vec!["vscode-copilot", "github-copilot"]
        );
        let mut findings = report
            .findings
            .iter()
            .map(|finding| (finding.rule_id.as_str(), finding.message.as_str()))
            .collect::<Vec<_>>();
        findings.sort_unstable();
        assert_eq!(
            findings,
            vec![
                (
                    "SKILL040",
                    "The field `allowed-tools` is not defined by the selected host profiles and may be ignored or interpreted differently.",
                ),
                (
                    "SKILL050",
                    "GitHub Copilot is likely to ignore the `allowed-tools` frontmatter field; document GitHub Copilot tool expectations with portable `tools` metadata or in the Markdown body.",
                ),
                (
                    "SKILL050",
                    "VS Code Copilot is likely to ignore the `allowed-tools` frontmatter field; document VS Code Copilot tool expectations with portable `tools` metadata or in the Markdown body.",
                ),
            ]
        );
        assert_eq!(
            compatibility_projection(&report.compatibility.matrix[0].profiles),
            vec![
                (
                    "vscode-copilot",
                    CompatibilityStatus::Warn,
                    vec!["SKILL050"]
                ),
                (
                    "github-copilot",
                    CompatibilityStatus::Warn,
                    vec!["SKILL050"]
                ),
            ]
        );
    }

    #[test]
    fn scan_copilot_profiles_warn_for_unknown_frontmatter_with_skill040() {
        let workspace = TestWorkspace::new("scan-copilot-unknown-frontmatter");
        workspace.write_file(
            ".github/skills/editor/SKILL.md",
            r#"---
name: editor
description: Reviews local workspace changes.
owner: platform
---
"#,
        );
        let config = parse_audit_config(
            r#"
profiles:
  - github-copilot
  - vscode-copilot
"#,
        )
        .expect("valid config");

        let report = scan_path(
            workspace.root(),
            &ScanOptions {
                config: Some(config),
                ..ScanOptions::default()
            },
        )
        .expect("scan path");

        assert_eq!(
            report
                .findings
                .iter()
                .map(|finding| (finding.rule_id.as_str(), finding.message.as_str()))
                .collect::<Vec<_>>(),
            vec![(
                "SKILL040",
                "The field `owner` is not defined by the selected host profiles and may be ignored or interpreted differently."
            )]
        );
        assert_eq!(
            compatibility_projection(&report.compatibility.matrix[0].profiles),
            vec![
                (
                    "github-copilot",
                    CompatibilityStatus::Warn,
                    vec!["SKILL040"]
                ),
                (
                    "vscode-copilot",
                    CompatibilityStatus::Warn,
                    vec!["SKILL040"]
                ),
            ]
        );
    }

    #[test]
    fn scan_copilot_profiles_ignore_suppressed_skill050_without_row_warning() {
        let workspace = TestWorkspace::new("scan-copilot-suppressed-skill050-attribution");
        workspace.write_file(
            ".github/skills/editor/SKILL.md",
            r#"---
name: editor
description: Reviews local workspace changes.
allowed-tools:
  - Bash(git diff:*)
---
"#,
        );
        let config = parse_audit_config(
            r#"
profiles:
  - github-copilot
  - vscode-copilot

ignore:
  - rule: SKILL050
    path: .github/skills/editor/SKILL.md
    reason: Repository wrapper translates Copilot tool metadata.
"#,
        )
        .expect("valid config");

        let report = scan_path(
            workspace.root(),
            &ScanOptions {
                config: Some(config),
                ..ScanOptions::default()
            },
        )
        .expect("scan path");

        assert_eq!(
            report
                .findings
                .iter()
                .map(|finding| finding.rule_id.as_str())
                .collect::<Vec<_>>(),
            vec!["SKILL040"]
        );
        assert_eq!(report.summary.suppressed_finding_count, 2);
        assert_eq!(
            compatibility_projection(&report.compatibility.matrix[0].profiles),
            vec![
                (
                    "github-copilot",
                    CompatibilityStatus::Pass,
                    Vec::<&str>::new()
                ),
                (
                    "vscode-copilot",
                    CompatibilityStatus::Pass,
                    Vec::<&str>::new()
                ),
            ]
        );
    }

    #[test]
    fn scan_suppressed_skill050_is_excluded_from_selected_profile_matrix_only() {
        let workspace = TestWorkspace::new("scan-suppressed-skill050-selected-profile");
        workspace.write_file(
            ".agents/skills/reviewer/SKILL.md",
            r#"---
name: reviewer
description: Reviews code changes.
allowed-tools:
  - Bash(git diff:*)
---

# Reviewer
"#,
        );
        let config = parse_audit_config(
            r#"
profiles:
  - agent-skills-spec
  - codex

ignore:
  - rule: SKILL050
    path: .agents/skills/reviewer/SKILL.md
    reason: Codex wrapper translates Claude-style tool metadata.
"#,
        )
        .expect("valid config");

        let report = scan_path(
            workspace.root(),
            &ScanOptions {
                config: Some(config),
                ..ScanOptions::default()
            },
        )
        .expect("scan path");

        assert_eq!(report.summary.finding_count, 1);
        assert_eq!(report.summary.suppressed_finding_count, 1);
        assert_eq!(report.findings[0].rule_id, "SKILL040");
        assert_eq!(report.findings[0].category, FindingCategory::Compatibility);
        assert_eq!(report.suppressed_findings[0].finding.rule_id, "SKILL050");
        assert_eq!(
            report.suppressed_findings[0].finding.category,
            FindingCategory::Compatibility
        );
        assert_eq!(
            report.suppressed_findings[0].suppression.reason,
            "Codex wrapper translates Claude-style tool metadata."
        );
        assert!(crate::fail::report_matches_fail_on(
            &report,
            &[Severity::Low]
        ));
        assert_eq!(
            compatibility_projection(&report.compatibility.matrix[0].profiles),
            vec![
                (
                    "agent-skills-spec",
                    CompatibilityStatus::Warn,
                    vec!["SKILL040"]
                ),
                ("codex", CompatibilityStatus::Pass, Vec::<&str>::new()),
            ]
        );
    }

    #[test]
    fn scan_suppressed_skill040_is_excluded_from_baseline_matrix_and_fail_on() {
        let workspace = TestWorkspace::new("scan-suppressed-skill040-baseline");
        workspace.write_file(
            "SKILL.md",
            r#"---
name: reviewer
description: Reviews code changes.
x-owner: platform-security
---

# Reviewer
"#,
        );
        let config = parse_audit_config(
            r#"
profiles:
  - agent-skills-spec
  - generic

ignore:
  - rule: SKILL040
    path: SKILL.md
    reason: Owner metadata is retained for an internal deterministic fixture.
"#,
        )
        .expect("valid config");

        let report = scan_path(
            workspace.root(),
            &ScanOptions {
                config: Some(config),
                ..ScanOptions::default()
            },
        )
        .expect("scan path");

        assert!(report.findings.is_empty());
        assert_eq!(report.summary.finding_count, 0);
        assert_eq!(report.summary.suppressed_finding_count, 1);
        assert_eq!(report.suppressed_findings[0].finding.rule_id, "SKILL040");
        assert_eq!(
            report.suppressed_findings[0].finding.category,
            FindingCategory::Compatibility
        );
        assert_eq!(
            report.suppressed_findings[0]
                .suppression
                .matched_path
                .as_deref(),
            Some("SKILL.md")
        );
        assert_eq!(
            report.suppressed_findings[0].suppression.reason,
            "Owner metadata is retained for an internal deterministic fixture."
        );
        assert!(!crate::fail::report_matches_fail_on(
            &report,
            &[Severity::Low]
        ));
        assert_eq!(
            compatibility_projection(&report.compatibility.matrix[0].profiles),
            vec![
                (
                    "agent-skills-spec",
                    CompatibilityStatus::Pass,
                    Vec::<&str>::new()
                ),
                ("generic", CompatibilityStatus::Pass, Vec::<&str>::new()),
            ]
        );
    }

    #[test]
    fn scan_copilot_profiles_are_unknown_for_permissions_without_findings() {
        let workspace = TestWorkspace::new("scan-copilot-permissions-matrix-only");
        workspace.write_file(
            ".github/skills/editor/SKILL.md",
            r#"---
name: editor
description: Reviews local workspace changes.
permissions:
  network: false
---
"#,
        );
        let config = parse_audit_config(
            r#"
profiles:
  - github-copilot
  - vscode-copilot
"#,
        )
        .expect("valid config");

        let report = scan_path(
            workspace.root(),
            &ScanOptions {
                config: Some(config),
                ..ScanOptions::default()
            },
        )
        .expect("scan path");

        assert!(report.findings.is_empty());
        assert_eq!(
            compatibility_projection(&report.compatibility.matrix[0].profiles),
            vec![
                (
                    "github-copilot",
                    CompatibilityStatus::Unknown,
                    Vec::<&str>::new()
                ),
                (
                    "vscode-copilot",
                    CompatibilityStatus::Unknown,
                    Vec::<&str>::new()
                ),
            ]
        );
    }

    #[test]
    fn scan_generic_fails_for_required_baseline_findings() {
        let workspace = TestWorkspace::new("scan-generic-fail");
        workspace.write_file(
            "SKILL.md",
            r#"---
description: Missing name fixture.
owner: platform
---

This manifest intentionally has no heading fallback.
"#,
        );
        let config = parse_audit_config(
            r#"
profiles:
  - generic
"#,
        )
        .expect("valid config");

        let report = scan_path(
            workspace.root(),
            &ScanOptions {
                config: Some(config),
                ..ScanOptions::default()
            },
        )
        .expect("scan path");

        assert_eq!(
            compatibility_projection(&report.compatibility.matrix[0].profiles),
            vec![(
                "generic",
                CompatibilityStatus::Fail,
                vec!["SKILL001", "SKILL040"]
            )]
        );
    }

    #[test]
    fn scan_generic_ignores_suppressed_findings() {
        let workspace = TestWorkspace::new("scan-generic-suppressed");
        workspace.write_file(
            "SKILL.md",
            r#"---
description: Suppressed missing name fixture.
---

This manifest intentionally has no heading fallback.
"#,
        );
        let config = parse_audit_config(
            r#"
profiles:
  - generic

ignore:
  - rule: SKILL001
    path: SKILL.md
    reason: Accepted missing name fixture.
"#,
        )
        .expect("valid config");

        let report = scan_path(
            workspace.root(),
            &ScanOptions {
                config: Some(config),
                ..ScanOptions::default()
            },
        )
        .expect("scan path");

        assert!(report.findings.is_empty());
        assert_eq!(report.summary.suppressed_finding_count, 1);
        assert_eq!(
            compatibility_projection(&report.compatibility.matrix[0].profiles),
            vec![("generic", CompatibilityStatus::Pass, Vec::<&str>::new())]
        );
    }

    #[test]
    fn scan_agent_skills_spec_ignores_suppressed_findings() {
        let workspace = TestWorkspace::new("scan-agent-spec-suppressed");
        workspace.write_file(
            "SKILL.md",
            r#"---
description: Suppressed missing name fixture.
---

This manifest intentionally has no heading fallback.
"#,
        );
        let config = parse_audit_config(
            r#"
ignore:
  - rule: SKILL001
    path: SKILL.md
    reason: Accepted missing name fixture.
"#,
        )
        .expect("valid config");

        let report = scan_path(
            workspace.root(),
            &ScanOptions {
                config: Some(config),
                ..ScanOptions::default()
            },
        )
        .expect("scan path");

        assert!(report.findings.is_empty());
        assert_eq!(report.summary.suppressed_finding_count, 1);
        assert_eq!(
            compatibility_projection(&report.compatibility.matrix[0].profiles)[0],
            (
                "agent-skills-spec",
                CompatibilityStatus::Pass,
                Vec::<&str>::new()
            )
        );
    }

    #[test]
    fn scan_explicit_config_profiles_limit_matrix_and_preserve_order() {
        let workspace = TestWorkspace::new("scan-configured-compatibility");
        workspace.write_file(
            "zeta/SKILL.md",
            r#"---
name: zeta
description: Zeta compatibility fixture.
---

# Zeta
"#,
        );
        workspace.write_file(
            "alpha/SKILL.md",
            r#"---
name: alpha
description: Alpha compatibility fixture.
---

# Alpha
"#,
        );
        let config = parse_audit_config(
            r#"
profiles:
  - generic
  - codex
"#,
        )
        .expect("valid config");

        let report = scan_path(
            workspace.root(),
            &ScanOptions {
                config: Some(config),
                ..ScanOptions::default()
            },
        )
        .expect("scan path");

        assert_eq!(report.compatibility.profiles, vec!["generic", "codex"]);
        assert_eq!(
            report
                .compatibility
                .matrix
                .iter()
                .map(|row| (row.path.as_str(), row.name.as_deref()))
                .collect::<Vec<_>>(),
            vec![
                ("alpha/SKILL.md", Some("alpha")),
                ("zeta/SKILL.md", Some("zeta")),
            ]
        );
        for row in &report.compatibility.matrix {
            assert_eq!(
                compatibility_projection(&row.profiles),
                vec![
                    ("generic", CompatibilityStatus::Pass, Vec::<&str>::new()),
                    ("codex", CompatibilityStatus::Unknown, Vec::<&str>::new()),
                ]
            );
        }
        assert_eq!(report.summary.finding_count, 0);
        assert_eq!(report.summary.suppressed_finding_count, 0);
    }

    #[test]
    fn scan_explicit_config_profiles_evaluates_agent_spec_when_selected() {
        let workspace = TestWorkspace::new("scan-agent-spec-selected-profile");
        workspace.write_file(
            "SKILL.md",
            r#"---
name: selected-agent-spec
---

# Selected Agent Spec
"#,
        );
        let config = parse_audit_config(
            r#"
profiles:
  - codex
  - agent-skills-spec
"#,
        )
        .expect("valid config");

        let report = scan_path(
            workspace.root(),
            &ScanOptions {
                config: Some(config),
                ..ScanOptions::default()
            },
        )
        .expect("scan path");

        assert_eq!(
            compatibility_projection(&report.compatibility.matrix[0].profiles),
            vec![
                ("codex", CompatibilityStatus::Fail, vec!["SKILL002"]),
                (
                    "agent-skills-spec",
                    CompatibilityStatus::Fail,
                    vec!["SKILL002"]
                ),
            ]
        );
    }

    #[test]
    fn scan_explicit_config_profiles_evaluates_generic_when_selected() {
        let workspace = TestWorkspace::new("scan-generic-selected-profile");
        workspace.write_file(
            "SKILL.md",
            r#"---
name: selected-generic
description: Selected generic fixture.
owner: platform
---

# Selected Generic
"#,
        );
        let config = parse_audit_config(
            r#"
profiles:
  - codex
  - generic
"#,
        )
        .expect("valid config");

        let report = scan_path(
            workspace.root(),
            &ScanOptions {
                config: Some(config),
                ..ScanOptions::default()
            },
        )
        .expect("scan path");

        assert_eq!(
            compatibility_projection(&report.compatibility.matrix[0].profiles),
            vec![
                ("codex", CompatibilityStatus::Warn, vec!["SKILL040"]),
                ("generic", CompatibilityStatus::Warn, vec!["SKILL040"]),
            ]
        );
    }

    #[test]
    fn scan_ignores_non_relative_file_references() {
        let workspace = TestWorkspace::new("scan-non-relative-references");
        workspace.write_file(
            "SKILL.md",
            r#"---
name: non-relative-references
description: Non-relative reference fixture.
---

# Non Relative References

Use [http](http://example.test), [https](https://example.test),
[mail](mailto:security@example.test), [anchor](#non-relative-references),
and [ftp](ftp://example.test/file), [tel](tel:+15551234567),
[urn](urn:isbn:9780143127796), [vscode](vscode://file/example).
"#,
        );

        let report = scan_path(workspace.root(), &ScanOptions::default()).expect("scan path");

        assert!(report.packages[0].graph.references.is_empty());
        assert!(report.findings.is_empty());
    }

    #[test]
    fn scan_checks_relative_references_after_stripping_query_and_fragment() {
        let workspace = TestWorkspace::new("scan-reference-query-fragment");
        workspace.write_file(
            "SKILL.md",
            r#"---
name: query-fragment-references
description: Query and fragment reference fixture.
---

# Query Fragment References

Read [guide](references/guide.md?raw=1#setup) and inspect ![badge](assets/badge.png#icon).
"#,
        );
        workspace.write_file("references/guide.md", "# Guide\n");
        workspace.write_file("assets/badge.png", "badge\n");

        let report = scan_path(workspace.root(), &ScanOptions::default()).expect("scan path");

        assert_eq!(report.summary.broken_reference_count, 0);
        assert_eq!(
            report.packages[0]
                .graph
                .references
                .iter()
                .map(|reference| (reference.target.as_str(), reference.exists))
                .collect::<Vec<_>>(),
            vec![
                ("assets/badge.png#icon", Some(true)),
                ("references/guide.md?raw=1#setup", Some(true)),
            ]
        );
    }

    #[test]
    fn scan_marks_unsafe_filesystem_references_missing_without_escaping_skill_root() {
        let workspace = TestWorkspace::new("scan-unsafe-references");
        workspace.write_file(
            "skill/SKILL.md",
            r#"---
name: unsafe-references
description: Unsafe reference fixture.
---

# Unsafe References

Read [parent](../outside.md), [absolute](/outside.md), and [windows](C:/outside.md).
"#,
        );
        workspace.write_file("outside.md", "# Outside\n");

        let report = scan_path(workspace.root(), &ScanOptions::default()).expect("scan path");

        assert_eq!(report.summary.broken_reference_count, 3);
        assert_eq!(
            report.packages[0]
                .graph
                .references
                .iter()
                .map(|reference| (reference.target.as_str(), reference.exists))
                .collect::<Vec<_>>(),
            vec![
                ("../outside.md", Some(false)),
                ("/outside.md", Some(false)),
                ("C:/outside.md", Some(false)),
            ]
        );
    }

    #[test]
    fn display_path_returns_original_path_when_not_under_root() {
        let root = Path::new("root");
        let outside = Path::new("outside").join("SKILL.md");

        assert_eq!(display_path(root, &outside), "outside/SKILL.md");
    }

    #[test]
    fn scan_security_prompt_injection_fixture_emits_sec011() {
        let report = scan_security_fixture("prompt-injection");

        let finding = assert_security_finding(&report, "SEC011", "SKILL.md", Some(8));
        assert_eq!(finding.confidence, FindingConfidence::Medium);
        assert_eq!(report.summary.actual_secret_evidence_count, 0);
        assert_eq!(report.summary.prompt_secret_exposure_count, 1);
    }

    #[test]
    fn scan_security_env_secret_usage_counts_actual_secret_evidence_only() {
        let report = scan_security_fixture("env-exfiltration");

        assert_security_finding(&report, "SEC002", "scripts/upload.sh", Some(3));
        assert_security_finding(&report, "SEC003", "scripts/upload.sh", Some(3));
        assert_eq!(report.summary.actual_secret_evidence_count, 3);
        assert_eq!(report.summary.prompt_secret_exposure_count, 1);
    }

    #[test]
    fn scan_security_hidden_instruction_fixtures_emit_sec012() {
        for fixture in [
            "hidden-instruction-comments",
            "hidden-instruction-code-block",
            "hidden-instruction-multiline-comment",
        ] {
            let report = scan_security_fixture(fixture);

            let finding = assert_security_finding(&report, "SEC012", "SKILL.md", None);
            assert_eq!(finding.confidence, FindingConfidence::Medium);
        }
    }

    #[test]
    fn scan_maps_representative_finding_confidence_conservatively() {
        assert_eq!(
            finding_confidence_from_rule_id(RuleId::Sec001),
            FindingConfidence::High
        );
        assert_eq!(
            finding_confidence_from_rule_id(RuleId::Skill041),
            FindingConfidence::High
        );
        assert_eq!(
            finding_confidence_from_rule_id(RuleId::Sec011),
            FindingConfidence::Medium
        );
        assert_eq!(
            finding_confidence_from_rule_id(RuleId::Sec012),
            FindingConfidence::Medium
        );
        assert_eq!(
            finding_confidence_from_rule_id(RuleId::Supply005),
            FindingConfidence::Medium
        );
        assert_eq!(
            finding_confidence_from_rule_id(RuleId::Supply012),
            FindingConfidence::High
        );
    }

    #[test]
    fn scan_security_normal_instructions_fixture_stays_clean_for_sec011_and_sec012() {
        let report = scan_security_fixture("normal-instructions");

        assert!(
            report
                .findings
                .iter()
                .all(|finding| !matches!(finding.rule_id.as_str(), "SEC011" | "SEC012")),
            "normal fixture emitted instruction security findings: {:#?}",
            report.findings
        );
    }

    #[test]
    fn scan_security_package_install_unpinned_fixture_emits_sec009() {
        let report = scan_security_fixture("package-install-unpinned");
        let sec009 = report
            .findings
            .iter()
            .filter(|finding| finding.rule_id == "SEC009")
            .collect::<Vec<_>>();

        assert_eq!(sec009.len(), 5, "findings: {:#?}", report.findings);
        assert_eq!(
            sec009
                .iter()
                .map(|finding| (finding.location.path.as_str(), finding.location.line))
                .collect::<Vec<_>>(),
            vec![
                ("scripts/install.sh", Some(3)),
                ("scripts/install.sh", Some(4)),
                ("scripts/install.sh", Some(5)),
                ("scripts/install.sh", Some(6)),
                ("scripts/install.sh", Some(7)),
            ]
        );
        assert!(sec009.iter().all(|finding| {
            finding.category == FindingCategory::Security
                && finding.severity == Severity::Low
                && finding.message.contains("supply-chain risk")
        }));
    }

    #[test]
    fn scan_security_package_install_pinned_and_lockfile_fixtures_avoid_sec009() {
        for fixture in ["package-install-pinned", "package-install-lockfile-backed"] {
            let report = scan_security_fixture(fixture);

            assert!(
                report
                    .findings
                    .iter()
                    .all(|finding| finding.rule_id != "SEC009"),
                "{fixture} emitted SEC009 findings: {:#?}",
                report.findings
            );
        }
    }

    #[test]
    fn scan_exact_pinned_requirements_manifest_avoids_install_reproducibility_findings() {
        let workspace = TestWorkspace::new("scan-exact-requirements-install");
        workspace.write_file("SKILL.md", security_package_install_skill());
        workspace.write_file("requirements.txt", "requests==2.32.0\nclick==8.1.7\n");
        workspace.write_file(
            "scripts/install.sh",
            "# SPDX-License-Identifier: Apache-2.0\n\npip install -r requirements.txt\n",
        );

        let report = scan_path(workspace.root(), &ScanOptions::default()).expect("scan path");

        assert!(
            report.findings.iter().all(|finding| !matches!(
                finding.rule_id.as_str(),
                "SEC009" | "SUPPLY003" | "SUPPLY004"
            )),
            "exact-pinned requirements emitted dependency reproducibility findings: {:#?}",
            report.findings
        );
        assert!(report.supply_chain.lockfiles.is_empty());
        assert_eq!(
            report
                .supply_chain
                .dependency_manifests
                .iter()
                .map(|manifest| (manifest.path.as_str(), manifest.pinning))
                .collect::<Vec<_>>(),
            vec![(
                "requirements.txt",
                DependencyManifestPinningKind::ExactPinned
            )]
        );
    }

    #[test]
    fn scan_range_based_requirements_manifest_keeps_dependency_findings() {
        let workspace = TestWorkspace::new("scan-range-requirements-install");
        workspace.write_file("SKILL.md", security_package_install_skill());
        workspace.write_file("requirements.txt", "requests>=2.0\n");
        workspace.write_file(
            "scripts/install.sh",
            "# SPDX-License-Identifier: Apache-2.0\n\npip install -r requirements.txt\n",
        );

        let report = scan_path(workspace.root(), &ScanOptions::default()).expect("scan path");

        assert_security_finding(&report, "SEC009", "scripts/install.sh", Some(3));
        assert!(report
            .findings
            .iter()
            .any(|finding| finding.rule_id == "SUPPLY003"
                && finding.location.path == "scripts/install.sh"));
        assert!(report
            .findings
            .iter()
            .any(|finding| finding.rule_id == "SUPPLY004"
                && finding.location.path == "requirements.txt"));
        assert!(report.supply_chain.lockfiles.is_empty());
        assert_eq!(
            report.supply_chain.dependency_manifests[0].pinning,
            DependencyManifestPinningKind::RangeBased
        );
    }

    #[test]
    fn scan_mismatched_requirements_manifest_keeps_install_reproducibility_findings() {
        let workspace = TestWorkspace::new("scan-mismatched-requirements-install");
        workspace.write_file("SKILL.md", security_package_install_skill());
        workspace.write_file("requirements.txt", "requests==2.32.0\n");
        workspace.write_file(
            "scripts/install.sh",
            "# SPDX-License-Identifier: Apache-2.0\n\npip install -r other.txt\n",
        );

        let report = scan_path(workspace.root(), &ScanOptions::default()).expect("scan path");

        assert_security_finding(&report, "SEC009", "scripts/install.sh", Some(3));
        assert!(report
            .findings
            .iter()
            .any(|finding| finding.rule_id == "SUPPLY003"
                && finding.location.path == "scripts/install.sh"));
        assert!(report.supply_chain.lockfiles.is_empty());
        assert_eq!(
            report.supply_chain.dependency_manifests[0].pinning,
            DependencyManifestPinningKind::ExactPinned
        );
    }

    #[test]
    fn scan_security_package_install_report_paths_are_portable() {
        let report = scan_security_fixture("package-install-unpinned");
        let json = serde_json::to_string_pretty(&report).expect("serialize report");
        let fixture_root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .join("fixtures/security/package-install-unpinned");

        assert!(!json_contains_workspace_root(&json, &fixture_root));
        assert!(json.contains("\"path\": \"scripts/install.sh\""));
        assert!(!json.contains("fixtures/security/package-install-unpinned"));
    }

    #[test]
    fn scan_security_fixture_corpus_emits_active_sec_findings_by_default() {
        let fixture_root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .join("fixtures/security");
        let report = scan_path(&fixture_root, &ScanOptions::default())
            .expect("scan security fixture corpus");

        let active_sec_rules = ACTIVE_RULE_IDS
            .iter()
            .copied()
            .filter(|rule_id| rule_id.starts_with("SEC"))
            .collect::<Vec<_>>();
        for rule_id in active_sec_rules {
            assert!(
                report.findings.iter().any(|finding| {
                    finding.category == FindingCategory::Security && finding.rule_id == rule_id
                }),
                "security corpus did not cover {rule_id}: {:#?}",
                report.findings
            );
        }
        assert_security_finding(&report, "SEC001", "curl-bash/scripts/install.sh", Some(3));
        assert_security_finding(
            &report,
            "SEC002",
            "env-exfiltration/scripts/upload.sh",
            Some(3),
        );
        assert_security_finding(
            &report,
            "SEC003",
            "env-exfiltration/scripts/upload.sh",
            Some(3),
        );
        assert_security_finding(
            &report,
            "SEC007",
            "write-outside/scripts/write-outside.sh",
            Some(3),
        );
        assert_security_finding(
            &report,
            "SEC009",
            "package-install-unpinned/scripts/install.sh",
            Some(3),
        );
        assert_security_finding(&report, "SEC011", "prompt-injection/SKILL.md", Some(8));
        assert_security_finding(
            &report,
            "SEC012",
            "hidden-instruction-comments/SKILL.md",
            Some(8),
        );
        let json = serde_json::to_string_pretty(&report).expect("serialize report");
        assert!(!json_contains_workspace_root(&json, &fixture_root));
    }

    #[test]
    fn scan_security_benign_fixtures_stay_clean_for_sec_findings() {
        for fixture in [
            "benign-local-script",
            "read-only-python",
            "normal-instructions",
        ] {
            let report = scan_security_fixture(fixture);

            assert!(
                report
                    .findings
                    .iter()
                    .all(|finding| !(finding.category == FindingCategory::Security
                        && finding.rule_id.starts_with("SEC"))),
                "{fixture} emitted SEC findings: {:#?}",
                report.findings
            );
        }
    }

    #[test]
    fn scan_security_sudo_install_fixture_keeps_reserved_sec005_metadata_only() {
        let report = scan_security_fixture("sudo-install");

        assert!(
            report
                .findings
                .iter()
                .all(|finding| finding.rule_id != "SEC005"),
            "sudo fixture emitted reserved SEC005 finding: {:#?}",
            report.findings
        );
    }

    #[test]
    fn scan_rule_execution_modes_preserve_current_default_output() {
        let workspace = TestWorkspace::new("scan-rule-execution-mode-no-drift");
        workspace.write_file(
            "SKILL.md",
            r#"---
name: rule-mode-no-drift
---

# Rule Mode No Drift

Read [missing](references/missing.md) and run scripts/install.sh.
"#,
        );
        workspace.write_file(
            "scripts/install.sh",
            "# SPDX-License-Identifier: Apache-2.0\n\nnpm install left-pad@^1.0.0\n",
        );

        let default_report =
            scan_path(workspace.root(), &ScanOptions::default()).expect("default scan");
        let default_json =
            serde_json::to_string_pretty(&default_report).expect("serialize default report");

        for mode in [
            RuleExecutionMode::Default,
            RuleExecutionMode::Strict,
            RuleExecutionMode::Research,
        ] {
            let options = ScanOptions {
                config: Some(AuditConfig {
                    rule_mode: mode,
                    ..AuditConfig::empty()
                }),
                ..ScanOptions::default()
            };
            let first = scan_path(workspace.root(), &options).expect("mode scan");
            let second = scan_path(workspace.root(), &options).expect("repeat mode scan");
            let first_json = serde_json::to_string_pretty(&first).expect("serialize first report");
            let second_json =
                serde_json::to_string_pretty(&second).expect("serialize second report");

            assert_eq!(first_json.as_bytes(), second_json.as_bytes());
            assert_eq!(
                first_json, default_json,
                "{mode} mode changed default output"
            );
            assert_eq!(
                first
                    .findings
                    .iter()
                    .map(|finding| finding.rule_id.as_str())
                    .collect::<Vec<_>>(),
                vec!["SKILL010", "SEC009", "SUPPLY003", "SUPPLY004"]
            );
        }
    }

    #[test]
    fn scan_security_analysis_does_not_execute_artifact_scripts() {
        let workspace = TestWorkspace::new("scan-security-static-only");
        workspace.write_file("SKILL.md", security_package_install_skill());
        workspace.write_file(
            "scripts/install.sh",
            "# SPDX-License-Identifier: Apache-2.0\n\nnpm install left-pad\ntouch executed-marker\n",
        );

        let report = scan_path(workspace.root(), &ScanOptions::default()).expect("scan path");

        assert_security_finding(&report, "SEC009", "scripts/install.sh", Some(3));
        assert!(!workspace.root().join("executed-marker").exists());
    }

    #[test]
    fn scan_unsuppressed_security_findings_trigger_fail_on_by_severity() {
        let workspace = TestWorkspace::new("scan-security-fail-on");
        workspace.write_file("SKILL.md", security_package_install_skill());
        workspace.write_file(
            "scripts/install.sh",
            "# SPDX-License-Identifier: Apache-2.0\n\nnpm install left-pad\n",
        );

        let report = scan_path(workspace.root(), &ScanOptions::default()).expect("scan path");

        assert_security_finding(&report, "SEC009", "scripts/install.sh", Some(3));
        assert!(crate::fail::report_matches_fail_on(
            &report,
            &[Severity::Low]
        ));
        assert!(crate::fail::report_matches_fail_on(
            &report,
            &[Severity::Medium]
        ));
    }

    #[test]
    fn scan_security_findings_can_be_suppressed_by_exact_rule_and_path() {
        let workspace = TestWorkspace::new("scan-security-suppression");
        workspace.write_file("SKILL.md", security_package_install_skill());
        workspace.write_file(
            "scripts/install.sh",
            "# SPDX-License-Identifier: Apache-2.0\n\nnpm install left-pad\n",
        );
        let config = parse_audit_config(
            r#"
ignore:
  - rule: SEC009
    path: scripts/install.sh
    reason: Package install command is reviewed in this fixture.
  - rule: SUPPLY003
    path: scripts/install.sh
    reason: Package install command is reviewed in this fixture.
  - rule: SUPPLY004
    path: scripts/install.sh
    reason: Package install command is reviewed in this fixture.
"#,
        )
        .expect("valid config");

        let report = scan_path(
            workspace.root(),
            &ScanOptions {
                config: Some(config),
                ..ScanOptions::default()
            },
        )
        .expect("scan path");

        assert_eq!(report.summary.finding_count, 0);
        assert_eq!(report.summary.suppressed_finding_count, 3);
        assert_eq!(
            suppressed_finding_projection(&report.suppressed_findings),
            vec![
                ("scripts/install.sh", "SEC009"),
                ("scripts/install.sh", "SUPPLY003"),
                ("scripts/install.sh", "SUPPLY004")
            ]
        );
        assert_eq!(
            report.suppressed_findings[0].finding.category,
            FindingCategory::Security
        );
        assert!(!crate::fail::report_matches_fail_on(
            &report,
            &[Severity::Low]
        ));
    }

    #[test]
    fn reports_skill001_missing_name_with_complete_finding_metadata() {
        let workspace = TestWorkspace::new("scan-skill001");
        workspace.write_file(
            "SKILL.md",
            r#"---
description: Missing name fixture.
---

This manifest has a description but no frontmatter name or heading fallback.
"#,
        );

        let report = scan_path(workspace.root(), &ScanOptions::default()).expect("scan path");

        assert_eq!(report.findings.len(), 1);
        assert_finding(
            &report.findings[0],
            ExpectedFinding {
                rule_id: "SKILL001",
                message: "The skill manifest does not declare a name.",
                path: "SKILL.md",
                line: Some(1),
            },
        );
    }

    #[test]
    fn reports_skill002_missing_description_with_complete_finding_metadata() {
        let workspace = TestWorkspace::new("scan-skill002");
        workspace.write_file(
            "SKILL.md",
            r#"---
name: missing-description
---

# Missing Description
"#,
        );

        let report = scan_path(workspace.root(), &ScanOptions::default()).expect("scan path");

        assert_eq!(report.findings.len(), 1);
        assert_finding(
            &report.findings[0],
            ExpectedFinding {
                rule_id: "SKILL002",
                message: "The skill manifest does not declare a description.",
                path: "SKILL.md",
                line: Some(1),
            },
        );
    }

    #[test]
    fn reports_skill010_broken_relative_reference_with_complete_finding_metadata() {
        let workspace = TestWorkspace::new("scan-skill010");
        workspace.write_file(
            "SKILL.md",
            r#"---
name: broken-reference
description: Broken reference fixture.
---

# Broken Reference

Read [missing guidance](references/missing.md).
"#,
        );

        let report = scan_path(workspace.root(), &ScanOptions::default()).expect("scan path");

        assert_eq!(report.findings.len(), 1);
        assert_finding(
            &report.findings[0],
            ExpectedFinding {
                rule_id: "SKILL010",
                message:
                    "The manifest references `references/missing.md`, but the file was not found.",
                path: "SKILL.md",
                line: Some(8),
            },
        );
    }

    #[test]
    fn reports_skill020_oversized_manifest_with_complete_finding_metadata() {
        let workspace = TestWorkspace::new("scan-skill020");
        workspace.write_file(
            "SKILL.md",
            r#"---
name: oversized
description: Oversized fixture.
---

# Oversized

This manifest is valid but deliberately longer than the low test threshold.
"#,
        );

        let report = scan_path(
            workspace.root(),
            &ScanOptions {
                max_manifest_bytes: 80,
                ..ScanOptions::default()
            },
        )
        .expect("scan path");

        assert_eq!(report.findings.len(), 1);
        assert_finding(
            &report.findings[0],
            ExpectedFinding {
                rule_id: "SKILL020",
                message: "The SKILL.md file exceeds the recommended manifest size.",
                path: "SKILL.md",
                line: Some(1),
            },
        );
    }

    #[test]
    fn reports_skill030_duplicate_names_with_complete_finding_metadata() {
        let workspace = TestWorkspace::new("scan-skill030");
        workspace.write_file(
            "alpha/SKILL.md",
            r#"---
name: shared-name
description: Alpha duplicate fixture.
---

# Alpha
"#,
        );
        workspace.write_file(
            "beta/SKILL.md",
            r#"---
name: shared-name
description: Beta duplicate fixture.
---

# Beta
"#,
        );

        let report = scan_path(workspace.root(), &ScanOptions::default()).expect("scan path");

        assert_eq!(report.findings.len(), 2);
        assert_eq!(report.summary.package_count, 2);
        assert_eq!(report.summary.finding_count, 2);
        assert_eq!(report.summary.invalid_manifest_count, 0);
        assert_eq!(report.summary.broken_reference_count, 0);
        assert_duplicate_name_finding(
            &report.findings[0],
            "shared-name",
            "alpha/SKILL.md",
            &["beta/SKILL.md"],
        );
        assert_duplicate_name_finding(
            &report.findings[1],
            "shared-name",
            "beta/SKILL.md",
            &["alpha/SKILL.md"],
        );
    }

    #[test]
    fn duplicate_name_findings_are_deterministic_by_package_path() {
        let workspace = TestWorkspace::new("scan-skill030-order");
        workspace.write_file(
            "zeta/SKILL.md",
            r#"---
name: shared-name
description: Zeta duplicate fixture.
---

# Zeta
"#,
        );
        workspace.write_file(
            "alpha/SKILL.md",
            r#"---
name: shared-name
description: Alpha duplicate fixture.
---

# Alpha
"#,
        );
        workspace.write_file(
            "middle/SKILL.md",
            r#"---
name: shared-name
description: Middle duplicate fixture.
---

# Middle
"#,
        );

        let report = scan_path(workspace.root(), &ScanOptions::default()).expect("scan path");

        assert_eq!(
            report
                .findings
                .iter()
                .map(|finding| finding.location.path.as_str())
                .collect::<Vec<_>>(),
            vec!["alpha/SKILL.md", "middle/SKILL.md", "zeta/SKILL.md"]
        );
        assert_duplicate_name_finding(
            &report.findings[0],
            "shared-name",
            "alpha/SKILL.md",
            &["middle/SKILL.md", "zeta/SKILL.md"],
        );
        assert_duplicate_name_finding(
            &report.findings[1],
            "shared-name",
            "middle/SKILL.md",
            &["alpha/SKILL.md", "zeta/SKILL.md"],
        );
        assert_duplicate_name_finding(
            &report.findings[2],
            "shared-name",
            "zeta/SKILL.md",
            &["alpha/SKILL.md", "middle/SKILL.md"],
        );
    }

    #[test]
    fn missing_name_packages_do_not_participate_in_duplicate_name_detection() {
        let workspace = TestWorkspace::new("scan-skill030-missing-name");
        workspace.write_file(
            "alpha/SKILL.md",
            r#"---
description: Missing name alpha fixture.
---

No heading fallback.
"#,
        );
        workspace.write_file(
            "beta/SKILL.md",
            r#"---
description: Missing name beta fixture.
---

No heading fallback.
"#,
        );

        let report = scan_path(workspace.root(), &ScanOptions::default()).expect("scan path");

        assert_eq!(report.summary.package_count, 2);
        assert_eq!(report.summary.finding_count, 2);
        assert_eq!(report.summary.invalid_manifest_count, 2);
        assert_eq!(report.summary.broken_reference_count, 0);
        assert!(report
            .findings
            .iter()
            .all(|finding| finding.rule_id == "SKILL001"));
    }

    #[test]
    fn duplicate_name_detection_is_case_sensitive() {
        let workspace = TestWorkspace::new("scan-skill030-case-sensitive");
        workspace.write_file(
            "upper/SKILL.md",
            r#"---
name: Example
description: Uppercase fixture.
---

# Upper
"#,
        );
        workspace.write_file(
            "lower/SKILL.md",
            r#"---
name: example
description: Lowercase fixture.
---

# Lower
"#,
        );

        let report = scan_path(workspace.root(), &ScanOptions::default()).expect("scan path");

        assert_eq!(report.summary.package_count, 2);
        assert_eq!(report.summary.finding_count, 0);
        assert!(report.findings.is_empty());
    }

    #[test]
    fn reports_skill040_unknown_frontmatter_field_with_complete_finding_metadata() {
        let workspace = TestWorkspace::new("scan-skill040");
        workspace.write_file(
            "SKILL.md",
            r#"---
name: unknown-frontmatter
description: Unknown frontmatter fixture.
experimental_host_hint: codex-only
---

# Unknown Frontmatter
"#,
        );

        let report = scan_path(workspace.root(), &ScanOptions::default()).expect("scan path");

        assert_eq!(report.findings.len(), 1);
        assert_eq!(report.summary.invalid_manifest_count, 0);
        assert_eq!(report.summary.broken_reference_count, 0);

        let finding = &report.findings[0];
        let metadata = rule_metadata("SKILL040").expect("rule metadata exists");
        assert_eq!(finding.rule_id, "SKILL040");
        assert_eq!(finding.severity, Severity::Low);
        assert_eq!(finding.category, FindingCategory::Compatibility);
        assert_eq!(finding.title, metadata.title);
        assert_eq!(
            finding.message,
            "The field `experimental_host_hint` is not defined by the selected host profiles and may be ignored or interpreted differently."
        );
        assert_eq!(finding.location.path, "SKILL.md");
        assert_eq!(finding.location.line, Some(4));
        assert_eq!(finding.rationale, metadata.rationale);
        assert_eq!(finding.remediation, metadata.remediation);
        assert_eq!(finding.suppression, metadata.suppression_guidance);
    }

    #[test]
    fn host_specific_frontmatter_still_reports_skill040_not_skill050() {
        let workspace = TestWorkspace::new("scan-host-specific-metadata-skill040");
        workspace.write_file(
            "SKILL.md",
            r#"---
name: host-specific-frontmatter
description: Host-specific frontmatter fixture.
codex:
  tools:
    - shell
---

# Host-specific Frontmatter
"#,
        );

        let report = scan_path(workspace.root(), &ScanOptions::default()).expect("scan path");

        assert_eq!(
            report
                .findings
                .iter()
                .map(|finding| finding.rule_id.as_str())
                .collect::<Vec<_>>(),
            vec!["SKILL040"]
        );
        assert_eq!(
            report.findings[0].message,
            "The field `codex` is not defined by the selected host profiles and may be ignored or interpreted differently."
        );
    }

    #[test]
    fn reports_skill040_unknown_frontmatter_field_line_from_crlf_frontmatter() {
        let workspace = TestWorkspace::new("scan-skill040-crlf-frontmatter");
        workspace.write_file(
            "SKILL.md",
            "\u{feff}---\r\nname: crlf-frontmatter\r\ndescription: CRLF frontmatter fixture.\r\nwindows_only_hint: true\r\n---\r\n\r\n# CRLF Frontmatter\r\n",
        );

        let report = scan_path(workspace.root(), &ScanOptions::default()).expect("scan path");

        assert_eq!(report.findings.len(), 1);
        assert_eq!(report.findings[0].rule_id, "SKILL040");
        assert_eq!(report.findings[0].location.line, Some(4));
    }

    #[test]
    fn accepted_frontmatter_fields_do_not_report_skill040() {
        let workspace = TestWorkspace::new("scan-skill040-accepted-fields");
        workspace.write_file(
            "SKILL.md",
            r#"---
name: accepted-frontmatter
description: Accepted frontmatter fixture.
tools:
  - shell
permissions:
  - filesystem-read
license: Apache-2.0
---

# Accepted Frontmatter
"#,
        );

        let report = scan_path(workspace.root(), &ScanOptions::default()).expect("scan path");

        assert!(report.findings.is_empty());
        assert_eq!(report.summary.finding_count, 0);
    }

    #[test]
    fn unknown_frontmatter_fields_are_reported_in_stable_order() {
        let workspace = TestWorkspace::new("scan-skill040-stable-order");
        workspace.write_file(
            "SKILL.md",
            r#"---
name: stable-unknown-frontmatter
description: Stable unknown frontmatter fixture.
zeta_hint: last
alpha_hint: first
middle_hint: middle
---

# Stable Unknown Frontmatter
"#,
        );

        let report = scan_path(workspace.root(), &ScanOptions::default()).expect("scan path");

        assert_eq!(
            report
                .findings
                .iter()
                .map(|finding| finding.message.as_str())
                .collect::<Vec<_>>(),
            vec![
                "The field `zeta_hint` is not defined by the selected host profiles and may be ignored or interpreted differently.",
                "The field `alpha_hint` is not defined by the selected host profiles and may be ignored or interpreted differently.",
                "The field `middle_hint` is not defined by the selected host profiles and may be ignored or interpreted differently.",
            ]
        );
        assert!(report
            .findings
            .iter()
            .all(|finding| finding.rule_id == "SKILL040"));
        assert_eq!(report.summary.invalid_manifest_count, 0);
        assert_eq!(report.summary.broken_reference_count, 0);
    }

    #[test]
    fn scan_reports_missing_name_missing_description_broken_reference_and_size() {
        let workspace = TestWorkspace::new("scan-structural-findings");
        workspace.write_file(
            "a-broken-reference/SKILL.md",
            r#"---
name: broken-reference
description: Broken reference fixture.
---

# Broken Reference

Read [missing](references/missing.md).
"#,
        );
        workspace.write_file(
            "b-missing-name/SKILL.md",
            r#"---
description: Missing name fixture.
---

This starts with a paragraph and has no heading fallback.
"#,
        );
        workspace.write_file(
            "c-missing-description/SKILL.md",
            r#"---
name: missing-description
---

# Missing Description
"#,
        );
        workspace.write_file(
            "d-oversized/SKILL.md",
            r#"---
name: oversized
description: Oversized fixture.
---

# Oversized

This content exceeds the deliberately tiny test threshold.
This extra line keeps only this manifest above the test size limit.
This second extra line makes the intended `SKILL020` case unambiguous.
"#,
        );

        let report = scan_path(
            workspace.root(),
            &ScanOptions {
                max_manifest_bytes: 180,
                ..ScanOptions::default()
            },
        )
        .expect("scan path");

        let rule_ids = report
            .findings
            .iter()
            .map(|finding| finding.rule_id.as_str())
            .collect::<Vec<_>>();
        assert_eq!(
            rule_ids,
            vec!["SKILL010", "SKILL001", "SKILL002", "SKILL020"]
        );
        assert_eq!(report.summary.package_count, 4);
        assert_eq!(report.summary.finding_count, 4);
        assert_eq!(report.summary.invalid_manifest_count, 2);
        assert_eq!(report.summary.broken_reference_count, 1);

        let broken_reference = &report.findings[0];
        let metadata = rule_metadata("SKILL010").expect("rule metadata exists");
        assert_eq!(broken_reference.severity, Severity::Low);
        assert_eq!(broken_reference.category, FindingCategory::Spec);
        assert_eq!(broken_reference.title, metadata.title);
        assert!(broken_reference.message.contains("references/missing.md"));
        assert_eq!(
            broken_reference.location.path,
            "a-broken-reference/SKILL.md"
        );
        assert_eq!(broken_reference.rationale, metadata.rationale);
        assert_eq!(broken_reference.remediation, metadata.remediation);
        assert_eq!(broken_reference.suppression, metadata.suppression_guidance);
    }

    #[test]
    fn scan_finding_metadata_matches_rule_registry_for_implemented_rules() {
        let workspace = TestWorkspace::new("scan-rule-metadata");
        workspace.write_file(
            "a-broken-reference/SKILL.md",
            r#"---
name: broken-reference
description: Broken reference fixture.
---

# Broken Reference

Read [missing](references/missing.md).
"#,
        );
        workspace.write_file(
            "b-missing-name/SKILL.md",
            r#"---
description: Missing name fixture.
---

No heading fallback is present here.
"#,
        );
        workspace.write_file(
            "c-missing-description/SKILL.md",
            r#"---
name: missing-description
---

# Missing Description
"#,
        );
        workspace.write_file(
            "d-duplicate-a/SKILL.md",
            r#"---
name: duplicate-name
description: Duplicate fixture A.
---

# Duplicate A
"#,
        );
        workspace.write_file(
            "e-duplicate-b/SKILL.md",
            r#"---
name: duplicate-name
description: Duplicate fixture B.
---

# Duplicate B
"#,
        );
        workspace.write_file(
            "f-unknown-frontmatter/SKILL.md",
            r#"---
name: unknown-frontmatter
description: Unknown frontmatter fixture.
owner: security
---

# Unknown Frontmatter
"#,
        );
        workspace.write_file(
            "g-malformed-frontmatter/SKILL.md",
            r#"---
name: [unterminated
---

# Malformed Frontmatter
"#,
        );
        let mut oversized_manifest = String::from(
            "---\nname: oversized\ndescription: Oversized fixture.\n---\n\n# Oversized\n\n",
        );
        oversized_manifest
            .push_str(&"x".repeat(ScanOptions::default().max_manifest_bytes as usize));
        workspace.write_file("h-oversized/SKILL.md", &oversized_manifest);

        let report = scan_path(workspace.root(), &ScanOptions::default()).expect("scan path");
        let mut covered_rule_ids = report
            .findings
            .iter()
            .map(|finding| finding.rule_id.as_str())
            .collect::<Vec<_>>();
        covered_rule_ids.sort_unstable();
        covered_rule_ids.dedup();

        assert_eq!(
            covered_rule_ids,
            vec![
                "SKILL001", "SKILL002", "SKILL010", "SKILL020", "SKILL030", "SKILL040", "SKILL041",
            ]
        );
        for finding in &report.findings {
            let metadata =
                rule_metadata(&finding.rule_id).expect("scanner finding must have metadata");

            assert_eq!(finding.title, metadata.title, "{} title", finding.rule_id);
            assert_eq!(
                finding.severity,
                expected_severity(metadata.severity),
                "{} severity",
                finding.rule_id
            );
            assert_eq!(
                finding.category,
                expected_category(metadata.category),
                "{} category",
                finding.rule_id
            );
            assert_eq!(
                finding.rationale, metadata.rationale,
                "{} rationale",
                finding.rule_id
            );
            assert_eq!(
                finding.remediation, metadata.remediation,
                "{} remediation",
                finding.rule_id
            );
            assert_eq!(
                finding.suppression, metadata.suppression_guidance,
                "{} suppression",
                finding.rule_id
            );
        }
    }

    #[test]
    fn scan_sorts_packages_and_findings_deterministically() {
        let workspace = TestWorkspace::new("scan-deterministic-order");
        workspace.write_file("zeta/SKILL.md", "# Zeta\n");
        workspace.write_file("alpha/SKILL.md", "# Alpha\n");
        workspace.write_file("middle/SKILL.md", "# Middle\n");

        let report = scan_path(workspace.root(), &ScanOptions::default()).expect("scan path");

        assert_eq!(
            report
                .packages
                .iter()
                .map(|package| package.manifest_path.as_str())
                .collect::<Vec<_>>(),
            vec!["alpha/SKILL.md", "middle/SKILL.md", "zeta/SKILL.md"]
        );
        assert_eq!(
            report
                .findings
                .iter()
                .map(finding_sort_tuple)
                .collect::<Vec<_>>(),
            vec![
                (
                    "alpha/SKILL.md",
                    Some(1),
                    "SKILL002",
                    "The skill manifest does not declare a description."
                ),
                (
                    "middle/SKILL.md",
                    Some(1),
                    "SKILL002",
                    "The skill manifest does not declare a description."
                ),
                (
                    "zeta/SKILL.md",
                    Some(1),
                    "SKILL002",
                    "The skill manifest does not declare a description."
                ),
            ]
        );
    }

    #[test]
    fn scan_inventories_artifact_files_recursively_without_top_level_dirs() {
        let workspace = TestWorkspace::new("scan-artifact-files");
        workspace.write_file(
            "SKILL.md",
            r#"---
name: artifact-files
description: Artifact file fixture.
---

# Artifact Files
"#,
        );
        workspace.write_file("scripts/build.ps1", "Write-Output build\n");
        workspace.write_file("scripts/nested/run.sh", "echo run\n");
        workspace.write_file("references/guide.md", "# Guide\n");
        workspace.create_dir("assets/images");

        let report = scan_path(workspace.root(), &ScanOptions::default()).expect("scan path");
        let files = &report.packages[0].graph.files;

        assert_eq!(
            file_projection(files),
            vec![
                (
                    "assets/images",
                    SkillArtifactKind::Assets,
                    SkillFileKind::Directory,
                    0
                ),
                (
                    "references/guide.md",
                    SkillArtifactKind::References,
                    SkillFileKind::File,
                    8
                ),
                (
                    "scripts/build.ps1",
                    SkillArtifactKind::Scripts,
                    SkillFileKind::File,
                    19
                ),
                (
                    "scripts/nested",
                    SkillArtifactKind::Scripts,
                    SkillFileKind::Directory,
                    0
                ),
                (
                    "scripts/nested/run.sh",
                    SkillArtifactKind::Scripts,
                    SkillFileKind::File,
                    9
                ),
            ]
        );
        assert!(files
            .iter()
            .all(|file| !matches!(file.path.as_str(), "scripts" | "references" | "assets")));
    }

    #[test]
    fn scan_reports_no_artifact_files_when_artifact_dirs_are_absent() {
        let workspace = TestWorkspace::new("scan-no-artifact-dirs");
        workspace.write_file(
            "SKILL.md",
            r#"---
name: no-artifacts
description: No artifact directories fixture.
---

# No Artifacts
"#,
        );

        let report = scan_path(workspace.root(), &ScanOptions::default()).expect("scan path");

        assert_eq!(report.summary.package_count, 1);
        assert!(report.packages[0].graph.artifacts.is_empty());
        assert!(report.packages[0].graph.files.is_empty());
    }

    #[test]
    fn scan_populates_external_url_and_remote_dependency_inventory_from_manifest_and_scripts() {
        let workspace = TestWorkspace::new("scan-url-inventory");
        workspace.write_file(
            "skill/SKILL.md",
            r#"---
name: url-inventory
description: URL inventory fixture.
homepage: https://docs.example.invalid/url-inventory
---

# URL Inventory

Fetch [pinned setup](https://raw.githubusercontent.com/example/skill/0123456789abcdef0123456789abcdef01234567/scripts/setup.sh) twice:
[duplicate pinned setup](https://raw.githubusercontent.com/example/skill/0123456789abcdef0123456789abcdef01234567/scripts/setup.sh).
"#,
        );
        workspace.write_file(
            "skill/scripts/install.sh",
            "#!/usr/bin/env sh\ncurl -L https://downloads.example.invalid/tools/helper.exe -o helper.exe\n",
        );

        let report = scan_path(workspace.root(), &ScanOptions::default()).expect("scan path");
        let json = serde_json::to_string_pretty(&report).expect("serialize report");

        assert_eq!(
            report
                .supply_chain
                .external_urls
                .iter()
                .map(|url| (
                    url.path.as_str(),
                    url.line,
                    url.source,
                    url.kind,
                    url.normalized.as_str(),
                    url.pinned
                ))
                .collect::<Vec<_>>(),
            vec![
                (
                    "skill/SKILL.md",
                    Some(4),
                    SupplyChainSourceKind::Frontmatter,
                    ExternalUrlKind::Documentation,
                    "https://docs.example.invalid/url-inventory",
                    None
                ),
                (
                    "skill/SKILL.md",
                    Some(9),
                    SupplyChainSourceKind::MarkdownLink,
                    ExternalUrlKind::GithubRaw,
                    "https://raw.githubusercontent.com/example/skill/0123456789abcdef0123456789abcdef01234567/scripts/setup.sh",
                    Some(true)
                ),
                (
                    "skill/scripts/install.sh",
                    Some(2),
                    SupplyChainSourceKind::Script,
                    ExternalUrlKind::DownloadedArtifact,
                    "https://downloads.example.invalid/tools/helper.exe",
                    Some(false)
                )
            ]
        );
        assert_eq!(
            report
                .supply_chain
                .remote_dependencies
                .iter()
                .map(|dependency| (
                    dependency.path.as_str(),
                    dependency.line,
                    dependency.kind,
                    dependency.name.as_deref(),
                    dependency.version.as_deref(),
                    dependency.pinned
                ))
                .collect::<Vec<_>>(),
            vec![
                (
                    "skill/SKILL.md",
                    Some(9),
                    RemoteDependencyKind::Script,
                    Some("scripts/setup.sh"),
                    Some("0123456789abcdef0123456789abcdef01234567"),
                    Some(true)
                ),
                (
                    "skill/scripts/install.sh",
                    Some(2),
                    RemoteDependencyKind::Artifact,
                    Some("helper.exe"),
                    None,
                    Some(false)
                )
            ]
        );
        assert!(!json_contains_workspace_root(&json, workspace.root()));
    }

    #[test]
    fn scan_inventories_only_files_under_skill_package_root() {
        let workspace = TestWorkspace::new("scan-package-root-artifacts");
        workspace.write_file(
            "skill/SKILL.md",
            r#"---
name: package-root-artifacts
description: Package root artifact fixture.
---

# Package Root Artifacts
"#,
        );
        workspace.write_file("skill/scripts/in-package.sh", "echo package\n");
        workspace.write_file("scripts/outside.sh", "echo outside\n");
        workspace.write_file("references/outside.md", "# Outside\n");
        workspace.write_file("assets/outside.txt", "outside\n");

        let report = scan_path(workspace.root(), &ScanOptions::default()).expect("scan path");

        assert_eq!(report.summary.package_count, 1);
        assert_eq!(report.packages[0].root, "skill");
        assert_eq!(
            report.packages[0].graph.artifacts,
            vec!["scripts".to_owned()]
        );
        assert_eq!(
            file_projection(&report.packages[0].graph.files),
            vec![(
                "scripts/in-package.sh",
                SkillArtifactKind::Scripts,
                SkillFileKind::File,
                13
            )]
        );
    }

    #[test]
    fn scan_phase1_artifact_inventory_fixture_is_stable() {
        let fixture = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../fixtures/spec/phase1/artifact-inventory");
        let fixture_file_size = |relative_path: &str| {
            std::fs::metadata(fixture.join(relative_path))
                .expect("fixture file metadata")
                .len()
        };

        let report = scan_path(&fixture, &ScanOptions::default()).expect("scan path");

        assert_eq!(report.summary.package_count, 1);
        assert_eq!(report.packages[0].root, "");
        assert_eq!(
            report.packages[0].graph.artifacts,
            vec!["scripts", "references", "assets"]
        );
        assert_eq!(
            file_projection(&report.packages[0].graph.files),
            vec![
                (
                    "assets/images",
                    SkillArtifactKind::Assets,
                    SkillFileKind::Directory,
                    0
                ),
                (
                    "assets/images/icon.txt",
                    SkillArtifactKind::Assets,
                    SkillFileKind::File,
                    fixture_file_size("assets/images/icon.txt")
                ),
                (
                    "references/guide.md",
                    SkillArtifactKind::References,
                    SkillFileKind::File,
                    fixture_file_size("references/guide.md")
                ),
                (
                    "references/nested",
                    SkillArtifactKind::References,
                    SkillFileKind::Directory,
                    0
                ),
                (
                    "references/nested/checklist.md",
                    SkillArtifactKind::References,
                    SkillFileKind::File,
                    fixture_file_size("references/nested/checklist.md")
                ),
                (
                    "scripts/build.sh",
                    SkillArtifactKind::Scripts,
                    SkillFileKind::File,
                    fixture_file_size("scripts/build.sh")
                ),
                (
                    "scripts/nested",
                    SkillArtifactKind::Scripts,
                    SkillFileKind::Directory,
                    0
                ),
                (
                    "scripts/nested/prepare.ps1",
                    SkillArtifactKind::Scripts,
                    SkillFileKind::File,
                    fixture_file_size("scripts/nested/prepare.ps1")
                ),
            ]
        );
        assert!(report.packages[0]
            .graph
            .files
            .iter()
            .all(|file| !matches!(file.path.as_str(), "scripts" | "references" | "assets")));
    }

    #[test]
    fn scan_phase1_duplicate_names_fixture_reports_skill030() {
        let fixture = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../fixtures/spec/phase1/duplicate-names");

        let report = scan_path(&fixture, &ScanOptions::default()).expect("scan path");

        assert_eq!(report.summary.package_count, 2);
        assert_eq!(report.summary.finding_count, 2);
        assert_eq!(report.summary.invalid_manifest_count, 0);
        assert_eq!(report.summary.broken_reference_count, 0);
        assert_eq!(
            report
                .findings
                .iter()
                .map(|finding| finding.rule_id.as_str())
                .collect::<Vec<_>>(),
            vec!["SKILL030", "SKILL030"]
        );
        assert_duplicate_name_finding(
            &report.findings[0],
            "phase1-duplicate-name",
            "alpha/SKILL.md",
            &["beta/SKILL.md"],
        );
        assert_duplicate_name_finding(
            &report.findings[1],
            "phase1-duplicate-name",
            "beta/SKILL.md",
            &["alpha/SKILL.md"],
        );
    }

    #[test]
    fn scan_ignores_top_level_artifact_file() {
        let workspace = TestWorkspace::new("scan-artifact-file");
        workspace.write_file(
            "SKILL.md",
            r#"---
name: artifact-file
description: Artifact file fixture.
---

# Artifact File
"#,
        );
        workspace.write_file("scripts", "not an artifact directory\n");

        let report = scan_path(workspace.root(), &ScanOptions::default()).expect("scan path");

        assert!(report.packages[0].graph.artifacts.is_empty());
        assert!(report.packages[0].graph.files.is_empty());
    }

    #[test]
    fn scan_reports_malformed_frontmatter_without_aborting() {
        let workspace = TestWorkspace::new("scan-malformed-frontmatter");
        workspace.write_file(
            "SKILL.md",
            r#"---
name: [unterminated
---

# Malformed
"#,
        );

        let report = scan_path(workspace.root(), &ScanOptions::default()).expect("scan path");

        assert_eq!(report.summary.package_count, 1);
        assert_eq!(report.summary.finding_count, 1);
        assert_eq!(report.summary.invalid_manifest_count, 1);
        assert_eq!(report.summary.broken_reference_count, 0);
        assert_eq!(report.packages[0].root, "");
        assert_eq!(report.packages[0].manifest_path, "SKILL.md");
        assert!(report.packages[0].manifest.name.is_none());
        assert!(report.packages[0].manifest.description.is_none());
        assert!(report.packages[0].manifest.frontmatter.is_empty());
        assert!(report.packages[0].manifest.body.is_empty());
        assert!(report.packages[0].manifest.headings.is_empty());
        assert!(report.packages[0].manifest.links.is_empty());
        assert!(report.packages[0].manifest.inline_code.is_empty());
        assert!(report.packages[0].manifest.code_blocks.is_empty());
        assert!(report.packages[0].manifest.declared_tools.is_empty());
        assert!(report.packages[0].manifest.declared_permissions.is_empty());
        assert!(report.packages[0].graph.references.is_empty());
        assert!(report.packages[0].graph.artifacts.is_empty());
        assert!(report.packages[0].graph.files.is_empty());

        let finding = &report.findings[0];
        let metadata = rule_metadata("SKILL041").expect("rule metadata exists");
        assert_eq!(finding.rule_id, "SKILL041");
        assert_eq!(finding.severity, Severity::Low);
        assert_eq!(finding.category, FindingCategory::Spec);
        assert_eq!(finding.title, metadata.title);
        assert!(finding
            .message
            .starts_with("The skill manifest frontmatter could not be parsed:"));
        assert!(finding.message.contains("line"));
        assert_eq!(finding.location.path, "SKILL.md");
        assert_eq!(finding.location.line, Some(3));
        assert_eq!(finding.rationale, metadata.rationale);
        assert_eq!(finding.remediation, metadata.remediation);
        assert_eq!(finding.suppression, metadata.suppression_guidance);
    }

    #[test]
    fn scan_reports_unclosed_frontmatter_as_malformed_frontmatter() {
        let workspace = TestWorkspace::new("scan-unclosed-frontmatter");
        workspace.write_file(
            "SKILL.md",
            "\u{feff}---\r\nname: silently-accepted-before\r\n\r\n# Body Heading\r\n",
        );

        let report = scan_path(workspace.root(), &ScanOptions::default()).expect("scan path");

        assert_eq!(report.summary.package_count, 1);
        assert_eq!(report.summary.finding_count, 1);
        assert_eq!(report.summary.invalid_manifest_count, 1);
        assert!(report.packages[0].manifest.name.is_none());
        assert!(report.packages[0].manifest.description.is_none());
        assert!(report.packages[0].manifest.headings.is_empty());
        let metadata = rule_metadata("SKILL041").expect("rule metadata exists");
        assert_eq!(report.findings[0].rule_id, "SKILL041");
        assert_eq!(report.findings[0].title, metadata.title);
        assert_eq!(report.findings[0].location.path, "SKILL.md");
        assert_eq!(report.findings[0].location.line, Some(1));
        assert!(report.findings[0].message.contains("unclosed frontmatter"));
    }

    #[test]
    fn scan_phase1_malformed_frontmatter_fixture_reports_skill041() {
        let fixture = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../fixtures/spec/phase1/malformed-frontmatter");

        let report = scan_path(&fixture, &ScanOptions::default()).expect("scan path");

        assert_eq!(report.summary.package_count, 1);
        assert_eq!(report.summary.finding_count, 1);
        assert_eq!(report.summary.invalid_manifest_count, 1);
        assert_eq!(report.summary.broken_reference_count, 0);
        assert_eq!(report.findings[0].rule_id, "SKILL041");
        assert_eq!(report.findings[0].location.path, "SKILL.md");
    }

    #[test]
    fn scan_continues_after_malformed_frontmatter_manifest() {
        let workspace = TestWorkspace::new("scan-continues-after-malformed-frontmatter");
        workspace.write_file(
            "broken/SKILL.md",
            r#"---
name: [unterminated
---

# Broken
"#,
        );
        workspace.write_file(
            "valid/SKILL.md",
            r#"---
name: valid-after-broken
description: Valid manifest after malformed frontmatter.
---

# Valid
"#,
        );

        let report = scan_path(workspace.root(), &ScanOptions::default()).expect("scan path");

        assert_eq!(report.summary.package_count, 2);
        assert_eq!(report.summary.finding_count, 1);
        assert_eq!(report.summary.invalid_manifest_count, 1);
        assert_eq!(
            report
                .packages
                .iter()
                .map(|package| (
                    package.manifest_path.as_str(),
                    package.manifest.name.as_deref()
                ))
                .collect::<Vec<_>>(),
            vec![
                ("broken/SKILL.md", None),
                ("valid/SKILL.md", Some("valid-after-broken")),
            ]
        );
        assert_eq!(report.findings[0].rule_id, "SKILL041");
        assert_eq!(report.findings[0].location.path, "broken/SKILL.md");
    }

    #[test]
    fn scan_returns_read_error_for_invalid_utf8_manifest() {
        let workspace = TestWorkspace::new("scan-invalid-utf8");
        let path = workspace.root().join("SKILL.md");
        std::fs::write(&path, [0xff, 0xfe, b'\n']).expect("write invalid UTF-8 manifest");

        let error =
            scan_path(workspace.root(), &ScanOptions::default()).expect_err("scan should fail");

        match error {
            AuditError::Read { path, source } => {
                assert!(path.ends_with("SKILL.md"), "unexpected path: {path:?}");
                assert_eq!(source.kind(), ErrorKind::InvalidData);
            }
            _ => panic!("expected read error"),
        }
    }

    #[test]
    fn scan_reports_oversized_manifest_without_reading_invalid_utf8_body() {
        let workspace = TestWorkspace::new("scan-oversized-invalid-utf8");
        let path = workspace.root().join("SKILL.md");
        let mut content = vec![b'a'; 129];
        content.push(0xff);
        std::fs::write(&path, content).expect("write oversized invalid UTF-8 manifest");

        let report = scan_path(
            workspace.root(),
            &ScanOptions {
                max_manifest_bytes: 128,
                ..ScanOptions::default()
            },
        )
        .expect("oversized manifest should not be fully read");

        assert_eq!(report.summary.package_count, 1);
        assert_eq!(report.summary.finding_count, 1);
        assert_eq!(report.summary.invalid_manifest_count, 0);
        assert_eq!(report.summary.broken_reference_count, 0);
        assert_eq!(report.packages[0].root, "");
        assert_eq!(report.packages[0].manifest_path, "SKILL.md");
        assert!(report.packages[0].manifest.name.is_none());
        assert!(report.packages[0].manifest.description.is_none());
        assert!(report.packages[0].manifest.frontmatter.is_empty());
        assert!(report.packages[0].manifest.body.is_empty());
        assert!(report.packages[0].manifest.headings.is_empty());
        assert!(report.packages[0].graph.references.is_empty());
        assert!(report.packages[0].graph.artifacts.is_empty());
        assert!(report.packages[0].graph.files.is_empty());
        assert_finding(
            &report.findings[0],
            ExpectedFinding {
                rule_id: "SKILL020",
                message: "The SKILL.md file exceeds the recommended manifest size.",
                path: "SKILL.md",
                line: Some(1),
            },
        );
    }

    #[test]
    fn scan_reports_missing_name_and_description_for_nul_byte_manifest() {
        let workspace = TestWorkspace::new("scan-nul-byte-manifest");
        let path = workspace.root().join("SKILL.md");
        std::fs::write(&path, b"```\n\0\0\0\n```\n")
            .expect("write valid UTF-8 manifest with NUL bytes");

        let report = scan_path(workspace.root(), &ScanOptions::default()).expect("scan path");

        assert_eq!(report.summary.package_count, 1);
        assert_eq!(
            report
                .findings
                .iter()
                .map(|finding| finding.rule_id.as_str())
                .collect::<Vec<_>>(),
            vec!["SKILL001", "SKILL002"]
        );
    }

    #[test]
    fn config_suppression_matches_exact_rule_and_normalized_relative_path() {
        let workspace = TestWorkspace::new("scan-suppression-exact");
        workspace.write_file(
            "nested/SKILL.md",
            r#"---
description: Missing name fixture.
---

This manifest intentionally has no heading fallback.
"#,
        );
        let config = parse_audit_config(
            r#"
ignore:
  - rule: SKILL001
    path: nested\SKILL.md
    reason: Accepted missing name fixture.
"#,
        )
        .expect("valid config");

        let report = scan_path(
            workspace.root(),
            &ScanOptions {
                config: Some(config),
                ..ScanOptions::default()
            },
        )
        .expect("scan path");

        assert_eq!(report.summary.finding_count, 0);
        assert_eq!(report.summary.suppressed_finding_count, 1);
        assert!(report.findings.is_empty());
        assert_eq!(report.suppressed_findings.len(), 1);
        assert_eq!(report.suppressed_findings[0].finding.rule_id, "SKILL001");
        assert_eq!(
            report.suppressed_findings[0].finding.location.path,
            "nested/SKILL.md"
        );
        assert_eq!(
            report.suppressed_findings[0].suppression.matched_rule,
            "SKILL001"
        );
        assert_eq!(
            report.suppressed_findings[0]
                .suppression
                .matched_path
                .as_deref(),
            Some("nested/SKILL.md")
        );
        assert_eq!(
            report.suppressed_findings[0].suppression.reason,
            "Accepted missing name fixture."
        );
    }

    #[test]
    fn config_suppression_does_not_match_unmatched_rule_or_path() {
        let workspace = TestWorkspace::new("scan-suppression-unmatched");
        workspace.write_file("SKILL.md", "```\nno manifest metadata\n```\n");
        let config = parse_audit_config(
            r#"
ignore:
  - rule: SKILL002
    path: other/SKILL.md
    reason: Wrong path.
  - rule: SKILL010
    path: SKILL.md
    reason: Wrong rule.
"#,
        )
        .expect("valid config");

        let report = scan_path(
            workspace.root(),
            &ScanOptions {
                config: Some(config),
                ..ScanOptions::default()
            },
        )
        .expect("scan path");

        assert_eq!(report.summary.finding_count, 2);
        assert_eq!(report.summary.suppressed_finding_count, 0);
        assert!(report.suppressed_findings.is_empty());
        assert_eq!(
            report
                .findings
                .iter()
                .map(|finding| finding.rule_id.as_str())
                .collect::<Vec<_>>(),
            vec!["SKILL001", "SKILL002"]
        );
    }

    #[test]
    fn config_suppression_requires_exact_path_without_globs() {
        let workspace = TestWorkspace::new("scan-suppression-exact-path-only");
        workspace.write_file(
            "skills/reviewer/SKILL.md",
            r#"---
description: Missing name fixture.
---

This manifest intentionally has no heading fallback.
"#,
        );
        let config = parse_audit_config(
            r#"
ignore:
  - rule: SKILL001
    path: skills/*/SKILL.md
    reason: Glob-like paths must not match.
"#,
        )
        .expect("valid config");

        let report = scan_path(
            workspace.root(),
            &ScanOptions {
                config: Some(config),
                ..ScanOptions::default()
            },
        )
        .expect("scan path");

        assert_eq!(report.summary.finding_count, 1);
        assert_eq!(report.summary.suppressed_finding_count, 0);
        assert!(report.suppressed_findings.is_empty());
        assert_eq!(report.findings[0].rule_id, "SKILL001");
        assert_eq!(report.findings[0].location.path, "skills/reviewer/SKILL.md");
    }

    #[test]
    fn config_suppression_requires_exact_rule_id() {
        let workspace = TestWorkspace::new("scan-suppression-exact-rule-only");
        workspace.write_file(
            "SKILL.md",
            r#"---
description: Missing name fixture.
---

This manifest intentionally has no heading fallback.
"#,
        );
        let config = parse_audit_config(
            r#"
ignore:
  - rule: SKILL002
    path: SKILL.md
    reason: Different rule on the same path must not match.
"#,
        )
        .expect("valid config");

        let report = scan_path(
            workspace.root(),
            &ScanOptions {
                config: Some(config),
                ..ScanOptions::default()
            },
        )
        .expect("scan path");

        assert_eq!(report.summary.finding_count, 1);
        assert_eq!(report.summary.suppressed_finding_count, 0);
        assert!(report.suppressed_findings.is_empty());
        assert_eq!(report.findings[0].rule_id, "SKILL001");
        assert_eq!(report.findings[0].location.path, "SKILL.md");
    }

    #[test]
    fn config_match_suppression_matches_grouped_frontmatter_evidence() {
        let workspace = TestWorkspace::new("scan-suppression-match-frontmatter");
        workspace.write_file(
            "alpha/SKILL.md",
            r#"---
name: alpha
description: Alpha fixture.
requires: node
---

# Alpha
"#,
        );
        workspace.write_file(
            "beta/SKILL.md",
            r#"---
name: beta
description: Beta fixture.
requires: python
owner: platform
---

# Beta
"#,
        );
        let config = parse_audit_config(
            r#"
ignore:
  - rule: SKILL040
    match: requires
    reason: Accepted generated requires metadata across reviewed fixtures.
"#,
        )
        .expect("valid config");

        let report = scan_path(
            workspace.root(),
            &ScanOptions {
                config: Some(config),
                ..ScanOptions::default()
            },
        )
        .expect("scan path");

        assert_eq!(report.summary.finding_count, 1);
        assert_eq!(report.summary.suppressed_finding_count, 2);
        assert_eq!(report.findings[0].rule_id, "SKILL040");
        assert!(report.findings[0].message.contains("`owner`"));
        assert_eq!(
            suppressed_finding_projection(&report.suppressed_findings),
            vec![
                ("alpha/SKILL.md", "SKILL040"),
                ("beta/SKILL.md", "SKILL040")
            ]
        );
        assert!(report
            .suppressed_findings
            .iter()
            .all(|entry| entry.suppression.matched_path.is_none()));
        assert!(report.suppressed_findings.iter().all(|entry| entry
            .suppression
            .matched_match
            .as_deref()
            == Some("requires")));
    }

    #[test]
    fn skill040_groups_repeated_metadata_fields_with_profiles() {
        let workspace = TestWorkspace::new("scan-skill040-grouped-metadata-field");
        workspace.write_file(
            "alpha/SKILL.md",
            r#"---
name: alpha
description: Alpha fixture.
requires: node
---

# Alpha
"#,
        );
        workspace.write_file(
            "beta/SKILL.md",
            r#"---
name: beta
description: Beta fixture.
requires: python
---

# Beta
"#,
        );
        let config = parse_audit_config(
            r#"
profiles:
  - codex
  - github-copilot
"#,
        )
        .expect("valid config");

        let report = scan_path(
            workspace.root(),
            &ScanOptions {
                config: Some(config),
                ..ScanOptions::default()
            },
        )
        .expect("scan path");

        assert_eq!(report.findings.len(), 2);
        assert_eq!(report.finding_groups.len(), 1);

        let group = &report.finding_groups[0];
        assert_eq!(group.rule_id, "SKILL040");
        assert_eq!(group.confidence, FindingConfidence::Medium);
        assert_eq!(group.title, "Host-specific or unrecognized metadata field");
        assert_eq!(
            group.evidence_key,
            "frontmatter_field=requires|host_profile=codex,github-copilot"
        );
        assert_eq!(
            group
                .dimensions
                .get("frontmatter_field")
                .map(String::as_str),
            Some("requires")
        );
        assert_eq!(
            group.dimensions.get("host_profile").map(String::as_str),
            Some("codex,github-copilot")
        );
        assert_eq!(group.finding_count, 2);
        assert_eq!(group.affected_package_count, 2);
    }

    #[test]
    fn config_suppression_matches_combined_path_and_match() {
        let workspace = TestWorkspace::new("scan-suppression-path-and-match");
        workspace.write_file(
            "alpha/SKILL.md",
            r#"---
name: alpha
description: Alpha fixture.
requires: node
---

# Alpha
"#,
        );
        workspace.write_file(
            "beta/SKILL.md",
            r#"---
name: beta
description: Beta fixture.
requires: python
owner: platform
---

# Beta
"#,
        );
        let config = parse_audit_config(
            r#"
ignore:
  - rule: SKILL040
    path: alpha/SKILL.md
    match: requires
    reason: Accepted generated requires metadata in alpha only.
"#,
        )
        .expect("valid config");

        let report = scan_path(
            workspace.root(),
            &ScanOptions {
                config: Some(config),
                ..ScanOptions::default()
            },
        )
        .expect("scan path");

        assert_eq!(report.summary.finding_count, 2);
        assert_eq!(report.summary.suppressed_finding_count, 1);
        assert_eq!(
            suppressed_finding_projection(&report.suppressed_findings),
            vec![("alpha/SKILL.md", "SKILL040")]
        );
        assert_eq!(
            report.suppressed_findings[0]
                .suppression
                .matched_path
                .as_deref(),
            Some("alpha/SKILL.md")
        );
        assert_eq!(
            report.suppressed_findings[0]
                .suppression
                .matched_match
                .as_deref(),
            Some("requires")
        );
        assert_eq!(
            report
                .findings
                .iter()
                .map(|finding| finding.location.path.as_str())
                .collect::<Vec<_>>(),
            vec!["beta/SKILL.md", "beta/SKILL.md"]
        );
    }

    #[test]
    fn config_match_suppression_does_not_match_unrelated_evidence() {
        let workspace = TestWorkspace::new("scan-suppression-match-unmatched");
        workspace.write_file(
            "SKILL.md",
            r#"---
name: unmatched
description: Unmatched fixture.
owner: platform
---

# Unmatched
"#,
        );
        let config = parse_audit_config(
            r#"
ignore:
  - rule: SKILL040
    match: requires
    reason: Accepted generated requires metadata only.
"#,
        )
        .expect("valid config");

        let report = scan_path(
            workspace.root(),
            &ScanOptions {
                config: Some(config),
                ..ScanOptions::default()
            },
        )
        .expect("scan path");

        assert_eq!(report.summary.finding_count, 1);
        assert_eq!(report.summary.suppressed_finding_count, 0);
        assert!(report.suppressed_findings.is_empty());
        assert_eq!(report.findings[0].rule_id, "SKILL040");
        assert!(report.findings[0].message.contains("`owner`"));
    }

    #[test]
    fn config_match_suppression_keeps_json_order_deterministic() {
        let workspace = TestWorkspace::new("scan-suppression-match-order-stability");
        workspace.write_file(
            "beta/SKILL.md",
            r#"---
name: beta
description: Beta fixture.
requires: python
---

# Beta
"#,
        );
        workspace.write_file(
            "alpha/SKILL.md",
            r#"---
name: alpha
description: Alpha fixture.
requires: node
---

# Alpha
"#,
        );
        let config = parse_audit_config(
            r#"
ignore:
  - rule: SKILL040
    match: frontmatter_field=requires
    reason: Accepted generated requires metadata across reviewed fixtures.
"#,
        )
        .expect("valid config");
        let options = ScanOptions {
            config: Some(config),
            ..ScanOptions::default()
        };

        let first = scan_path(workspace.root(), &options).expect("first scan");
        let second = scan_path(workspace.root(), &options).expect("second scan");
        let (first_json, first_value) = report_json_value(&first);
        let (second_json, second_value) = report_json_value(&second);

        assert_eq!(first_json.as_bytes(), second_json.as_bytes());
        assert_eq!(first_value, second_value);
        assert_eq!(
            suppressed_finding_projection(&first.suppressed_findings),
            vec![
                ("alpha/SKILL.md", "SKILL040"),
                ("beta/SKILL.md", "SKILL040")
            ]
        );
        assert_eq!(
            first_value["suppressed_findings"][0]["suppression"]["matched_match"],
            "frontmatter_field=requires"
        );
    }

    #[test]
    fn config_suppression_leaves_unrelated_findings_unaffected() {
        let workspace = TestWorkspace::new("scan-suppression-unrelated");
        workspace.write_file(
            "SKILL.md",
            r#"---
name: suppression-unrelated
owner: platform
---

# Suppression Unrelated

Read [missing](references/missing.md).
"#,
        );
        let config = parse_audit_config(
            r#"
ignore:
  - rule: SKILL010
    path: SKILL.md
    reason: Broken reference tracked elsewhere.
"#,
        )
        .expect("valid config");

        let report = scan_path(
            workspace.root(),
            &ScanOptions {
                config: Some(config),
                ..ScanOptions::default()
            },
        )
        .expect("scan path");

        assert_eq!(report.summary.finding_count, 1);
        assert_eq!(report.summary.suppressed_finding_count, 1);
        assert_eq!(report.summary.broken_reference_count, 0);
        assert_eq!(
            report
                .findings
                .iter()
                .map(|finding| finding.rule_id.as_str())
                .collect::<Vec<_>>(),
            vec!["SKILL040"]
        );
        assert_eq!(report.suppressed_findings[0].finding.rule_id, "SKILL010");
    }

    #[test]
    fn multiple_suppressed_findings_keep_deterministic_finding_order() {
        let workspace = TestWorkspace::new("scan-suppression-multiple-order");
        workspace.write_file("alpha/SKILL.md", "```\nno manifest metadata\n```\n");
        workspace.write_file(
            "beta/SKILL.md",
            r#"---
name: broken-reference
description: Broken reference fixture.
---

# Broken Reference

Read [missing](references/missing.md).
"#,
        );
        let config = parse_audit_config(
            r#"
ignore:
  - rule: SKILL010
    path: beta/SKILL.md
    reason: Broken reference tracked elsewhere.
  - rule: SKILL002
    path: alpha/SKILL.md
    reason: Description intentionally omitted.
  - rule: SKILL001
    path: alpha/SKILL.md
    reason: Name intentionally omitted.
"#,
        )
        .expect("valid config");

        let report = scan_path(
            workspace.root(),
            &ScanOptions {
                config: Some(config),
                ..ScanOptions::default()
            },
        )
        .expect("scan path");

        assert!(report.findings.is_empty());
        assert_eq!(report.summary.suppressed_finding_count, 3);
        assert_eq!(
            suppressed_finding_projection(&report.suppressed_findings),
            vec![
                ("alpha/SKILL.md", "SKILL001"),
                ("alpha/SKILL.md", "SKILL002"),
                ("beta/SKILL.md", "SKILL010"),
            ]
        );
    }

    #[test]
    fn summary_counts_exclude_suppressed_findings_in_mixed_reports() {
        let workspace = TestWorkspace::new("scan-suppression-summary-mixed");
        workspace.write_file(
            "SKILL.md",
            r#"[](references/missing.md)
"#,
        );
        let config = parse_audit_config(
            r#"
ignore:
  - rule: SKILL001
    path: SKILL.md
    reason: Name intentionally omitted.
  - rule: SKILL010
    path: SKILL.md
    reason: Broken reference tracked elsewhere.
"#,
        )
        .expect("valid config");

        let report = scan_path(
            workspace.root(),
            &ScanOptions {
                config: Some(config),
                ..ScanOptions::default()
            },
        )
        .expect("scan path");

        assert_eq!(report.summary.finding_count, 1);
        assert_eq!(report.summary.suppressed_finding_count, 2);
        assert_eq!(report.summary.invalid_manifest_count, 1);
        assert_eq!(report.summary.broken_reference_count, 0);
        assert_eq!(
            report
                .findings
                .iter()
                .map(|finding| finding.rule_id.as_str())
                .collect::<Vec<_>>(),
            vec!["SKILL002"]
        );
        assert_eq!(
            suppressed_finding_projection(&report.suppressed_findings),
            vec![("SKILL.md", "SKILL001"), ("SKILL.md", "SKILL010")]
        );
    }

    #[test]
    fn duplicate_name_suppression_leaves_sibling_duplicate_finding_active() {
        let workspace = TestWorkspace::new("scan-suppression-duplicate-sibling");
        workspace.write_file(
            "alpha/SKILL.md",
            r#"---
name: shared-duplicate
description: Alpha duplicate fixture.
---

# Alpha Duplicate
"#,
        );
        workspace.write_file(
            "beta/SKILL.md",
            r#"---
name: shared-duplicate
description: Beta duplicate fixture.
---

# Beta Duplicate
"#,
        );
        let config = parse_audit_config(
            r#"
ignore:
  - rule: SKILL030
    path: alpha/SKILL.md
    reason: Alpha duplicate accepted for fixture coverage.
"#,
        )
        .expect("valid config");

        let report = scan_path(
            workspace.root(),
            &ScanOptions {
                config: Some(config),
                ..ScanOptions::default()
            },
        )
        .expect("scan path");

        assert_eq!(report.summary.finding_count, 1);
        assert_eq!(report.summary.suppressed_finding_count, 1);
        assert_duplicate_name_finding(
            &report.findings[0],
            "shared-duplicate",
            "beta/SKILL.md",
            &["alpha/SKILL.md"],
        );
        assert_eq!(
            suppressed_finding_projection(&report.suppressed_findings),
            vec![("alpha/SKILL.md", "SKILL030")]
        );
    }

    #[test]
    fn json_output_includes_suppression_summary_and_details() {
        let workspace = TestWorkspace::new("scan-json-suppression-details");
        workspace.write_file("SKILL.md", "```\nno manifest metadata\n```\n");
        let config = parse_audit_config(
            r#"
ignore:
  - rule: SKILL001
    path: SKILL.md
    reason: Name intentionally omitted in regression fixture.
"#,
        )
        .expect("valid config");

        let report = scan_path(
            workspace.root(),
            &ScanOptions {
                config: Some(config),
                ..ScanOptions::default()
            },
        )
        .expect("scan path");
        let (_json, value) = report_json_value(&report);

        assert_eq!(value["summary"]["finding_count"], 1);
        assert_eq!(value["summary"]["suppressed_finding_count"], 1);
        assert_eq!(
            json_string_array(&value["findings"], "rule_id"),
            vec!["SKILL002"]
        );
        assert_eq!(
            value["suppressed_findings"][0]["finding"]["rule_id"],
            "SKILL001"
        );
        assert_eq!(
            value["suppressed_findings"][0]["finding"]["location"]["path"],
            "SKILL.md"
        );
        assert_eq!(
            value["suppressed_findings"][0]["suppression"]["matched_rule"],
            "SKILL001"
        );
        assert_eq!(
            value["suppressed_findings"][0]["suppression"]["matched_path"],
            "SKILL.md"
        );
        assert_eq!(
            value["suppressed_findings"][0]["suppression"]["reason"],
            "Name intentionally omitted in regression fixture."
        );
    }

    #[test]
    fn json_output_keeps_suppressed_findings_order_and_stable_bytes() {
        let workspace = TestWorkspace::new("scan-json-suppression-order-stability");
        workspace.write_file("alpha/SKILL.md", "```\nno manifest metadata\n```\n");
        workspace.write_file(
            "beta/SKILL.md",
            r#"---
name: broken-reference
description: Broken reference fixture.
---

# Broken Reference

Read [missing](references/missing.md).
"#,
        );
        let config = parse_audit_config(
            r#"
ignore:
  - rule: SKILL010
    path: beta/SKILL.md
    reason: Broken reference tracked elsewhere.
  - rule: SKILL001
    path: alpha/SKILL.md
    reason: Name intentionally omitted.
  - rule: SKILL002
    path: alpha/SKILL.md
    reason: Description intentionally omitted.
"#,
        )
        .expect("valid config");
        let options = ScanOptions {
            config: Some(config),
            ..ScanOptions::default()
        };

        let first = scan_path(workspace.root(), &options).expect("first scan");
        let second = scan_path(workspace.root(), &options).expect("second scan");
        let (first_json, first_value) = report_json_value(&first);
        let (second_json, second_value) = report_json_value(&second);

        assert_eq!(first_json.as_bytes(), second_json.as_bytes());
        assert_eq!(first_value, second_value);
        assert_eq!(first_value["summary"]["finding_count"], 0);
        assert_eq!(first_value["summary"]["suppressed_finding_count"], 3);

        let suppressed = first_value["suppressed_findings"]
            .as_array()
            .expect("suppressed findings array");
        assert_eq!(
            suppressed
                .iter()
                .map(|entry| {
                    (
                        entry["finding"]["location"]["path"].as_str().expect("path"),
                        entry["finding"]["rule_id"].as_str().expect("rule id"),
                        entry["suppression"]["reason"].as_str().expect("reason"),
                    )
                })
                .collect::<Vec<_>>(),
            vec![
                ("alpha/SKILL.md", "SKILL001", "Name intentionally omitted."),
                (
                    "alpha/SKILL.md",
                    "SKILL002",
                    "Description intentionally omitted."
                ),
                (
                    "beta/SKILL.md",
                    "SKILL010",
                    "Broken reference tracked elsewhere."
                ),
            ]
        );
    }

    #[test]
    fn scan_phase1_oversized_manifest_fixture_reports_only_skill020() {
        let fixture = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../fixtures/spec/phase1/oversized-manifest");

        let report = scan_path(
            &fixture,
            &ScanOptions {
                max_manifest_bytes: 120,
                ..ScanOptions::default()
            },
        )
        .expect("oversized manifest should still parse");

        assert_eq!(report.summary.package_count, 1);
        assert_eq!(
            report
                .findings
                .iter()
                .map(|finding| finding.rule_id.as_str())
                .collect::<Vec<_>>(),
            vec!["SKILL020"]
        );
    }

    #[test]
    fn json_output_uses_relative_paths_and_stable_summary_fields() {
        let workspace = TestWorkspace::new("scan-json-stability");
        workspace.write_file(
            "skill/SKILL.md",
            r#"---
name: json-stability
description: JSON stability fixture.
---

# JSON Stability
"#,
        );

        let report = scan_path(workspace.root(), &ScanOptions::default()).expect("scan path");
        let (json, value) = report_json_value(&report);

        assert_eq!(value["summary"]["package_count"], 1);
        assert_eq!(value["summary"]["finding_count"], 0);
        assert_eq!(value["summary"]["invalid_manifest_count"], 0);
        assert_eq!(value["summary"]["broken_reference_count"], 0);
        assert_eq!(value["packages"][0]["root"], "skill");
        assert_eq!(value["packages"][0]["manifest_path"], "skill/SKILL.md");
        assert_eq!(value["packages"][0]["manifest"]["name"], "json-stability");
        assert_eq!(
            value["packages"][0]["manifest"]["description"],
            "JSON stability fixture."
        );
        assert_eq!(
            value["compatibility"]["profiles"],
            serde_json::json!(HOST_PROFILES)
        );
        assert_eq!(
            value["compatibility"]["matrix"][0]["path"],
            "skill/SKILL.md"
        );
        assert_eq!(
            value["compatibility"]["matrix"][0]["profiles"]
                .as_array()
                .expect("compatibility profiles")
                .iter()
                .map(|profile| (
                    profile["profile"].as_str().expect("profile"),
                    profile["status"].as_str().expect("status"),
                    profile["finding_ids"]
                        .as_array()
                        .expect("finding ids")
                        .len(),
                ))
                .collect::<Vec<_>>(),
            vec![
                ("agent-skills-spec", "pass", 0),
                ("claude-code", "unknown", 0),
                ("codex", "unknown", 0),
                ("github-copilot", "unknown", 0),
                ("vscode-copilot", "unknown", 0),
                ("generic", "pass", 0),
            ]
        );
        assert!(!json_contains_workspace_root(&json, workspace.root()));
        assert_eq!(value["audit"]["timestamp"], serde_json::Value::Null);
        assert!(!json.contains("generated_at"));
    }

    #[test]
    fn json_output_matches_full_pretty_expected_report() {
        let workspace = TestWorkspace::new("scan-json-full-expected-report");
        workspace.write_file("SKILL.md", "# Stable Snapshot\n\nStable description.\n");

        let report = scan_path(workspace.root(), &ScanOptions::default()).expect("scan path");
        let json = serde_json::to_string_pretty(&report).expect("serialize report");
        let mut value: serde_json::Value = serde_json::from_str(&json).expect("parse report");

        let expected = r##"{
  "packages": [
    {
      "root": "",
      "manifest_path": "SKILL.md",
      "manifest": {
        "name": "Stable Snapshot",
        "description": "Stable description.",
        "frontmatter": {},
        "body": "# Stable Snapshot\n\nStable description.\n",
        "headings": [
          "Stable Snapshot"
        ],
        "links": [],
        "inline_code": [],
        "code_blocks": [],
        "declared_tools": [],
        "declared_permissions": []
      },
      "graph": {
        "references": [],
        "artifacts": [],
        "files": []
      }
    }
  ],
  "findings": [],
  "finding_groups": [],
  "patterns": [],
  "suppressed_findings": [],
  "summary": {
    "package_count": 1,
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
    "offline_readiness": [
      {
        "path": "SKILL.md",
        "status": "ready",
        "score": 95,
        "reasons": [
          "no local license evidence found"
        ]
      }
    ]
  },
  "compatibility": {
    "profiles": [
      "agent-skills-spec",
      "claude-code",
      "codex",
      "github-copilot",
      "vscode-copilot",
      "generic"
    ],
    "matrix": [
      {
        "path": "SKILL.md",
        "name": "Stable Snapshot",
        "profiles": [
          {
            "profile": "agent-skills-spec",
            "status": "pass",
            "finding_ids": []
          },
          {
            "profile": "claude-code",
            "status": "unknown",
            "finding_ids": []
          },
          {
            "profile": "codex",
            "status": "unknown",
            "finding_ids": []
          },
          {
            "profile": "github-copilot",
            "status": "unknown",
            "finding_ids": []
          },
          {
            "profile": "vscode-copilot",
            "status": "unknown",
            "finding_ids": []
          },
          {
            "profile": "generic",
            "status": "pass",
            "finding_ids": []
          }
        ]
      }
    ]
  }
}"##;
        assert_eq!(value["audit"]["output_schema_version"], "1");
        assert!(json.starts_with("{\n  \"audit\":"));
        assert_eq!(value["audit"]["scanner"]["name"], "agent-audit");
        assert_eq!(
            value["audit"]["scanner"]["version"],
            env!("CARGO_PKG_VERSION")
        );
        assert_eq!(value["audit"]["timestamp"], serde_json::Value::Null);
        assert_eq!(
            value["audit"]["host_profiles"]["selected"],
            serde_json::json!(HOST_PROFILES)
        );
        assert!(value["audit"]["ruleset"]["hash"]
            .as_str()
            .expect("ruleset hash")
            .starts_with("fnv1a64:"));
        assert!(value["audit"]["host_profiles"]["hash"]
            .as_str()
            .expect("host profile hash")
            .starts_with("fnv1a64:"));
        value
            .as_object_mut()
            .expect("report object")
            .remove("audit");

        let expected_value: serde_json::Value =
            serde_json::from_str(expected).expect("parse expected report");
        assert_eq!(value, expected_value);
        assert!(!json_contains_workspace_root(&json, workspace.root()));
    }

    #[test]
    fn json_output_orders_packages_deterministically() {
        let workspace = TestWorkspace::new("scan-json-package-order");
        workspace.write_file(
            ".agents/skills/beta/SKILL.md",
            r#"---
name: beta
description: Beta fixture.
---

# Beta
"#,
        );
        workspace.write_file(
            ".agents/skills/alpha/SKILL.md",
            r#"---
name: alpha
description: Alpha fixture.
---

# Alpha
"#,
        );
        workspace.write_file(
            ".agents/skills/zeta/SKILL.md",
            r#"---
name: zeta
description: Zeta fixture.
---

# Zeta
"#,
        );

        let report = scan_path(workspace.root(), &ScanOptions::default()).expect("scan path");
        let (_json, value) = report_json_value(&report);

        assert_eq!(value["summary"]["package_count"], 3);
        assert_eq!(value["summary"]["finding_count"], 0);
        assert_eq!(
            json_string_array(&value["packages"], "manifest_path"),
            vec![
                ".agents/skills/alpha/SKILL.md",
                ".agents/skills/beta/SKILL.md",
                ".agents/skills/zeta/SKILL.md",
            ]
        );
    }

    #[test]
    fn json_output_orders_findings_deterministically() {
        let workspace = TestWorkspace::new("scan-json-finding-order");
        workspace.write_file(
            "zeta/SKILL.md",
            r#"---
name: zeta
---

# Zeta
"#,
        );
        workspace.write_file(
            "alpha/SKILL.md",
            r#"---
name: alpha
---

# Alpha
"#,
        );
        workspace.write_file(
            "middle/SKILL.md",
            r#"---
name: middle
---

# Middle
"#,
        );

        let report = scan_path(workspace.root(), &ScanOptions::default()).expect("scan path");
        let (_json, value) = report_json_value(&report);

        assert_eq!(value["summary"]["package_count"], 3);
        assert_eq!(value["summary"]["finding_count"], 3);
        assert_eq!(value["summary"]["invalid_manifest_count"], 3);
        assert_eq!(value["summary"]["broken_reference_count"], 0);
        assert_eq!(
            value["findings"]
                .as_array()
                .expect("findings array")
                .iter()
                .map(|finding| (
                    finding["location"]["path"].as_str().expect("path"),
                    finding["rule_id"].as_str().expect("rule id"),
                    finding["message"].as_str().expect("message"),
                ))
                .collect::<Vec<_>>(),
            vec![
                (
                    "alpha/SKILL.md",
                    "SKILL002",
                    "The skill manifest does not declare a description."
                ),
                (
                    "middle/SKILL.md",
                    "SKILL002",
                    "The skill manifest does not declare a description."
                ),
                (
                    "zeta/SKILL.md",
                    "SKILL002",
                    "The skill manifest does not declare a description."
                ),
            ]
        );
    }

    #[test]
    fn json_output_preserves_finding_metadata_and_summary_counts() {
        let workspace = TestWorkspace::new("scan-json-finding-metadata");
        workspace.write_file(
            "a-broken-reference/SKILL.md",
            r#"---
name: broken-reference
description: Broken reference fixture.
---

# Broken Reference

Read [missing](references/missing.md).
"#,
        );
        workspace.write_file(
            "b-missing-name/SKILL.md",
            r#"---
description: Missing name fixture.
---

This starts with a paragraph and has no heading fallback.
"#,
        );
        workspace.write_file(
            "c-missing-description/SKILL.md",
            r#"---
name: missing-description
---

# Missing Description
"#,
        );
        workspace.write_file(
            "d-oversized/SKILL.md",
            r#"---
name: oversized
description: Oversized fixture.
---

# Oversized

This content exceeds the deliberately tiny test threshold.
This extra line keeps only this manifest above the test size limit.
This second extra line makes the intended `SKILL020` case unambiguous.
"#,
        );

        let report = scan_path(
            workspace.root(),
            &ScanOptions {
                max_manifest_bytes: 180,
                ..ScanOptions::default()
            },
        )
        .expect("scan path");
        let (_json, value) = report_json_value(&report);

        assert_eq!(value["summary"]["package_count"], 4);
        assert_eq!(value["summary"]["finding_count"], 4);
        assert_eq!(value["summary"]["invalid_manifest_count"], 2);
        assert_eq!(value["summary"]["broken_reference_count"], 1);
        assert_eq!(
            json_string_array(&value["findings"], "rule_id"),
            vec!["SKILL010", "SKILL001", "SKILL002", "SKILL020"]
        );

        let findings = value["findings"].as_array().expect("findings array");
        for finding in findings {
            let object = finding.as_object().expect("finding object");
            for key in [
                "rule_id",
                "severity",
                "category",
                "title",
                "message",
                "location",
                "rationale",
                "remediation",
                "suppression",
            ] {
                assert!(object.contains_key(key), "missing finding key {key}");
            }
            assert_eq!(finding["severity"], "low");
            assert_eq!(finding["category"], "spec");
            assert!(!finding["title"].as_str().expect("title").is_empty());
            assert!(!finding["message"].as_str().expect("message").is_empty());
            assert!(!finding["rationale"].as_str().expect("rationale").is_empty());
            assert!(!finding["remediation"]
                .as_str()
                .expect("remediation")
                .is_empty());
            assert!(finding["suppression"]
                .as_str()
                .expect("suppression")
                .contains(finding["rule_id"].as_str().expect("rule id")));

            let location = finding["location"].as_object().expect("location object");
            assert!(location.contains_key("path"));
            assert!(location.contains_key("line"));
            assert!(finding["location"]["path"]
                .as_str()
                .expect("location path")
                .ends_with("SKILL.md"));
            assert!(finding["location"]["line"].is_number());
        }
        assert_eq!(
            findings
                .iter()
                .map(|finding| finding["location"]["line"].as_u64().expect("line"))
                .collect::<Vec<_>>(),
            vec![8, 1, 1, 1]
        );
    }

    #[test]
    fn json_output_uses_relative_reference_paths_without_local_paths() {
        let workspace = TestWorkspace::new("scan-json-relative-references");
        workspace.write_file(
            "skill/SKILL.md",
            r#"---
name: relative-references
description: Relative references fixture.
---

# Relative References

Read [guidance](references/guidance.md).
"#,
        );
        workspace.write_file("skill/references/guidance.md", "# Guidance\n");
        workspace.create_dir("skill/scripts");
        workspace.create_dir("skill/assets");

        let report = scan_path(workspace.root(), &ScanOptions::default()).expect("scan path");
        let (json, value) = report_json_value(&report);

        assert_eq!(value["summary"]["package_count"], 1);
        assert_eq!(value["summary"]["finding_count"], 0);
        assert_eq!(
            value["packages"][0]["graph"]["references"][0]["target"],
            "references/guidance.md"
        );
        assert_eq!(
            value["packages"][0]["graph"]["references"][0]["exists"],
            true
        );
        assert_eq!(value["packages"][0]["graph"]["references"][0]["line"], 8);
        assert_eq!(
            value["packages"][0]["graph"]["artifacts"]
                .as_array()
                .expect("artifacts array")
                .iter()
                .map(|artifact| artifact.as_str().expect("artifact"))
                .collect::<Vec<_>>(),
            vec!["scripts", "references", "assets"]
        );
        assert!(!json_contains_workspace_root(&json, workspace.root()));
    }

    #[test]
    fn json_output_workspace_root_detector_matches_escaped_windows_paths() {
        let root = Path::new(r"C:\ws\saas\agent_skill_auditor");

        assert!(json_contains_workspace_root(
            r"C:\ws\saas\agent_skill_auditor\skill\SKILL.md",
            root
        ));
        assert!(json_contains_workspace_root(
            "C:/ws/saas/agent_skill_auditor/skill/SKILL.md",
            root
        ));
        assert!(json_contains_workspace_root(
            r#"{"path":"C:\\ws\\saas\\agent_skill_auditor\\skill\\SKILL.md"}"#,
            root
        ));
    }

    struct ExpectedFinding {
        rule_id: &'static str,
        message: &'static str,
        path: &'static str,
        line: Option<usize>,
    }

    fn assert_duplicate_name_finding(
        finding: &SkillFinding,
        name: &str,
        path: &str,
        other_paths: &[&str],
    ) {
        let other_paths = other_paths
            .iter()
            .map(|other_path| format!("`{other_path}`"))
            .collect::<Vec<_>>()
            .join(", ");

        assert_eq!(finding.rule_id, "SKILL030");
        assert_eq!(finding.severity, Severity::Low);
        assert_eq!(finding.category, FindingCategory::Compatibility);
        let metadata = rule_metadata("SKILL030").expect("rule metadata exists");

        assert_eq!(finding.title, metadata.title);
        assert_eq!(
            finding.message,
            format!(
                "The skill name `{name}` is also declared by other manifest path(s): {other_paths}."
            )
        );
        assert_eq!(finding.location.path, path);
        assert_eq!(finding.location.line, Some(1));
        assert_eq!(finding.rationale, metadata.rationale);
        assert_eq!(finding.remediation, metadata.remediation);
        assert_eq!(finding.suppression, metadata.suppression_guidance);
    }

    fn assert_finding(finding: &SkillFinding, expected: ExpectedFinding) {
        let metadata = rule_metadata(expected.rule_id).expect("rule metadata exists");

        assert_eq!(finding.rule_id, expected.rule_id);
        assert_eq!(finding.severity, Severity::Low);
        assert_eq!(finding.category, FindingCategory::Spec);
        assert_eq!(finding.title, metadata.title);
        assert_eq!(finding.message, expected.message);
        assert_eq!(finding.location.path, expected.path);
        assert_eq!(finding.location.line, expected.line);
        assert_eq!(finding.rationale, metadata.rationale);
        assert_eq!(finding.remediation, metadata.remediation);
        assert_eq!(finding.suppression, metadata.suppression_guidance);
    }

    fn finding_sort_tuple(finding: &SkillFinding) -> (&str, Option<usize>, &str, &str) {
        (
            finding.location.path.as_str(),
            finding.location.line,
            finding.rule_id.as_str(),
            finding.message.as_str(),
        )
    }

    fn expected_severity(severity: RegistrySeverity) -> Severity {
        match severity {
            RegistrySeverity::Info => Severity::Info,
            RegistrySeverity::Low => Severity::Low,
            RegistrySeverity::Medium => Severity::Medium,
            RegistrySeverity::High => Severity::High,
            RegistrySeverity::Critical => Severity::Critical,
        }
    }

    fn expected_category(category: RegistryCategory) -> FindingCategory {
        match category {
            RegistryCategory::Spec => FindingCategory::Spec,
            RegistryCategory::Compatibility => FindingCategory::Compatibility,
            RegistryCategory::Security => FindingCategory::Security,
            RegistryCategory::Quality => FindingCategory::Quality,
            RegistryCategory::Portability => FindingCategory::Portability,
            RegistryCategory::Reproducibility => FindingCategory::Reproducibility,
        }
    }

    fn file_projection(files: &[SkillFile]) -> Vec<(&str, SkillArtifactKind, SkillFileKind, u64)> {
        files
            .iter()
            .map(|file| {
                (
                    file.path.as_str(),
                    file.artifact,
                    file.kind,
                    file.size_bytes,
                )
            })
            .collect()
    }

    fn compatibility_projection(
        profiles: &[ProfileCompatibilityResult],
    ) -> Vec<(&str, CompatibilityStatus, Vec<&str>)> {
        profiles
            .iter()
            .map(|profile| {
                (
                    profile.profile.as_str(),
                    profile.status,
                    profile
                        .finding_ids
                        .iter()
                        .map(String::as_str)
                        .collect::<Vec<_>>(),
                )
            })
            .collect()
    }

    fn string_vec(values: &[&str]) -> Vec<String> {
        values.iter().map(|value| (*value).to_owned()).collect()
    }

    fn security_package_install_skill() -> &'static str {
        r#"---
name: security-package-install
description: Security package install fixture.
---

# Security Package Install

Run scripts/install.sh during setup.
"#
    }

    fn report_json_value(report: &ScanReport) -> (String, serde_json::Value) {
        let json = serde_json::to_string_pretty(report).expect("serialize report");
        let value = serde_json::from_str(&json).expect("parse report JSON");
        (json, value)
    }

    fn json_string_array(value: &serde_json::Value, key: &str) -> Vec<String> {
        value
            .as_array()
            .expect("JSON array")
            .iter()
            .map(|item| item[key].as_str().expect("string field").to_owned())
            .collect()
    }

    fn suppressed_finding_projection(findings: &[SuppressedFinding]) -> Vec<(&str, &str)> {
        findings
            .iter()
            .map(|entry| {
                (
                    entry.finding.location.path.as_str(),
                    entry.finding.rule_id.as_str(),
                )
            })
            .collect()
    }

    fn json_contains_workspace_root(json: &str, root: &Path) -> bool {
        let raw_root = root.to_string_lossy().into_owned();
        let normalized_root = raw_root.replace('\\', "/");

        for candidate in [raw_root.as_str(), normalized_root.as_str()] {
            if !candidate.is_empty()
                && (json.contains(candidate) || json.contains(&json_escaped_fragment(candidate)))
            {
                return true;
            }
        }

        false
    }

    fn json_escaped_fragment(value: &str) -> String {
        let escaped = serde_json::to_string(value).expect("escape JSON string");
        escaped
            .strip_prefix('"')
            .and_then(|value| value.strip_suffix('"'))
            .unwrap_or(&escaped)
            .to_owned()
    }

    fn scan_security_fixture(relative_path: &str) -> ScanReport {
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .join("fixtures/security")
            .join(relative_path);
        scan_path(&path, &ScanOptions::default())
            .unwrap_or_else(|error| panic!("scan security fixture {relative_path}: {error}"))
    }

    fn assert_security_finding<'a>(
        report: &'a ScanReport,
        rule_id: &str,
        path: &str,
        line: Option<usize>,
    ) -> &'a SkillFinding {
        report
            .findings
            .iter()
            .find(|finding| {
                finding.rule_id == rule_id
                    && finding.category == FindingCategory::Security
                    && finding.location.path == path
                    && line.is_none_or(|expected| finding.location.line == Some(expected))
            })
            .unwrap_or_else(|| {
                panic!(
                    "missing {rule_id} finding in report: {:#?}",
                    report.findings
                )
            })
    }
}
