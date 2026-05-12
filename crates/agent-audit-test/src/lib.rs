// SPDX-License-Identifier: Apache-2.0

pub const FIXTURE_GROUPS: &[&str] = &[
    "spec",
    "compatibility",
    "security",
    "behavior",
    "supply-chain",
];

#[cfg(test)]
mod tests {
    use super::*;
    use agent_audit_core::model::ScanSummary;
    use agent_audit_core::{
        parse_audit_config, scan_path, FindingCategory, FindingLocation, ScanOptions, ScanReport,
        Severity, SkillFinding, SkillGraph, SkillManifest, SkillPackage,
    };
    use agent_audit_report::{
        render_html, render_json, render_report, render_sarif, render_summary, ReportFormat,
    };
    use std::collections::BTreeMap;
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicUsize, Ordering};

    const EMPTY_FINDING_IDS: &[&str] = &[];
    const DEFAULT_COMPATIBILITY_PROJECTION: &[(&str, &str, &[&str])] = &[
        ("agent-skills-spec", "pass", EMPTY_FINDING_IDS),
        ("claude-code", "warn", EMPTY_FINDING_IDS),
        ("codex", "warn", EMPTY_FINDING_IDS),
        ("github-copilot", "warn", EMPTY_FINDING_IDS),
        ("vscode-copilot", "warn", EMPTY_FINDING_IDS),
        ("generic", "pass", EMPTY_FINDING_IDS),
    ];
    const SUPPLY_CHAIN_FIXTURES: &[&str] = &[
        "binary-artifact",
        "downloaded-executable-no-checksum",
        "e2e-representative",
        "github-raw-pinned",
        "github-raw-unpinned",
        "license-missing",
        "license-present",
        "offline-partial",
        "offline-ready",
        "package-install-with-lockfile",
        "package-install-without-lockfile",
        "permission-conflict",
        "trust-manifest-invalid",
        "trust-manifest-valid",
        "unpinned-package-version",
    ];
    const SUPPLY_CHAIN_SECTION_KEYS: &[&str] = &[
        "binaries",
        "checksums",
        "executables",
        "external_urls",
        "licenses",
        "lockfiles",
        "offline_readiness",
        "package_managers",
        "permissions",
        "remote_dependencies",
        "trust_manifests",
    ];
    const IMPLEMENTED_SUPPLY_CHAIN_SECTION_KEYS: &[&str] = &[
        "binaries",
        "checksums",
        "executables",
        "external_urls",
        "licenses",
        "lockfiles",
        "package_managers",
        "permissions",
        "remote_dependencies",
        "trust_manifests",
    ];

    #[test]
    fn fixture_groups_match_planned_fixture_directories() {
        assert_eq!(
            FIXTURE_GROUPS,
            &[
                "spec",
                "compatibility",
                "security",
                "behavior",
                "supply-chain"
            ]
        );
    }

    #[test]
    fn github_action_metadata_runs_checked_in_cli_with_expected_inputs() {
        let action_path = workspace_root().join("action.yml");
        let content = fs::read_to_string(&action_path).expect("read action metadata");
        let metadata: serde_yaml::Value =
            serde_yaml::from_str(&content).expect("parse action metadata");

        assert_eq!(metadata["runs"]["using"], "composite");
        let inputs = metadata["inputs"].as_mapping().expect("inputs mapping");
        for input in [
            "path",
            "profiles",
            "fail-on",
            "format",
            "report",
            "output",
            "config",
            "strict-supply-chain",
        ] {
            assert!(
                inputs.contains_key(serde_yaml::Value::from(input)),
                "missing action input {input}"
            );
        }

        let steps = metadata["runs"]["steps"]
            .as_sequence()
            .expect("action steps");
        assert_eq!(steps.len(), 1);
        let step = &steps[0];
        assert_eq!(step["shell"], "bash");
        let run = step["run"].as_str().expect("run script");

        assert!(run.contains("$GITHUB_ACTION_PATH/Cargo.toml"));
        assert!(run.contains("-p agent-audit-cli"));
        assert!(run.contains("args=(scan"));
        assert!(run.contains("args+=(--profile \"$profile\")"));
        assert!(run.contains("args+=(--fail-on \"$severity\")"));
        assert!(run.contains("--strict-supply-chain"));
        assert!(!run.contains("curl"));
        assert!(!run.contains("wget"));
    }

    #[test]
    fn milestone5_supply_chain_fixture_corpus_has_expected_projections() {
        let root = supply_chain_root();
        let expected_root = root.join("expected");
        assert!(expected_root.is_dir(), "missing supply-chain expected dir");
        let report = scan_path(&root, &ScanOptions::default()).expect("scan supply-chain corpus");

        assert_eq!(fixture_directory_names(&root), SUPPLY_CHAIN_FIXTURES);

        let mut covered_sections = SUPPLY_CHAIN_SECTION_KEYS
            .iter()
            .map(|section| ((*section).to_owned(), 0usize))
            .collect::<BTreeMap<_, _>>();

        for fixture_name in SUPPLY_CHAIN_FIXTURES {
            let fixture_root = root.join(fixture_name);
            assert!(
                fixture_root.join("SKILL.md").is_file(),
                "{fixture_name} should include SKILL.md"
            );

            let expected_path = expected_root.join(format!("{fixture_name}.json"));
            assert!(
                expected_path.is_file(),
                "{fixture_name} should include an expected JSON projection"
            );

            let expected_json =
                fs::read_to_string(&expected_path).expect("read expected projection");
            assert_portable_fixture_text(&expected_json, &expected_path);
            let value: serde_json::Value =
                serde_json::from_str(&expected_json).expect("parse expected projection JSON");
            assert_eq!(value["fixture"], *fixture_name);
            assert!(value["expected_findings"].is_array());
            assert_eq!(
                supply_chain_projection_for_fixture(&report, fixture_name),
                value["supply_chain"],
                "{fixture_name} supply-chain projection"
            );
            assert_eq!(
                finding_projection_for_fixture(&report, fixture_name),
                value["expected_findings"],
                "{fixture_name} expected findings"
            );

            let supply_chain = value["supply_chain"]
                .as_object()
                .expect("expected supply_chain object");
            let mut keys = supply_chain.keys().cloned().collect::<Vec<_>>();
            keys.sort();
            assert_eq!(keys, SUPPLY_CHAIN_SECTION_KEYS, "{fixture_name} keys");

            for section_name in SUPPLY_CHAIN_SECTION_KEYS {
                let section = supply_chain[*section_name]
                    .as_array()
                    .unwrap_or_else(|| panic!("{fixture_name}.{section_name} should be an array"));
                if !section.is_empty() {
                    *covered_sections
                        .get_mut(*section_name)
                        .expect("covered section") += 1;
                }
            }
        }

        assert!(
            IMPLEMENTED_SUPPLY_CHAIN_SECTION_KEYS
                .iter()
                .all(|section| covered_sections[*section] > 0),
            "every implemented supply-chain section should be represented: {covered_sections:?}"
        );

        let invalid_projection = expected_supply_chain_projection("trust-manifest-invalid");
        assert_eq!(
            invalid_projection["supply_chain"]["trust_manifests"][0]["valid"],
            false
        );
        assert_eq!(
            invalid_projection["expected_findings"],
            serde_json::json!([
                {
                    "rule_id": "SUPPLY012",
                    "path": "trust-manifest-invalid/agent-audit.trust.yaml",
                    "message": "The trust manifest has a parse error: Invalid trust manifest YAML: did not find expected ',' or ']' at line 4 column 1, while parsing a flow sequence at line 3 column 14. Fix the YAML syntax or remove the manifest until it can be parsed."
                }
            ])
        );
        assert_eq!(
            invalid_projection["expected_trust_manifest_diagnostics"][0]["kind"],
            "parse-error"
        );

        let pinned_projection = expected_supply_chain_projection("github-raw-pinned");
        assert_eq!(
            pinned_projection["supply_chain"]["external_urls"][0]["pinned"],
            true
        );
        let unpinned_projection = expected_supply_chain_projection("github-raw-unpinned");
        assert_eq!(
            unpinned_projection["supply_chain"]["external_urls"][0]["pinned"],
            false
        );
    }

    #[test]
    fn milestone5_supply_chain_fixture_files_are_portable_and_deterministic() {
        for path in fixture_file_paths(&supply_chain_root()) {
            let text = fs::read_to_string(&path)
                .unwrap_or_else(|error| panic!("read fixture file {}: {error}", path.display()));
            assert_portable_fixture_text(&text, &path);
        }
    }

    #[test]
    fn milestone5_supply_chain_expected_source_locations_match_fixture_lines() {
        let root = supply_chain_root();

        for fixture_name in SUPPLY_CHAIN_FIXTURES {
            let projection = expected_supply_chain_projection(fixture_name);
            for section_name in SUPPLY_CHAIN_SECTION_KEYS {
                let section = projection["supply_chain"][*section_name]
                    .as_array()
                    .unwrap_or_else(|| panic!("{fixture_name}.{section_name} should be an array"));

                for entry in section {
                    let path = entry["path"]
                        .as_str()
                        .unwrap_or_else(|| panic!("{fixture_name}.{section_name} entry has path"));
                    let source_path = root.join(path);
                    assert!(
                        source_path.is_file(),
                        "{fixture_name}.{section_name} source path should exist: {path}"
                    );

                    let Some(line) = entry["line"].as_u64() else {
                        continue;
                    };
                    assert!(
                        line > 0,
                        "{fixture_name}.{section_name} line should be 1-based"
                    );

                    let source_text = fs::read_to_string(&source_path).unwrap_or_else(|error| {
                        panic!("read source fixture {}: {error}", source_path.display())
                    });
                    let source_line =
                        source_text
                            .lines()
                            .nth((line - 1) as usize)
                            .unwrap_or_else(|| {
                                panic!("{fixture_name}.{section_name} line {line} exists in {path}")
                            });

                    for fragment in expected_source_line_fragments(section_name, entry) {
                        assert!(
                            source_line.contains(&fragment),
                            "{fixture_name}.{section_name} {path}:{line} should contain evidence fragment {fragment:?}; line was {source_line:?}"
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn milestone5_e2e_representative_outputs_match_expected_baselines() {
        let fixture_root = supply_chain_root().join("e2e-representative");
        let first_report =
            scan_path(&fixture_root, &ScanOptions::default()).expect("scan e2e fixture");
        let second_report =
            scan_path(&fixture_root, &ScanOptions::default()).expect("rescan e2e fixture");

        let first_json = render_json(&first_report).expect("render e2e JSON");
        let second_json = render_json(&second_report).expect("rerender e2e JSON");
        let expected_json = expected_e2e_representative_json();

        assert_eq!(first_json.as_bytes(), second_json.as_bytes());
        assert_eq!(first_json, expected_json);
        assert_eq!(first_report.summary.package_count, 1);
        assert_eq!(first_report.summary.finding_count, 0);
        assert!(!json_contains_path(&first_json, &workspace_root()));
        assert!(!first_json.contains("timestamp"));
        assert!(!first_json.contains("generated_at"));

        let value: serde_json::Value = serde_json::from_str(&first_json).expect("parse e2e JSON");
        let supply_chain = &value["supply_chain"];
        assert_eq!(supply_chain["trust_manifests"].as_array().unwrap().len(), 1);
        assert_eq!(supply_chain["lockfiles"].as_array().unwrap().len(), 1);
        assert_eq!(supply_chain["external_urls"].as_array().unwrap().len(), 2);
        assert_eq!(supply_chain["executables"].as_array().unwrap().len(), 2);
        assert_eq!(
            supply_chain["remote_dependencies"]
                .as_array()
                .unwrap()
                .len(),
            2
        );
        assert_eq!(
            value["packages"][0]["graph"]["files"][0]["path"],
            "assets/badge.txt"
        );

        let summary = render_summary(&first_report);
        assert_eq!(summary, expected_e2e_representative_summary());
        assert!(summary.contains("Supply chain:\n"));
        assert!(summary.contains("External URLs: 2 total, 0 mutable"));
        assert!(summary.contains("Dependencies: 2 observed, 0 unpinned"));
        assert!(summary.contains("No findings."));
    }

    #[test]
    fn representative_corpus_scan_matches_recorded_phase1_run() {
        let corpus_root = representative_corpus_root();
        let report =
            scan_path(&corpus_root, &ScanOptions::default()).expect("scan representative corpus");

        assert!((20..=50).contains(&report.summary.package_count));
        assert_eq!(report.summary.package_count, 30);
        assert_eq!(report.summary.finding_count, 16);
        assert_eq!(report.summary.suppressed_finding_count, 0);
        assert_eq!(report.summary.invalid_manifest_count, 5);
        assert_eq!(report.summary.broken_reference_count, 4);

        assert_eq!(
            package_paths(&report),
            vec![
                ".agents/skills/artifacts/SKILL.md",
                ".agents/skills/broken-reference/SKILL.md",
                ".agents/skills/missing-description/SKILL.md",
                ".agents/skills/triage/SKILL.md",
                ".claude/skills/duplicate-a/SKILL.md",
                ".claude/skills/duplicate-b/SKILL.md",
                ".claude/skills/planning/SKILL.md",
                ".claude/skills/unknown-frontmatter/SKILL.md",
                ".github/skills/assets/SKILL.md",
                ".github/skills/broken-reference/SKILL.md",
                ".github/skills/missing-name/SKILL.md",
                ".github/skills/release-notes/SKILL.md",
                "deep/products/alpha/.agents/skills/nested-agent/SKILL.md",
                "deep/products/beta/SKILL.md",
                "generic/artifact-complete/SKILL.md",
                "generic/assets-only/SKILL.md",
                "generic/broken-reference/SKILL.md",
                "generic/duplicate-a/SKILL.md",
                "generic/duplicate-b/SKILL.md",
                "generic/missing-description/SKILL.md",
                "generic/missing-name/SKILL.md",
                "generic/references-only/SKILL.md",
                "generic/scripts-only/SKILL.md",
                "generic/unknown-field/SKILL.md",
                "generic/valid-basic/SKILL.md",
                "generic/valid-tools/SKILL.md",
                "nested/team/platform/review/SKILL.md",
                "nested/team/portability/missing-name/SKILL.md",
                "nested/team/quality/docs/SKILL.md",
                "nested/team/security/checks/SKILL.md",
            ]
        );

        assert_eq!(
            rule_counts(&report),
            BTreeMap::from([
                ("SKILL001".to_owned(), 3),
                ("SKILL002".to_owned(), 2),
                ("SKILL010".to_owned(), 4),
                ("SKILL030".to_owned(), 4),
                ("SKILL040".to_owned(), 3),
            ])
        );
        assert_eq!(
            category_counts(&report),
            BTreeMap::from([
                (FindingCategory::Spec, 9),
                (FindingCategory::Compatibility, 7),
            ])
        );

        let finding_keys = finding_order_keys(&report);
        let mut sorted_finding_keys = finding_keys.clone();
        sorted_finding_keys.sort();
        assert_eq!(finding_keys, sorted_finding_keys);

        let json = render_json(&report).expect("render JSON");
        let reparsed: serde_json::Value = serde_json::from_str(&json).expect("parse JSON");
        assert_eq!(reparsed["summary"]["package_count"], 30);
        assert!(!json_contains_path(&json, &workspace_root()));
        assert!(!json.contains("timestamp"));
        assert!(!json.contains("generated_at"));

        let summary = render_summary(&report);
        assert!(summary.contains("Packages: 30"));
        assert!(summary.contains("Findings: 16"));
        assert!(summary.contains("Suppressed findings: 0"));
        assert!(summary.contains("SKILL010 [low/spec]"));

        let sarif = render_sarif(&report).expect("render SARIF");
        let sarif_value: serde_json::Value = serde_json::from_str(&sarif).expect("parse SARIF");
        assert_eq!(sarif_value["version"], "2.1.0");
        assert_eq!(
            sarif_value["runs"][0]["results"].as_array().unwrap().len(),
            16
        );
        assert!(!json_contains_path(&sarif, &workspace_root()));

        let html = render_html(&report);
        assert!(html.contains("<h2 id=\"summary\">Executive Summary</h2>"));
        assert!(html.contains("<span class=\"count\">30</span>Packages"));
        assert!(html.contains("<span class=\"count\">16</span>Findings"));
        assert!(html.contains("<span class=\"count\">0</span>Suppressed findings"));
        assert!(html.contains("generic/broken-reference/SKILL.md:8"));

        for format in [
            ReportFormat::Summary,
            ReportFormat::Json,
            ReportFormat::Sarif,
            ReportFormat::Html,
        ] {
            let output = render_report(&report, format).expect("render report format");
            assert!(output.ends_with('\n'));
        }
    }

    #[test]
    fn representative_corpus_full_json_matches_phase2_expected_output() {
        let corpus_root = representative_corpus_root();
        let first_report =
            scan_path(&corpus_root, &ScanOptions::default()).expect("scan representative corpus");
        let second_report =
            scan_path(&corpus_root, &ScanOptions::default()).expect("rescan representative corpus");

        let first_json = render_json(&first_report).expect("render JSON");
        let second_json = render_json(&second_report).expect("rerender JSON");
        let expected_json = expected_representative_corpus_json();

        assert_eq!(first_json.as_bytes(), second_json.as_bytes());
        assert_eq!(first_json, expected_json);
        assert!(!first_json.contains("timestamp"));
        assert!(!first_json.contains("generated_at"));
        assert!(!json_contains_path(&first_json, &workspace_root()));

        let value: serde_json::Value =
            serde_json::from_str(&first_json).expect("parse rendered JSON");
        assert_eq!(value["summary"]["package_count"], 30);
        assert_eq!(value["summary"]["finding_count"], 16);
        assert_eq!(value["summary"]["suppressed_finding_count"], 0);

        let finding_keys = json_finding_order_keys(&value);
        let mut sorted_finding_keys = finding_keys.clone();
        sorted_finding_keys.sort();
        assert_eq!(finding_keys, sorted_finding_keys);
    }

    #[test]
    fn phase2_suppression_mixed_order_fixture_matches_expected_json_snapshot() {
        let fixture_root = phase2_root().join("suppressions/mixed-order");
        let config = parse_audit_config(
            &fs::read_to_string(fixture_root.join("agent-audit.yaml")).expect("read config"),
        )
        .expect("parse config");
        let options = ScanOptions {
            config: Some(config),
            ..ScanOptions::default()
        };

        let first_report = scan_path(&fixture_root, &options).expect("scan suppression fixture");
        let second_report = scan_path(&fixture_root, &options).expect("rescan suppression fixture");
        let first_projection = suppression_snapshot_projection(&first_report);
        let second_projection = suppression_snapshot_projection(&second_report);
        let expected: serde_json::Value = serde_json::from_str(include_str!(
            "../../../fixtures/spec/phase2/expected/suppression-mixed-order.json"
        ))
        .expect("parse expected suppression snapshot");

        assert_eq!(first_projection, second_projection);
        assert_eq!(first_projection, expected);

        let rendered = render_json(&first_report).expect("render JSON");
        assert!(!json_contains_path(&rendered, &workspace_root()));
        assert!(!rendered.contains("timestamp"));
        assert!(!rendered.contains("generated_at"));
    }

    #[test]
    fn phase2_rule_doc_example_fixtures_emit_documented_rules() {
        for rule_id in [
            "SKILL001", "SKILL002", "SKILL010", "SKILL020", "SKILL030", "SKILL040", "SKILL041",
        ] {
            let non_compliant = phase2_root()
                .join("rule-doc-examples")
                .join(rule_id)
                .join("non-compliant");
            let options = rule_doc_example_scan_options(rule_id);
            let report = scan_path(&non_compliant, &options).expect("scan non-compliant");
            let expected_findings = rule_doc_non_compliant_finding_count(rule_id);

            assert_eq!(
                report
                    .findings
                    .iter()
                    .map(|finding| finding.rule_id.as_str())
                    .collect::<Vec<_>>(),
                vec![rule_id; expected_findings],
                "{rule_id} non-compliant fixture should emit only that rule"
            );
            assert_eq!(
                report.summary.finding_count, expected_findings,
                "{rule_id} finding count"
            );
            assert_eq!(
                report.summary.suppressed_finding_count, 0,
                "{rule_id} suppressed count"
            );
        }
    }

    #[test]
    fn phase2_rule_doc_compliant_fixtures_scan_cleanly() {
        for rule_id in [
            "SKILL001", "SKILL002", "SKILL010", "SKILL020", "SKILL030", "SKILL040", "SKILL041",
        ] {
            let compliant = phase2_root()
                .join("rule-doc-examples")
                .join(rule_id)
                .join("compliant");
            let report = scan_path(&compliant, &ScanOptions::default()).expect("scan compliant");

            assert_eq!(
                report.summary.package_count,
                rule_doc_compliant_package_count(rule_id),
                "{rule_id} package count"
            );
            assert!(
                report.findings.is_empty(),
                "{rule_id} compliant fixture should not emit findings: {:?}",
                report.findings
            );
        }
    }

    #[test]
    fn phase3_compatibility_fixtures_exercise_profile_outcomes() {
        let spec_basic = scan_compatibility_fixture("valid/spec-basic", ScanOptions::default());
        assert_eq!(spec_basic.summary.finding_count, 0);
        assert_compatibility_profile_projection(
            &spec_basic,
            "SKILL.md",
            DEFAULT_COMPATIBILITY_PROJECTION,
        );

        let missing_description =
            scan_compatibility_fixture("invalid/missing-description", ScanOptions::default());
        assert_eq!(rule_ids(&missing_description), vec!["SKILL002"]);
        assert!(
            compatibility_projection_for_path(&missing_description, "SKILL.md")
                .iter()
                .all(|(_, status, finding_ids)| {
                    status == "fail" && finding_ids == &vec!["SKILL002".to_owned()]
                })
        );

        let claude_extra =
            scan_compatibility_fixture("host/claude-extra-field", ScanOptions::default());
        assert_eq!(rule_ids(&claude_extra), vec!["SKILL050"]);
        assert_compatibility_profile_projection(
            &claude_extra,
            ".claude/skills/claude-extra-field/SKILL.md",
            &[
                ("agent-skills-spec", "pass", &[]),
                ("claude-code", "warn", &["SKILL050"]),
                ("codex", "warn", &[]),
                ("github-copilot", "warn", &[]),
                ("vscode-copilot", "warn", &[]),
                ("generic", "pass", &[]),
            ],
        );

        let copilot_path =
            scan_compatibility_fixture("host/copilot-path-layout", ScanOptions::default());
        assert_eq!(copilot_path.summary.finding_count, 0);
        assert_compatibility_profile_projection(
            &copilot_path,
            "SKILL.md",
            DEFAULT_COMPATIBILITY_PROJECTION,
        );

        let codex_script =
            scan_compatibility_fixture("host/codex-script-reference", ScanOptions::default());
        assert_eq!(codex_script.summary.finding_count, 0);
        assert_compatibility_profile_projection(
            &codex_script,
            ".agents/skills/codex-script-reference/SKILL.md",
            DEFAULT_COMPATIBILITY_PROJECTION,
        );

        let vscode_ignored =
            scan_compatibility_fixture("host/vscode-ignored-metadata", ScanOptions::default());
        assert_eq!(rule_ids(&vscode_ignored), vec!["SKILL050", "SKILL050"]);
        assert_compatibility_profile_projection(
            &vscode_ignored,
            ".github/skills/vscode-ignored-metadata/SKILL.md",
            &[
                ("agent-skills-spec", "pass", &[]),
                ("claude-code", "warn", &[]),
                ("codex", "warn", &[]),
                ("github-copilot", "warn", &["SKILL050"]),
                ("vscode-copilot", "warn", &["SKILL050"]),
                ("generic", "pass", &[]),
            ],
        );

        let permissions =
            scan_compatibility_fixture("host/unsupported-permissions", ScanOptions::default());
        assert_eq!(permissions.summary.finding_count, 0);
        assert_compatibility_profile_projection(
            &permissions,
            ".github/skills/unsupported-permissions/SKILL.md",
            DEFAULT_COMPATIBILITY_PROJECTION,
        );

        let generic_unknown =
            scan_compatibility_fixture("host/generic-unknown-behavior", ScanOptions::default());
        assert_eq!(rule_ids(&generic_unknown), vec!["SKILL040"]);
        let generic_row = compatibility_projection_for_path(&generic_unknown, "SKILL.md");
        assert!(generic_row.iter().all(|(_, status, _)| status == "warn"));
        assert_eq!(
            generic_row
                .iter()
                .find(|(profile, _, _)| profile == "generic")
                .expect("generic profile")
                .2,
            vec!["SKILL040".to_owned()]
        );

        let mixed_root = compatibility_root().join("host/mixed-profile-metadata");
        let mixed_config = parse_audit_config(
            &fs::read_to_string(mixed_root.join("agent-audit.yaml")).expect("read config"),
        )
        .expect("parse mixed profile config");
        let mixed = scan_path(
            &mixed_root,
            &ScanOptions {
                config: Some(mixed_config),
                ..ScanOptions::default()
            },
        )
        .expect("scan mixed profile compatibility fixture");
        assert_eq!(
            mixed.compatibility.profiles,
            vec!["agent-skills-spec", "codex"]
        );
        assert_eq!(rule_ids(&mixed), vec!["SKILL050", "SKILL040"]);
        assert_compatibility_profile_projection(
            &mixed,
            ".agents/skills/mixed-profile-metadata/SKILL.md",
            &[
                ("agent-skills-spec", "warn", &["SKILL040"]),
                ("codex", "warn", &["SKILL050"]),
            ],
        );
    }

    #[test]
    fn phase3_compatibility_matrix_fixture_matches_full_json_snapshot() {
        let first_report = scan_compatibility_fixture("matrix", ScanOptions::default());
        let second_report = scan_compatibility_fixture("matrix", ScanOptions::default());

        let first_json = render_json(&first_report).expect("render compatibility matrix JSON");
        let second_json = render_json(&second_report).expect("rerender compatibility matrix JSON");
        let expected_json = expected_compatibility_matrix_json();

        assert_eq!(first_json.as_bytes(), second_json.as_bytes());
        assert_eq!(first_json, expected_json);
        assert!(!first_json.contains("timestamp"));
        assert!(!first_json.contains("generated_at"));
        assert!(!json_contains_path(&first_json, &workspace_root()));

        let value: serde_json::Value =
            serde_json::from_str(&first_json).expect("parse compatibility matrix JSON");
        assert_eq!(value["summary"]["package_count"], 6);
        assert_eq!(value["summary"]["finding_count"], 2);
        assert_eq!(
            value["compatibility"]["matrix"].as_array().unwrap().len(),
            6
        );
    }

    #[test]
    fn phase4_security_corpus_matches_full_json_snapshot() {
        let first_report = scan_security_corpus(ScanOptions::default());
        let second_report = scan_security_corpus(ScanOptions::default());

        let first_json = render_json(&first_report).expect("render security corpus JSON");
        let second_json = render_json(&second_report).expect("rerender security corpus JSON");
        let expected_json = expected_security_corpus_json();

        assert_eq!(first_json.as_bytes(), second_json.as_bytes());
        assert_eq!(first_json, expected_json);
        assert!(!first_json.contains("timestamp"));
        assert!(!first_json.contains("generated_at"));
        assert!(!json_contains_path(&first_json, &workspace_root()));

        let value: serde_json::Value =
            serde_json::from_str(&first_json).expect("parse security corpus JSON");
        assert_eq!(value["summary"]["package_count"], 16);
        assert_eq!(value["summary"]["finding_count"], 38);
        assert_eq!(value["summary"]["suppressed_finding_count"], 0);

        let finding_keys = json_finding_order_keys(&value);
        let mut sorted_finding_keys = finding_keys.clone();
        sorted_finding_keys.sort();
        assert_eq!(finding_keys, sorted_finding_keys);

        let finding_paths = value["findings"]
            .as_array()
            .expect("findings array")
            .iter()
            .map(|finding| finding["location"]["path"].as_str().expect("finding path"))
            .collect::<Vec<_>>();
        assert!(!finding_paths
            .iter()
            .any(|path| path.starts_with("benign-local-script/")));
        assert!(!finding_paths
            .iter()
            .any(|path| path.starts_with("read-only-python/")));
        assert!(finding_paths
            .iter()
            .any(|path| path == &"multi-language/scripts/client.js"));
        assert!(finding_paths
            .iter()
            .any(|path| path == &"multi-language/scripts/send.py"));
        assert!(finding_paths
            .iter()
            .any(|path| path == &"multi-language/scripts/write.ts"));
    }

    #[test]
    fn phase4_security_suppression_fixture_matches_full_json_snapshot() {
        let fixture_root = security_root().join("suppressed-package-install");
        let config = parse_audit_config(
            &fs::read_to_string(fixture_root.join("agent-audit.yaml")).expect("read config"),
        )
        .expect("parse security suppression config");
        let options = ScanOptions {
            config: Some(config),
            ..ScanOptions::default()
        };

        let first_report = scan_path(&fixture_root, &options).expect("scan suppression fixture");
        let second_report = scan_path(&fixture_root, &options).expect("rescan suppression fixture");
        let first_json = render_json(&first_report).expect("render security suppression JSON");
        let second_json = render_json(&second_report).expect("rerender security suppression JSON");
        let expected_json = expected_security_suppression_json();

        assert_eq!(first_json.as_bytes(), second_json.as_bytes());
        assert_eq!(first_json, expected_json);
        assert!(!first_json.contains("timestamp"));
        assert!(!first_json.contains("generated_at"));
        assert!(!json_contains_path(&first_json, &workspace_root()));

        let value: serde_json::Value =
            serde_json::from_str(&first_json).expect("parse security suppression JSON");
        assert_eq!(value["summary"]["finding_count"], 2);
        assert_eq!(value["summary"]["suppressed_finding_count"], 1);
        assert_eq!(
            value["suppressed_findings"][0]["finding"]["rule_id"],
            "SEC009"
        );
        assert_eq!(
            value["findings"]
                .as_array()
                .expect("findings array")
                .iter()
                .map(|finding| finding["rule_id"].as_str().expect("finding rule"))
                .collect::<Vec<_>>(),
            vec!["SUPPLY003", "SUPPLY004"]
        );
        assert_eq!(
            value["suppressed_findings"][0]["suppression"]["reason"],
            "Package install command is pinned by an external reviewed process for this fixture."
        );
    }

    #[test]
    fn json_report_schema_documents_report_contract_sections() {
        let schema = report_schema();

        assert_eq!(
            schema["$schema"],
            "https://json-schema.org/draft/2020-12/schema"
        );
        assert!(!string_array(&schema["required"]).contains(&"supply_chain".to_owned()));
        assert_eq!(
            schema["properties"]["supply_chain"]["$ref"],
            "#/$defs/supplyChainInventory"
        );
        assert!(!string_array(&schema["required"]).contains(&"compatibility".to_owned()));
        assert_eq!(
            schema["properties"]["compatibility"]["$ref"],
            "#/$defs/compatibilityMatrix"
        );

        let supply_chain_schema = &schema["$defs"]["supplyChainInventory"];
        assert_eq!(
            string_array(&supply_chain_schema["required"]),
            vec![
                "licenses",
                "trust_manifests",
                "external_urls",
                "remote_dependencies",
                "package_managers",
                "lockfiles",
                "executables",
                "binaries",
                "checksums",
                "permissions",
                "offline_readiness"
            ]
        );
        assert_eq!(
            supply_chain_schema["properties"]["licenses"]["items"]["$ref"],
            "#/$defs/licenseEvidence"
        );
        assert_eq!(
            supply_chain_schema["properties"]["offline_readiness"]["items"]["$ref"],
            "#/$defs/offlineReadiness"
        );
        assert_eq!(
            string_array(&schema["$defs"]["supplyChainSourceKind"]["enum"]),
            vec![
                "frontmatter",
                "markdown-link",
                "inline-code",
                "code-block",
                "script",
                "package-manifest",
                "lockfile",
                "trust-manifest",
                "filesystem",
                "inferred"
            ]
        );

        let compatibility_schema = &schema["$defs"]["compatibilityMatrix"];
        assert_eq!(
            string_array(&compatibility_schema["required"]),
            vec!["profiles", "matrix"]
        );
        assert_eq!(
            compatibility_schema["properties"]["matrix"]["items"]["$ref"],
            "#/$defs/skillCompatibilityRow"
        );

        let row_schema = &schema["$defs"]["skillCompatibilityRow"];
        assert_eq!(
            string_array(&row_schema["required"]),
            vec!["path", "name", "profiles"]
        );
        assert_eq!(
            string_array(&row_schema["properties"]["name"]["type"]),
            vec!["string", "null"]
        );

        let profile_schema = &schema["$defs"]["profileCompatibilityResult"];
        assert_eq!(
            string_array(&profile_schema["required"]),
            vec!["profile", "status", "finding_ids"]
        );
        assert_eq!(
            string_array(&schema["$defs"]["compatibilityStatus"]["enum"]),
            vec!["pass", "warn", "fail", "unknown"]
        );

        let report = scan_compatibility_fixture("matrix", ScanOptions::default());
        let json = render_json(&report).expect("render compatibility report JSON");
        let value: serde_json::Value =
            serde_json::from_str(&json).expect("parse compatibility report JSON");
        assert_json_report_matches_schema_contract(&value);

        let reparsed: ScanReport =
            serde_json::from_value(value.clone()).expect("deserialize compatibility report");
        assert_eq!(
            render_json(&reparsed).expect("rerender compatibility report"),
            json
        );

        let legacy_report: ScanReport = serde_json::from_value(serde_json::json!({
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
        }))
        .expect("deserialize legacy report without compatibility");
        assert!(legacy_report.compatibility.is_empty());
        assert!(legacy_report.supply_chain.licenses.is_empty());
    }

    #[test]
    fn milestone6_html_report_sections_render_in_delivery_order() {
        let workspace = TestWorkspace::new("milestone6-sections");
        write_milestone6_html_workspace(&workspace);

        let report = scan_path(workspace.root(), &ScanOptions::default())
            .expect("scan milestone 6 HTML workspace");
        let html = render_html(&report);

        assert_in_order(
            &html,
            &[
                "<h2 id=\"summary\">Executive Summary</h2>",
                "<h2 id=\"risk-distribution\">Risk Distribution</h2>",
                "<h2 id=\"compatibility\">Compatibility / Host Support</h2>",
                "<h2 id=\"top-risky-skills\">Top Risky Skills</h2>",
                "<h2 id=\"broken-references\">Broken References</h2>",
                "<h2 id=\"external-urls\">External URLs</h2>",
                "<h2 id=\"secret-usage\">Secret Usage</h2>",
                "<h2 id=\"offline-readiness\">Offline Readiness</h2>",
                "<h2 id=\"packages\">Packages</h2>",
                "<h2 id=\"findings\">Findings</h2>",
                "<h2 id=\"skill-details\">Skill Details</h2>",
            ],
        );
        assert!(html.contains("clean-package"));
        assert!(html.contains("risky-package"));
        assert!(html.contains("https://docs.example/milestone6?source=skill&amp;mode=html"));
    }

    #[test]
    fn milestone6_html_scan_and_render_are_byte_deterministic_and_portable() {
        let workspace = TestWorkspace::new("milestone6-deterministic-html");
        write_milestone6_html_workspace(&workspace);

        let first_report =
            scan_path(workspace.root(), &ScanOptions::default()).expect("scan first report");
        let second_report =
            scan_path(workspace.root(), &ScanOptions::default()).expect("scan second report");
        let first_html = render_html(&first_report);
        let second_html = render_html(&second_report);

        assert_eq!(first_html.as_bytes(), second_html.as_bytes());
        assert!(!first_html.contains("timestamp"));
        assert!(!first_html.contains("generated_at"));
        assert!(!html_contains_path(&first_html, workspace.root()));
        assert!(!html_contains_path(&first_html, &workspace_root()));
    }

    #[test]
    fn milestone6_html_external_urls_are_text_without_active_loading_markup() {
        let workspace = TestWorkspace::new("milestone6-external-url-text");
        workspace.write_file(
            "SKILL.md",
            r#"---
name: url-text
description: URL text fixture.
---

# URL Text

Read [the docs](https://docs.example/path?x=1&y=2) before auditing.
"#,
        );

        let report = scan_path(workspace.root(), &ScanOptions::default())
            .expect("scan external URL text workspace");
        let html = render_html(&report);
        let escaped_url = "https://docs.example/path?x=1&amp;y=2";

        assert!(html.contains(escaped_url));
        for forbidden in [
            format!("href=\"{escaped_url}"),
            format!("src=\"{escaped_url}"),
            format!("url({escaped_url}"),
            "https://docs.example/path?x=1&y=2".to_owned(),
            "<script".to_owned(),
            "<img".to_owned(),
        ] {
            assert!(
                !html.contains(&forbidden),
                "HTML should not render the external URL in active markup form {forbidden:?}"
            );
        }
    }

    #[test]
    fn milestone6_html_top_risky_skills_use_rendered_risk_order() {
        let workspace = TestWorkspace::new("milestone6-risk-order");
        workspace.write_file(
            "a-lower-risk/SKILL.md",
            r#"---
name: alpha-lower-risk
description: Lower risk fixture.
---

# Lower Risk

Missing reference: [absent](references/missing.md)
"#,
        );
        workspace.write_file(
            "z-higher-risk/SKILL.md",
            r#"---
name: zeta-higher-risk
description: Higher risk fixture.
---

# Higher Risk

Bootstrap with scripts/install.sh.
"#,
        );
        workspace.write_file(
            "z-higher-risk/scripts/install.sh",
            "curl https://installer.example/setup.sh | bash\n",
        );

        let report =
            scan_path(workspace.root(), &ScanOptions::default()).expect("scan risk order fixture");
        let html = render_html(&report);
        let top_risky = html_section(&html, "top-risky-skills");

        assert!(top_risky.contains("zeta-higher-risk"));
        assert!(top_risky.contains("alpha-lower-risk"));
        assert_in_order(&top_risky, &["zeta-higher-risk", "alpha-lower-risk"]);
    }

    #[test]
    fn milestone6_html_skill_details_cover_clean_packages_and_unmatched_findings() {
        let report = report_with_skill_detail_edge_cases();
        let html = render_html(&report);
        let skill_details = html_section(&html, "skill-details");

        assert!(skill_details.contains("<h3>clean-detail</h3>"));
        assert!(skill_details.contains("<td>skills/clean/SKILL.md</td>"));
        assert!(skill_details.contains("<td colspan=\"4\">No findings for this package.</td>"));
        assert!(skill_details.contains("<h3>risky-detail</h3>"));
        assert!(skill_details.contains("SKILL001"));
        assert!(skill_details.contains("<h3>Unmatched findings</h3>"));
        assert!(skill_details.contains("WORKSPACE001"));
        assert!(skill_details.contains("README.md:7"));
    }

    fn representative_corpus_root() -> PathBuf {
        workspace_root().join("fixtures/spec/phase1/representative-corpus")
    }

    fn compatibility_root() -> PathBuf {
        workspace_root().join("fixtures/compatibility")
    }

    fn phase2_root() -> PathBuf {
        workspace_root().join("fixtures/spec/phase2")
    }

    fn security_root() -> PathBuf {
        workspace_root().join("fixtures/security")
    }

    fn supply_chain_root() -> PathBuf {
        workspace_root().join("fixtures/supply-chain")
    }

    fn expected_supply_chain_projection(name: &str) -> serde_json::Value {
        let path = supply_chain_root()
            .join("expected")
            .join(format!("{name}.json"));
        serde_json::from_str(
            &fs::read_to_string(&path)
                .unwrap_or_else(|error| panic!("read expected projection {name}: {error}")),
        )
        .unwrap_or_else(|error| panic!("parse expected projection {name}: {error}"))
    }

    fn expected_e2e_representative_json() -> &'static str {
        let expected = include_str!(
            "../../../fixtures/supply-chain/expected/e2e-representative-full-report.json"
        );
        expected.strip_suffix('\n').unwrap_or(expected)
    }

    fn expected_e2e_representative_summary() -> &'static str {
        let expected =
            include_str!("../../../fixtures/supply-chain/expected/e2e-representative-summary.txt");
        expected.strip_suffix('\n').unwrap_or(expected)
    }

    fn scan_security_corpus(options: ScanOptions) -> ScanReport {
        scan_path(&security_root(), &options).expect("scan security corpus")
    }

    fn scan_compatibility_fixture(relative_path: &str, options: ScanOptions) -> ScanReport {
        scan_path(&compatibility_root().join(relative_path), &options)
            .unwrap_or_else(|error| panic!("scan compatibility fixture {relative_path}: {error}"))
    }

    fn rule_doc_example_scan_options(rule_id: &str) -> ScanOptions {
        match rule_id {
            "SKILL020" => ScanOptions {
                max_manifest_bytes: 180,
                ..ScanOptions::default()
            },
            _ => ScanOptions::default(),
        }
    }

    fn rule_doc_non_compliant_finding_count(rule_id: &str) -> usize {
        match rule_id {
            "SKILL030" => 2,
            _ => 1,
        }
    }

    fn rule_doc_compliant_package_count(rule_id: &str) -> usize {
        match rule_id {
            "SKILL030" => 2,
            _ => 1,
        }
    }

    fn expected_representative_corpus_json() -> &'static str {
        let expected =
            include_str!("../../../fixtures/spec/phase2/expected/representative-corpus.json");
        expected.strip_suffix('\n').unwrap_or(expected)
    }

    fn expected_compatibility_matrix_json() -> &'static str {
        let expected =
            include_str!("../../../fixtures/compatibility/expected/matrix-full-report.json");
        expected.strip_suffix('\n').unwrap_or(expected)
    }

    fn expected_security_corpus_json() -> &'static str {
        let expected = include_str!("../../../fixtures/security/expected/corpus-full-report.json");
        expected.strip_suffix('\n').unwrap_or(expected)
    }

    fn expected_security_suppression_json() -> &'static str {
        let expected =
            include_str!("../../../fixtures/security/expected/suppressed-package-install.json");
        expected.strip_suffix('\n').unwrap_or(expected)
    }

    fn report_schema() -> serde_json::Value {
        serde_json::from_str(include_str!("../../../docs/report.schema.json"))
            .expect("parse JSON report schema")
    }

    fn assert_json_report_matches_schema_contract(value: &serde_json::Value) {
        assert!(value["packages"].is_array());
        assert!(value["findings"].is_array());
        assert!(value["suppressed_findings"].is_array());
        assert!(value["summary"].is_object());

        let supply_chain = value["supply_chain"]
            .as_object()
            .expect("supply chain object");
        assert_eq!(
            supply_chain.keys().cloned().collect::<Vec<_>>(),
            vec![
                "binaries".to_owned(),
                "checksums".to_owned(),
                "executables".to_owned(),
                "external_urls".to_owned(),
                "licenses".to_owned(),
                "lockfiles".to_owned(),
                "offline_readiness".to_owned(),
                "package_managers".to_owned(),
                "permissions".to_owned(),
                "remote_dependencies".to_owned(),
                "trust_manifests".to_owned()
            ]
        );
        for section in supply_chain.values() {
            assert!(section.is_array());
        }

        let compatibility = value["compatibility"]
            .as_object()
            .expect("compatibility object");
        assert_eq!(
            compatibility.keys().cloned().collect::<Vec<_>>(),
            vec!["matrix".to_owned(), "profiles".to_owned()]
        );
        assert!(compatibility["profiles"]
            .as_array()
            .expect("compatibility profiles")
            .iter()
            .all(serde_json::Value::is_string));

        let allowed_statuses = ["pass", "warn", "fail", "unknown"];
        for row in compatibility["matrix"]
            .as_array()
            .expect("compatibility matrix")
        {
            let row = row.as_object().expect("compatibility row object");
            assert_eq!(
                row.keys().cloned().collect::<Vec<_>>(),
                vec!["name".to_owned(), "path".to_owned(), "profiles".to_owned()]
            );
            assert!(row["path"].is_string());
            assert!(row["name"].is_string() || row["name"].is_null());

            for profile in row["profiles"]
                .as_array()
                .expect("row compatibility profiles")
            {
                let profile = profile.as_object().expect("profile result object");
                assert_eq!(
                    profile.keys().cloned().collect::<Vec<_>>(),
                    vec![
                        "finding_ids".to_owned(),
                        "profile".to_owned(),
                        "status".to_owned()
                    ]
                );
                assert!(profile["profile"].is_string());
                assert!(allowed_statuses.contains(
                    &profile["status"]
                        .as_str()
                        .expect("compatibility status string")
                ));
                assert!(profile["finding_ids"]
                    .as_array()
                    .expect("finding IDs")
                    .iter()
                    .all(serde_json::Value::is_string));
            }
        }
    }

    fn string_array(value: &serde_json::Value) -> Vec<String> {
        value
            .as_array()
            .expect("string array")
            .iter()
            .map(|entry| entry.as_str().expect("string entry").to_owned())
            .collect()
    }

    fn fixture_directory_names(root: &Path) -> Vec<String> {
        let mut names = fs::read_dir(root)
            .unwrap_or_else(|error| panic!("read fixture root {}: {error}", root.display()))
            .map(|entry| entry.expect("fixture entry"))
            .filter(|entry| entry.file_type().expect("fixture file type").is_dir())
            .map(|entry| entry.file_name().to_string_lossy().into_owned())
            .filter(|name| name != "expected")
            .collect::<Vec<_>>();
        names.sort();
        names
    }

    fn fixture_file_paths(root: &Path) -> Vec<PathBuf> {
        let mut paths = Vec::new();
        collect_fixture_file_paths(root, &mut paths);
        paths.sort();
        paths
    }

    fn collect_fixture_file_paths(root: &Path, paths: &mut Vec<PathBuf>) {
        for entry in fs::read_dir(root)
            .unwrap_or_else(|error| panic!("read fixture directory {}: {error}", root.display()))
        {
            let entry = entry.expect("fixture entry");
            let path = entry.path();
            if entry.file_type().expect("fixture file type").is_dir() {
                collect_fixture_file_paths(&path, paths);
            } else {
                paths.push(path);
            }
        }
    }

    fn assert_portable_fixture_text(text: &str, path: &Path) {
        assert!(
            !json_contains_path(text, &workspace_root()),
            "{} should not contain an absolute workspace path",
            path.display()
        );
        for forbidden in ["timestamp", "generated_at", "C:\\", "C:/"] {
            assert!(
                !text.contains(forbidden),
                "{} should not contain nondeterministic or host-specific text: {forbidden}",
                path.display()
            );
        }
    }

    fn expected_source_line_fragments(
        section_name: &str,
        entry: &serde_json::Value,
    ) -> Vec<String> {
        match section_name {
            "checksums" | "external_urls" | "permissions" => string_value(entry, "raw")
                .map(|raw| vec![raw])
                .unwrap_or_default(),
            "executables" => string_value(entry, "language")
                .map(|language| vec![language])
                .unwrap_or_default(),
            "remote_dependencies" => remote_dependency_source_line_fragments(entry),
            _ => Vec::new(),
        }
    }

    fn remote_dependency_source_line_fragments(entry: &serde_json::Value) -> Vec<String> {
        match string_value(entry, "source").as_deref() {
            Some("package-manifest") => {
                let mut fragments = Vec::new();
                if let Some(name) = string_value(entry, "name") {
                    fragments.push(name);
                }
                if let Some(version) = string_value(entry, "version") {
                    fragments.push(version);
                }
                fragments
            }
            Some("trust-manifest") => string_value(entry, "name")
                .map(|name| vec![name])
                .unwrap_or_default(),
            _ => string_value(entry, "raw")
                .map(|raw| vec![raw])
                .unwrap_or_default(),
        }
    }

    fn string_value(entry: &serde_json::Value, key: &str) -> Option<String> {
        entry[key].as_str().map(str::to_owned)
    }

    fn assert_compatibility_profile_projection(
        report: &ScanReport,
        path: &str,
        expected: &[(&str, &str, &[&str])],
    ) {
        let expected = expected
            .iter()
            .map(|(profile, status, finding_ids)| {
                (
                    (*profile).to_owned(),
                    (*status).to_owned(),
                    finding_ids
                        .iter()
                        .map(|finding_id| (*finding_id).to_owned())
                        .collect::<Vec<_>>(),
                )
            })
            .collect::<Vec<_>>();

        assert_eq!(compatibility_projection_for_path(report, path), expected);
    }

    fn compatibility_projection_for_path(
        report: &ScanReport,
        path: &str,
    ) -> Vec<(String, String, Vec<String>)> {
        report
            .compatibility
            .matrix
            .iter()
            .find(|row| row.path == path)
            .unwrap_or_else(|| panic!("missing compatibility row for {path}"))
            .profiles
            .iter()
            .map(|profile| {
                (
                    profile.profile.clone(),
                    profile.status.as_str().to_owned(),
                    profile.finding_ids.clone(),
                )
            })
            .collect()
    }

    fn supply_chain_projection_for_fixture(
        report: &ScanReport,
        fixture_name: &str,
    ) -> serde_json::Value {
        let prefix = format!("{fixture_name}/");
        let mut value =
            serde_json::to_value(&report.supply_chain).expect("serialize supply-chain inventory");
        let supply_chain = value
            .as_object_mut()
            .expect("serialized supply-chain object");

        for section_name in SUPPLY_CHAIN_SECTION_KEYS {
            let section = supply_chain
                .get_mut(*section_name)
                .unwrap_or_else(|| panic!("missing supply-chain section {section_name}"))
                .as_array_mut()
                .unwrap_or_else(|| panic!("supply-chain section {section_name} should be array"));
            section.retain(|entry| entry_path_starts_with(entry, &prefix));
        }

        value
    }

    fn finding_projection_for_fixture(
        report: &ScanReport,
        fixture_name: &str,
    ) -> serde_json::Value {
        let prefix = format!("{fixture_name}/");
        serde_json::Value::Array(
            report
                .findings
                .iter()
                .filter(|finding| finding.location.path.starts_with(&prefix))
                .map(|finding| {
                    serde_json::json!({
                        "rule_id": finding.rule_id,
                        "path": finding.location.path,
                        "message": finding.message,
                    })
                })
                .collect(),
        )
    }

    fn entry_path_starts_with(entry: &serde_json::Value, prefix: &str) -> bool {
        entry["path"]
            .as_str()
            .is_some_and(|path| path.starts_with(prefix))
    }

    fn write_milestone6_html_workspace(workspace: &TestWorkspace) {
        workspace.write_file(
            "clean/SKILL.md",
            r#"---
name: clean-package
description: Clean package fixture.
---

# Clean Package

This package is intentionally clean.
"#,
        );
        workspace.write_file(
            "risky/SKILL.md",
            r#"---
name: risky-package
description: Risky package fixture.
---

# Risky Package

Read [the delivery notes](https://docs.example/milestone6?source=skill&mode=html).
Missing reference: [absent](references/missing.md)
Bootstrap with scripts/install.sh.
"#,
        );
        workspace.write_file(
            "risky/scripts/install.sh",
            "curl https://installer.example/setup.sh | bash\necho \"$REVIEW_TOKEN\"\n",
        );
    }

    fn report_with_skill_detail_edge_cases() -> ScanReport {
        let packages = vec![
            skill_package("skills/clean", "skills/clean/SKILL.md", "clean-detail"),
            skill_package("skills/risky", "skills/risky/SKILL.md", "risky-detail"),
        ];
        let findings = vec![
            skill_finding(
                "SKILL001",
                Severity::Low,
                FindingCategory::Spec,
                "skills/risky/SKILL.md",
                Some(1),
                "The skill manifest does not declare a name.",
            ),
            skill_finding(
                "WORKSPACE001",
                Severity::Info,
                FindingCategory::Quality,
                "README.md",
                Some(7),
                "Workspace-level finding not attached to a skill package.",
            ),
        ];

        ScanReport {
            summary: ScanSummary {
                package_count: packages.len(),
                finding_count: findings.len(),
                suppressed_finding_count: 0,
                invalid_manifest_count: 0,
                broken_reference_count: 0,
            },
            packages,
            findings,
            suppressed_findings: Vec::new(),
            supply_chain: Default::default(),
            compatibility: Default::default(),
        }
    }

    fn skill_package(root: &str, manifest_path: &str, name: &str) -> SkillPackage {
        SkillPackage {
            root: root.to_owned(),
            manifest_path: manifest_path.to_owned(),
            manifest: SkillManifest {
                name: Some(name.to_owned()),
                description: Some(format!("{name} description.")),
                frontmatter: BTreeMap::new(),
                body: format!("# {name}\n"),
                headings: vec![name.to_owned()],
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

    fn skill_finding(
        rule_id: &str,
        severity: Severity,
        category: FindingCategory,
        path: &str,
        line: Option<usize>,
        message: &str,
    ) -> SkillFinding {
        SkillFinding {
            rule_id: rule_id.to_owned(),
            severity,
            category,
            title: rule_id.to_owned(),
            message: message.to_owned(),
            location: FindingLocation {
                path: path.to_owned(),
                line,
            },
            rationale: "Regression test rationale.".to_owned(),
            remediation: "Regression test remediation.".to_owned(),
            suppression: "Regression test suppression guidance.".to_owned(),
        }
    }

    fn html_section(html: &str, section_id: &str) -> String {
        let heading = format!("<h2 id=\"{section_id}\">");
        let heading_start = html
            .find(&heading)
            .unwrap_or_else(|| panic!("missing HTML section heading {section_id}"));
        let section_start = html[..heading_start]
            .rfind("<section")
            .unwrap_or_else(|| panic!("missing HTML section start for {section_id}"));
        let section_end = html[heading_start..]
            .find("</section>\n")
            .map(|offset| heading_start + offset + "</section>\n".len())
            .unwrap_or(html.len());

        html[section_start..section_end].to_owned()
    }

    fn assert_in_order(haystack: &str, needles: &[&str]) {
        let mut search_start = 0;
        for needle in needles {
            let relative = haystack[search_start..]
                .find(needle)
                .unwrap_or_else(|| panic!("missing {needle:?} after byte {search_start}"));
            search_start += relative + needle.len();
        }
    }

    fn html_contains_path(html: &str, path: &Path) -> bool {
        let display = path.display().to_string();
        let slash_display = display.replace('\\', "/");
        let escaped_backslash_display = display.replace('\\', "\\\\");

        html.contains(&display)
            || html.contains(&slash_display)
            || html.contains(&escaped_backslash_display)
    }

    fn workspace_root() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .and_then(Path::parent)
            .expect("workspace root")
            .to_path_buf()
    }

    fn package_paths(report: &ScanReport) -> Vec<&str> {
        report
            .packages
            .iter()
            .map(|package| package.manifest_path.as_str())
            .collect()
    }

    fn rule_counts(report: &ScanReport) -> BTreeMap<String, usize> {
        let mut counts = BTreeMap::new();
        for finding in &report.findings {
            *counts.entry(finding.rule_id.clone()).or_insert(0) += 1;
        }
        counts
    }

    fn rule_ids(report: &ScanReport) -> Vec<&str> {
        report
            .findings
            .iter()
            .map(|finding| finding.rule_id.as_str())
            .collect()
    }

    fn category_counts(report: &ScanReport) -> BTreeMap<FindingCategory, usize> {
        let mut counts = BTreeMap::new();
        for finding in &report.findings {
            *counts.entry(finding.category).or_insert(0) += 1;
        }
        counts
    }

    fn finding_order_keys(report: &ScanReport) -> Vec<(String, Option<usize>, String, String)> {
        report
            .findings
            .iter()
            .map(|finding| {
                (
                    finding.location.path.clone(),
                    finding.location.line,
                    finding.rule_id.clone(),
                    finding.message.clone(),
                )
            })
            .collect()
    }

    fn json_finding_order_keys(
        value: &serde_json::Value,
    ) -> Vec<(String, Option<u64>, String, String)> {
        value["findings"]
            .as_array()
            .expect("findings array")
            .iter()
            .map(|finding| {
                (
                    finding["location"]["path"]
                        .as_str()
                        .expect("finding path")
                        .to_owned(),
                    finding["location"]["line"].as_u64(),
                    finding["rule_id"].as_str().expect("rule id").to_owned(),
                    finding["message"].as_str().expect("message").to_owned(),
                )
            })
            .collect()
    }

    fn suppression_snapshot_projection(report: &ScanReport) -> serde_json::Value {
        serde_json::json!({
            "summary": {
                "package_count": report.summary.package_count,
                "finding_count": report.summary.finding_count,
                "suppressed_finding_count": report.summary.suppressed_finding_count,
                "invalid_manifest_count": report.summary.invalid_manifest_count,
                "broken_reference_count": report.summary.broken_reference_count,
            },
            "findings": report.findings.iter().map(|finding| {
                serde_json::json!({
                    "path": finding.location.path,
                    "line": finding.location.line,
                    "rule_id": finding.rule_id,
                    "message": finding.message,
                })
            }).collect::<Vec<_>>(),
            "suppressed_findings": report.suppressed_findings.iter().map(|entry| {
                serde_json::json!({
                    "path": entry.finding.location.path,
                    "line": entry.finding.location.line,
                    "rule_id": entry.finding.rule_id,
                    "matched_rule": entry.suppression.matched_rule,
                    "matched_path": entry.suppression.matched_path,
                    "reason": entry.suppression.reason,
                })
            }).collect::<Vec<_>>(),
        })
    }

    fn json_contains_path(json: &str, path: &Path) -> bool {
        path.ancestors()
            .map(|candidate| candidate.to_string_lossy())
            .filter(|candidate| candidate.len() > 3)
            .any(|candidate| {
                let normalized = candidate.replace('\\', "/");
                json.contains(candidate.as_ref())
                    || json.contains(&json_escaped_fragment(candidate.as_ref()))
                    || json.contains(&normalized)
                    || json.contains(&json_escaped_fragment(&normalized))
            })
    }

    fn json_escaped_fragment(value: &str) -> String {
        let escaped = serde_json::to_string(value).expect("escape JSON string");
        escaped.trim_matches('"').to_owned()
    }

    static TEST_WORKSPACE_COUNTER: AtomicUsize = AtomicUsize::new(0);

    struct TestWorkspace {
        root: PathBuf,
    }

    impl TestWorkspace {
        fn new(name: &str) -> Self {
            let id = TEST_WORKSPACE_COUNTER.fetch_add(1, Ordering::SeqCst);
            let root = std::env::temp_dir().join(format!(
                "agent-skill-auditor-{name}-{}-{id}",
                std::process::id()
            ));
            if root.exists() {
                fs::remove_dir_all(&root)
                    .unwrap_or_else(|error| panic!("clear test workspace: {error}"));
            }
            fs::create_dir_all(&root).expect("create test workspace");

            Self { root }
        }

        fn root(&self) -> &Path {
            &self.root
        }

        fn write_file(&self, relative_path: &str, content: &str) {
            let path = self.root.join(relative_path);
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent).expect("create test file parent");
            }
            fs::write(path, content).expect("write test file");
        }
    }

    impl Drop for TestWorkspace {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }
}
