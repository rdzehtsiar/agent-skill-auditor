// SPDX-License-Identifier: Apache-2.0

pub const FIXTURE_GROUPS: &[&str] = &["spec", "compatibility", "security", "behavior"];

#[cfg(test)]
mod tests {
    use super::*;
    use agent_audit_core::{scan_path, FindingCategory, ScanOptions};
    use agent_audit_report::{
        render_html, render_json, render_report, render_sarif, render_summary, ReportFormat,
    };
    use std::collections::BTreeMap;
    use std::path::{Path, PathBuf};

    #[test]
    fn fixture_groups_match_planned_fixture_directories() {
        assert_eq!(
            FIXTURE_GROUPS,
            &["spec", "compatibility", "security", "behavior"]
        );
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
        assert!(html.contains("<h2 id=\"summary\">Summary</h2>"));
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

    fn representative_corpus_root() -> PathBuf {
        workspace_root().join("fixtures/spec/phase1/representative-corpus")
    }

    fn expected_representative_corpus_json() -> &'static str {
        let expected =
            include_str!("../../../fixtures/spec/phase2/expected/representative-corpus.json");
        expected.strip_suffix('\n').unwrap_or(expected)
    }

    fn workspace_root() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .and_then(Path::parent)
            .expect("workspace root")
            .to_path_buf()
    }

    fn package_paths(report: &agent_audit_core::ScanReport) -> Vec<&str> {
        report
            .packages
            .iter()
            .map(|package| package.manifest_path.as_str())
            .collect()
    }

    fn rule_counts(report: &agent_audit_core::ScanReport) -> BTreeMap<String, usize> {
        let mut counts = BTreeMap::new();
        for finding in &report.findings {
            *counts.entry(finding.rule_id.clone()).or_insert(0) += 1;
        }
        counts
    }

    fn category_counts(report: &agent_audit_core::ScanReport) -> BTreeMap<FindingCategory, usize> {
        let mut counts = BTreeMap::new();
        for finding in &report.findings {
            *counts.entry(finding.category).or_insert(0) += 1;
        }
        counts
    }

    fn finding_order_keys(
        report: &agent_audit_core::ScanReport,
    ) -> Vec<(String, Option<usize>, String, String)> {
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
}
