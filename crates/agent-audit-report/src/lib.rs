// SPDX-License-Identifier: Apache-2.0

use std::collections::{BTreeMap, BTreeSet};

use agent_audit_core::{FindingCategory, ScanReport, Severity, SkillFinding, SkillPackage};
use serde_json::{json, Value};

pub const SUPPORTED_REPORT_FORMATS: &[&str] = &["summary", "json", "sarif", "html"];

pub fn render_html(report: &ScanReport) -> String {
    let mut html = String::from(
        r#"<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Agent Skill Auditor Report</title>
<style>
body{font-family:system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;line-height:1.5;margin:2rem;color:#1f2933;background:#ffffff}
h1,h2{line-height:1.2}
table{border-collapse:collapse;width:100%;margin:1rem 0 2rem}
th,td{border:1px solid #d9e2ec;padding:.5rem;text-align:left;vertical-align:top}
th{background:#f0f4f8}
.summary{display:grid;grid-template-columns:repeat(auto-fit,minmax(12rem,1fr));gap:.75rem;margin:1rem 0 2rem}
.summary div{border:1px solid #d9e2ec;padding:.75rem}
.count{display:block;font-size:1.5rem;font-weight:700}
</style>
</head>
<body>
<h1>Agent Skill Auditor Report</h1>
"#,
    );

    html.push_str("<section aria-labelledby=\"summary\"><h2 id=\"summary\">Summary</h2><div class=\"summary\">");
    html.push_str(&summary_count("Packages", report.summary.package_count));
    html.push_str(&summary_count("Findings", report.summary.finding_count));
    html.push_str(&summary_count(
        "Invalid manifests",
        report.summary.invalid_manifest_count,
    ));
    html.push_str(&summary_count(
        "Broken references",
        report.summary.broken_reference_count,
    ));
    html.push_str("</div></section>\n");

    html.push_str(
        "<section aria-labelledby=\"packages\"><h2 id=\"packages\">Packages</h2><table><thead><tr><th>Name</th><th>Description</th><th>Manifest</th><th>Root</th></tr></thead><tbody>",
    );
    let packages = sorted_packages(&report.packages);
    if packages.is_empty() {
        html.push_str("<tr><td colspan=\"4\">No packages discovered.</td></tr>");
    }
    for package in packages {
        html.push_str("<tr><td>");
        html.push_str(&escape_html(package.manifest.name.as_deref().unwrap_or("")));
        html.push_str("</td><td>");
        html.push_str(&escape_html(
            package.manifest.description.as_deref().unwrap_or(""),
        ));
        html.push_str("</td><td>");
        html.push_str(&escape_html(&package.manifest_path));
        html.push_str("</td><td>");
        html.push_str(&escape_html(&package.root));
        html.push_str("</td></tr>");
    }
    html.push_str("</tbody></table></section>\n");

    html.push_str(
        "<section aria-labelledby=\"findings\"><h2 id=\"findings\">Findings</h2><table><thead><tr><th>Rule</th><th>Severity</th><th>Category</th><th>Location</th><th>Title</th><th>Message</th><th>Why it matters</th><th>How to fix</th><th>Suppression</th></tr></thead><tbody>",
    );
    let findings = sorted_findings(&report.findings);
    if findings.is_empty() {
        html.push_str("<tr><td colspan=\"9\">No findings.</td></tr>");
    }
    for finding in findings {
        html.push_str("<tr><td>");
        html.push_str(&escape_html(&finding.rule_id));
        html.push_str("</td><td>");
        html.push_str(severity_name(finding.severity));
        html.push_str("</td><td>");
        html.push_str(category_name(finding.category));
        html.push_str("</td><td>");
        html.push_str(&escape_html(&location_display(
            &finding.location.path,
            finding.location.line,
        )));
        html.push_str("</td><td>");
        html.push_str(&escape_html(&finding.title));
        html.push_str("</td><td>");
        html.push_str(&escape_html(&finding.message));
        html.push_str("</td><td>");
        html.push_str(&escape_html(&finding.rationale));
        html.push_str("</td><td>");
        html.push_str(&escape_html(&finding.remediation));
        html.push_str("</td><td>");
        html.push_str(&escape_html(&finding.suppression));
        html.push_str("</td></tr>");
    }
    html.push_str("</tbody></table></section>\n</body>\n</html>\n");

    html
}

pub fn render_sarif(report: &ScanReport) -> serde_json::Result<String> {
    serde_json::to_string_pretty(&sarif_value(report))
}

fn summary_count(label: &str, count: usize) -> String {
    format!("<div><span class=\"count\">{count}</span>{label}</div>")
}

fn sorted_packages(packages: &[SkillPackage]) -> Vec<&SkillPackage> {
    let mut sorted = packages.iter().collect::<Vec<_>>();
    sorted.sort_by(|left, right| {
        left.manifest_path
            .cmp(&right.manifest_path)
            .then(left.root.cmp(&right.root))
    });
    sorted
}

fn location_display(path: &str, line: Option<usize>) -> String {
    match line {
        Some(line) => format!("{path}:{line}"),
        None => path.to_owned(),
    }
}

fn escape_html(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());

    for character in value.chars() {
        match character {
            '&' => escaped.push_str("&amp;"),
            '<' => escaped.push_str("&lt;"),
            '>' => escaped.push_str("&gt;"),
            '"' => escaped.push_str("&quot;"),
            '\'' => escaped.push_str("&#39;"),
            _ => escaped.push(character),
        }
    }

    escaped
}

fn sarif_value(report: &ScanReport) -> Value {
    let sorted_findings = sorted_findings(&report.findings);
    let rule_indexes = rule_indexes(&sorted_findings);

    json!({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "Agent Skill Auditor",
                        "semanticVersion": env!("CARGO_PKG_VERSION"),
                        "rules": sarif_rules(&sorted_findings)
                    }
                },
                "results": sarif_results(&sorted_findings, &rule_indexes)
            }
        ]
    })
}

fn sorted_findings(findings: &[SkillFinding]) -> Vec<&SkillFinding> {
    let mut sorted = findings.iter().collect::<Vec<_>>();
    sorted.sort_by(|left, right| {
        left.location
            .path
            .cmp(&right.location.path)
            .then(left.location.line.cmp(&right.location.line))
            .then(left.rule_id.cmp(&right.rule_id))
            .then(left.message.cmp(&right.message))
    });
    sorted
}

fn rule_indexes(findings: &[&SkillFinding]) -> BTreeMap<String, usize> {
    rule_ids(findings)
        .into_iter()
        .enumerate()
        .map(|(index, rule_id)| (rule_id, index))
        .collect()
}

fn rule_ids(findings: &[&SkillFinding]) -> Vec<String> {
    findings
        .iter()
        .map(|finding| finding.rule_id.clone())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn sarif_rules(findings: &[&SkillFinding]) -> Vec<Value> {
    let findings_by_rule = findings
        .iter()
        .map(|finding| (finding.rule_id.as_str(), *finding))
        .collect::<BTreeMap<_, _>>();

    findings_by_rule
        .values()
        .map(|finding| {
            json!({
                "id": finding.rule_id,
                "name": finding.title,
                "shortDescription": {
                    "text": finding.title
                },
                "fullDescription": {
                    "text": finding.rationale
                },
                "help": {
                    "text": format!("{}\n\n{}", finding.remediation, finding.suppression)
                },
                "defaultConfiguration": {
                    "level": sarif_level(finding.severity)
                },
                "properties": {
                    "agentAuditSeverity": severity_name(finding.severity),
                    "category": category_name(finding.category)
                }
            })
        })
        .collect()
}

fn sarif_results(findings: &[&SkillFinding], rule_indexes: &BTreeMap<String, usize>) -> Vec<Value> {
    findings
        .iter()
        .map(|finding| {
            let uri = sarif_uri_reference(&finding.location.path);
            let physical_location = match finding.location.line {
                Some(line) => json!({
                    "artifactLocation": {
                        "uri": uri
                    },
                    "region": {
                        "startLine": line
                    }
                }),
                None => json!({
                    "artifactLocation": {
                        "uri": uri
                    }
                }),
            };

            json!({
                "ruleId": finding.rule_id,
                "ruleIndex": rule_indexes[&finding.rule_id],
                "level": sarif_level(finding.severity),
                "message": {
                    "text": finding.message
                },
                "locations": [
                    {
                        "physicalLocation": physical_location
                    }
                ],
                "properties": {
                    "agentAuditSeverity": severity_name(finding.severity),
                    "category": category_name(finding.category)
                }
            })
        })
        .collect()
}

fn sarif_uri_reference(path: &str) -> String {
    let mut encoded = String::with_capacity(path.len());

    for byte in path.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' | b'/' => {
                encoded.push(char::from(byte));
            }
            _ => encoded.push_str(&format!("%{byte:02X}")),
        }
    }

    encoded
}

fn sarif_level(severity: Severity) -> &'static str {
    match severity {
        Severity::Info => "note",
        Severity::Low | Severity::Medium => "warning",
        Severity::High | Severity::Critical => "error",
    }
}

fn severity_name(severity: Severity) -> &'static str {
    match severity {
        Severity::Info => "info",
        Severity::Low => "low",
        Severity::Medium => "medium",
        Severity::High => "high",
        Severity::Critical => "critical",
    }
}

fn category_name(category: FindingCategory) -> &'static str {
    match category {
        FindingCategory::Spec => "spec",
        FindingCategory::Compatibility => "compatibility",
        FindingCategory::Security => "security",
        FindingCategory::Quality => "quality",
        FindingCategory::Portability => "portability",
        FindingCategory::Reproducibility => "reproducibility",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use agent_audit_core::model::ScanSummary;
    use agent_audit_core::{
        FindingLocation, SkillFinding, SkillGraph, SkillManifest, SkillPackage, SkillReference,
    };
    use std::collections::BTreeMap;
    use std::path::Path;

    #[test]
    fn supported_report_formats_match_phase_one_outputs() {
        assert_eq!(
            SUPPORTED_REPORT_FORMATS,
            &["summary", "json", "sarif", "html"]
        );
    }

    #[test]
    fn html_output_has_summary_packages_and_findings() {
        let report = report_with_packages_and_findings(
            vec![package(
                "skills/review",
                "skills/review/SKILL.md",
                Some("review-skill"),
                Some("Reviews agent skills."),
            )],
            vec![finding(
                "SKILL010",
                Severity::Low,
                FindingCategory::Spec,
                "Broken relative reference",
                "The referenced file could not be found.",
                "skills/review/SKILL.md",
                Some(12),
            )],
        );

        let html = render_html(&report);

        assert!(html.contains("<h2 id=\"summary\">Summary</h2>"));
        assert!(html.contains("<h2 id=\"packages\">Packages</h2>"));
        assert!(html.contains("<h2 id=\"findings\">Findings</h2>"));
        assert!(html.contains("<span class=\"count\">1</span>Packages"));
        assert!(html.contains("<span class=\"count\">1</span>Findings"));
        assert!(html.contains("<span class=\"count\">0</span>Invalid manifests"));
        assert!(html.contains("<span class=\"count\">1</span>Broken references"));
        assert!(html.contains("review-skill"));
        assert!(html.contains("Reviews agent skills."));
        assert!(html.contains("skills/review/SKILL.md:12"));
        assert!(html.contains("SKILL010"));
        assert!(html.contains("Broken relative reference"));
        assert!(html.contains("The referenced file could not be found."));
    }

    #[test]
    fn html_output_escapes_report_derived_strings_as_plain_text() {
        let report = report_with_packages_and_findings(
            vec![package(
                "skills/<root>",
                "skills/<skill>/SKILL.md",
                Some("<b>name</b>"),
                Some("\"description\" & 'notes'"),
            )],
            vec![finding(
                "SEC<script>",
                Severity::High,
                FindingCategory::Security,
                "<img src=x>",
                "</td><script>alert(1)</script>",
                "skills/<skill>/SKILL.md",
                None,
            )],
        );

        let html = render_html(&report);

        assert!(html.contains("&lt;b&gt;name&lt;/b&gt;"));
        assert!(html.contains("&quot;description&quot; &amp; &#39;notes&#39;"));
        assert!(html.contains("skills/&lt;skill&gt;/SKILL.md"));
        assert!(html.contains("SEC&lt;script&gt;"));
        assert!(html.contains("&lt;img src=x&gt;"));
        assert!(html.contains("&lt;/td&gt;&lt;script&gt;alert(1)&lt;/script&gt;"));
        assert!(!html.contains("<b>name</b>"));
        assert!(!html.contains("</td><script>alert(1)</script>"));
    }

    #[test]
    fn html_output_renders_empty_state_rows_for_no_packages_and_no_findings() {
        let report = report_with_packages_and_findings(Vec::new(), Vec::new());

        let html = render_html(&report);

        assert!(html.contains("<tr><td colspan=\"4\">No packages discovered.</td></tr>"));
        assert!(html.contains("<tr><td colspan=\"9\">No findings.</td></tr>"));
    }

    #[test]
    fn html_output_orders_packages_and_findings_deterministically() {
        let report = report_with_packages_and_findings(
            vec![
                package("zeta", "zeta/SKILL.md", Some("zeta"), Some("Zeta.")),
                package("alpha-b", "alpha/SKILL.md", Some("alpha-b"), Some("B.")),
                package("alpha-a", "alpha/SKILL.md", Some("alpha-a"), Some("A.")),
            ],
            vec![
                finding(
                    "SKILL020",
                    Severity::Medium,
                    FindingCategory::Spec,
                    "Oversized skill manifest",
                    "Later path.",
                    "zeta/SKILL.md",
                    Some(1),
                ),
                finding(
                    "SKILL030",
                    Severity::Low,
                    FindingCategory::Spec,
                    "Duplicate skill name",
                    "Second message.",
                    "alpha/SKILL.md",
                    Some(2),
                ),
                finding(
                    "SKILL010",
                    Severity::Low,
                    FindingCategory::Spec,
                    "Broken relative reference",
                    "No line sorts before line.",
                    "alpha/SKILL.md",
                    None,
                ),
            ],
        );

        let html = render_html(&report);

        assert_in_order(&html, &["alpha-a", "alpha-b", "zeta"]);
        assert_in_order(
            &html,
            &[
                "No line sorts before line.",
                "Second message.",
                "Later path.",
            ],
        );
    }

    #[test]
    fn html_output_is_deterministic_and_offline() {
        let report = report_with_packages_and_findings(
            vec![package(
                "skills/review",
                "skills/review/SKILL.md",
                Some("review-skill"),
                Some("Reviews agent skills."),
            )],
            vec![finding(
                "SKILL001",
                Severity::Low,
                FindingCategory::Spec,
                "Missing skill name",
                "The skill manifest does not declare a name.",
                "skills/review/SKILL.md",
                Some(1),
            )],
        );

        let first = render_html(&report);
        let second = render_html(&report);

        assert_eq!(first, second);
        assert!(!first.contains("http://"));
        assert!(!first.contains("https://"));
        assert!(!first.contains("<script"));
        assert!(!first.contains("timestamp"));
        assert!(!first.contains("generated_at"));
    }

    #[test]
    fn sarif_output_has_required_shape() {
        let report = report_with_findings(vec![finding(
            "SKILL001",
            Severity::Low,
            FindingCategory::Spec,
            "Missing skill name",
            "The skill manifest does not declare a name.",
            "SKILL.md",
            Some(1),
        )]);

        let value = render_sarif_value(&report);

        assert_eq!(value["version"], "2.1.0");
        assert_eq!(
            value["$schema"],
            "https://json.schemastore.org/sarif-2.1.0.json"
        );
        assert_eq!(
            value["runs"][0]["tool"]["driver"]["name"],
            "Agent Skill Auditor"
        );
        assert_eq!(
            value["runs"][0]["tool"]["driver"]["rules"]
                .as_array()
                .unwrap()
                .len(),
            1
        );
        assert_eq!(value["runs"][0]["results"].as_array().unwrap().len(), 1);
    }

    #[test]
    fn sarif_output_handles_zero_findings() {
        let report = report_with_findings(Vec::new());

        let value = render_sarif_value(&report);

        assert_eq!(
            value["runs"][0]["tool"]["driver"]["rules"]
                .as_array()
                .expect("rules array")
                .len(),
            0
        );
        assert_eq!(
            value["runs"][0]["results"]
                .as_array()
                .expect("results array")
                .len(),
            0
        );
    }

    #[test]
    fn sarif_output_preserves_finding_metadata_and_location() {
        let report = report_with_findings(vec![finding(
            "SEC005",
            Severity::High,
            FindingCategory::Security,
            "Use of sudo",
            "The script invokes `sudo`.",
            "scripts/build.sh",
            Some(12),
        )]);

        let value = render_sarif_value(&report);
        let rule = &value["runs"][0]["tool"]["driver"]["rules"][0];
        let result = &value["runs"][0]["results"][0];

        assert_eq!(rule["id"], "SEC005");
        assert_eq!(rule["name"], "Use of sudo");
        assert_eq!(rule["shortDescription"]["text"], "Use of sudo");
        assert_eq!(rule["fullDescription"]["text"], "Use of sudo rationale.");
        assert_eq!(
            rule["help"]["text"],
            "Use of sudo remediation.\n\nSuppress `SEC005` only with a documented reason."
        );
        assert_eq!(rule["defaultConfiguration"]["level"], "error");
        assert_eq!(rule["properties"]["agentAuditSeverity"], "high");
        assert_eq!(rule["properties"]["category"], "security");
        assert_eq!(result["ruleId"], "SEC005");
        assert_eq!(result["ruleIndex"], 0);
        assert_eq!(result["level"], "error");
        assert_eq!(result["message"]["text"], "The script invokes `sudo`.");
        assert_eq!(
            result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"],
            "scripts/build.sh"
        );
        assert_eq!(
            result["locations"][0]["physicalLocation"]["region"]["startLine"],
            12
        );
        assert_eq!(result["properties"]["agentAuditSeverity"], "high");
        assert_eq!(result["properties"]["category"], "security");
    }

    #[test]
    fn sarif_output_orders_results_by_path_line_rule_id_then_message() {
        let report = report_with_findings(vec![
            finding(
                "SKILL020",
                Severity::Medium,
                FindingCategory::Spec,
                "Oversized skill manifest",
                "Later path.",
                "zeta/SKILL.md",
                Some(1),
            ),
            finding(
                "SKILL030",
                Severity::Low,
                FindingCategory::Spec,
                "Duplicate skill name",
                "Second message.",
                "alpha/SKILL.md",
                Some(2),
            ),
            finding(
                "SKILL010",
                Severity::Low,
                FindingCategory::Spec,
                "Broken relative reference",
                "No line sorts before line.",
                "alpha/SKILL.md",
                None,
            ),
            finding(
                "SKILL040",
                Severity::Low,
                FindingCategory::Spec,
                "Unknown frontmatter field",
                "Line one sorts before line two.",
                "alpha/SKILL.md",
                Some(1),
            ),
            finding(
                "SKILL020",
                Severity::Low,
                FindingCategory::Spec,
                "Oversized skill manifest",
                "First rule id at same path and line.",
                "alpha/SKILL.md",
                Some(2),
            ),
            finding(
                "SKILL030",
                Severity::Low,
                FindingCategory::Spec,
                "Duplicate skill name",
                "First message.",
                "alpha/SKILL.md",
                Some(2),
            ),
        ]);

        let value = render_sarif_value(&report);

        assert_eq!(
            sarif_result_tuples(&value),
            vec![
                (
                    "alpha/SKILL.md",
                    None,
                    "SKILL010",
                    "No line sorts before line."
                ),
                (
                    "alpha/SKILL.md",
                    Some(1),
                    "SKILL040",
                    "Line one sorts before line two."
                ),
                (
                    "alpha/SKILL.md",
                    Some(2),
                    "SKILL020",
                    "First rule id at same path and line."
                ),
                ("alpha/SKILL.md", Some(2), "SKILL030", "First message."),
                ("alpha/SKILL.md", Some(2), "SKILL030", "Second message."),
                ("zeta/SKILL.md", Some(1), "SKILL020", "Later path."),
            ]
        );
    }

    #[test]
    fn sarif_output_uses_rule_indexes_matching_sorted_rule_metadata() {
        let report = report_with_findings(vec![
            finding(
                "SKILL020",
                Severity::Medium,
                FindingCategory::Spec,
                "Oversized skill manifest",
                "Oversized manifest.",
                "zeta/SKILL.md",
                Some(5),
            ),
            finding(
                "SKILL001",
                Severity::Low,
                FindingCategory::Spec,
                "Missing skill name",
                "The skill manifest does not declare a name.",
                "alpha/SKILL.md",
                Some(1),
            ),
            finding(
                "SKILL020",
                Severity::Medium,
                FindingCategory::Spec,
                "Oversized skill manifest",
                "A second oversized manifest.",
                "alpha/SKILL.md",
                None,
            ),
        ]);

        let value = render_sarif_value(&report);

        assert_eq!(sarif_rule_ids(&value), vec!["SKILL001", "SKILL020"]);
        assert_eq!(
            sarif_result_rule_indexes(&value),
            vec![("SKILL020", 1), ("SKILL001", 0), ("SKILL020", 1),]
        );
    }

    #[test]
    fn sarif_output_omits_region_when_location_has_no_line() {
        let report = report_with_findings(vec![finding(
            "SKILL010",
            Severity::Low,
            FindingCategory::Spec,
            "Broken relative reference",
            "The referenced file could not be found.",
            "SKILL.md",
            None,
        )]);

        let value = render_sarif_value(&report);
        let physical_location = &value["runs"][0]["results"][0]["locations"][0]["physicalLocation"];

        assert_eq!(physical_location["artifactLocation"]["uri"], "SKILL.md");
        assert!(physical_location.get("region").is_none());
    }

    #[test]
    fn sarif_output_percent_encodes_uri_reference_path_segments() {
        let report = report_with_findings(vec![finding(
            "SKILL010",
            Severity::Low,
            FindingCategory::Spec,
            "Broken relative reference",
            "The referenced file could not be found.",
            "skill package/references/has#hash?query%percent.md",
            Some(3),
        )]);

        let value = render_sarif_value(&report);

        assert_eq!(
            sarif_result_paths(&value),
            vec!["skill%20package/references/has%23hash%3Fquery%25percent.md"]
        );
    }

    #[test]
    fn sarif_uri_reference_encodes_unsafe_characters_and_preserves_slashes() {
        let cases = [
            ("has space/SKILL.md", "has%20space/SKILL.md"),
            ("has#hash/SKILL.md", "has%23hash/SKILL.md"),
            ("has?query/SKILL.md", "has%3Fquery/SKILL.md"),
            ("has%percent/SKILL.md", "has%25percent/SKILL.md"),
            ("nested/path/SKILL.md", "nested/path/SKILL.md"),
        ];

        for (path, expected) in cases {
            assert_eq!(sarif_uri_reference(path), expected);
        }
    }

    #[test]
    fn sarif_output_maps_agent_audit_severities_to_sarif_levels() {
        let report = report_with_findings(vec![
            finding(
                "INFO",
                Severity::Info,
                FindingCategory::Quality,
                "Info",
                "Info finding.",
                "a/SKILL.md",
                Some(1),
            ),
            finding(
                "LOW",
                Severity::Low,
                FindingCategory::Quality,
                "Low",
                "Low finding.",
                "b/SKILL.md",
                Some(1),
            ),
            finding(
                "MEDIUM",
                Severity::Medium,
                FindingCategory::Quality,
                "Medium",
                "Medium finding.",
                "c/SKILL.md",
                Some(1),
            ),
            finding(
                "HIGH",
                Severity::High,
                FindingCategory::Quality,
                "High",
                "High finding.",
                "d/SKILL.md",
                Some(1),
            ),
            finding(
                "CRITICAL",
                Severity::Critical,
                FindingCategory::Quality,
                "Critical",
                "Critical finding.",
                "e/SKILL.md",
                Some(1),
            ),
        ]);

        let value = render_sarif_value(&report);

        assert_eq!(
            sarif_result_levels(&value),
            vec!["note", "warning", "warning", "error", "error"]
        );
        assert_eq!(
            sarif_result_agent_audit_severities(&value),
            vec!["info", "low", "medium", "high", "critical"]
        );
    }

    #[test]
    fn sarif_output_is_deterministic_and_portable() {
        let report = report_with_findings(vec![
            finding(
                "SKILL020",
                Severity::Medium,
                FindingCategory::Spec,
                "Oversized skill manifest",
                "The SKILL.md file exceeds the recommended manifest size.",
                "zeta/SKILL.md",
                Some(5),
            ),
            finding(
                "SKILL001",
                Severity::Low,
                FindingCategory::Spec,
                "Missing skill name",
                "The skill manifest does not declare a name.",
                "alpha/SKILL.md",
                Some(1),
            ),
            finding(
                "SKILL020",
                Severity::Medium,
                FindingCategory::Spec,
                "Oversized skill manifest",
                "A second oversized manifest.",
                "alpha/SKILL.md",
                None,
            ),
        ]);

        let first = render_sarif(&report).expect("render SARIF");
        let second = render_sarif(&report).expect("render SARIF again");
        let value: Value = serde_json::from_str(&first).expect("parse SARIF");

        assert_eq!(first, second);
        assert_eq!(sarif_rule_ids(&value), vec!["SKILL001", "SKILL020"]);
        assert_eq!(
            sarif_result_paths(&value),
            vec!["alpha/SKILL.md", "alpha/SKILL.md", "zeta/SKILL.md"]
        );
        assert!(!json_contains_workspace_root(
            &first,
            Path::new(env!("CARGO_MANIFEST_DIR"))
        ));
        assert!(!first.contains("timestamp"));
        assert!(!first.contains("generated_at"));
    }

    fn report_with_findings(findings: Vec<SkillFinding>) -> ScanReport {
        report_with_packages_and_findings(Vec::new(), findings)
    }

    fn report_with_packages_and_findings(
        packages: Vec<SkillPackage>,
        findings: Vec<SkillFinding>,
    ) -> ScanReport {
        let package_count = packages.len();

        ScanReport {
            packages,
            summary: ScanSummary {
                package_count,
                finding_count: findings.len(),
                invalid_manifest_count: 0,
                broken_reference_count: findings
                    .iter()
                    .filter(|finding| finding.rule_id == "SKILL010")
                    .count(),
            },
            findings,
        }
    }

    fn package(
        root: &str,
        manifest_path: &str,
        name: Option<&str>,
        description: Option<&str>,
    ) -> SkillPackage {
        SkillPackage {
            root: root.to_owned(),
            manifest_path: manifest_path.to_owned(),
            manifest: SkillManifest {
                name: name.map(str::to_owned),
                description: description.map(str::to_owned),
                frontmatter: BTreeMap::new(),
                body: String::new(),
                headings: Vec::new(),
                links: Vec::<SkillReference>::new(),
                inline_code: Vec::new(),
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

    fn finding(
        rule_id: &str,
        severity: Severity,
        category: FindingCategory,
        title: &str,
        message: &str,
        path: &str,
        line: Option<usize>,
    ) -> SkillFinding {
        SkillFinding {
            rule_id: rule_id.to_owned(),
            severity,
            category,
            title: title.to_owned(),
            message: message.to_owned(),
            location: FindingLocation {
                path: path.to_owned(),
                line,
            },
            rationale: format!("{title} rationale."),
            remediation: format!("{title} remediation."),
            suppression: format!("Suppress `{rule_id}` only with a documented reason."),
        }
    }

    fn render_sarif_value(report: &ScanReport) -> Value {
        let sarif = render_sarif(report).expect("render SARIF");
        serde_json::from_str(&sarif).expect("parse SARIF")
    }

    fn sarif_rule_ids(value: &Value) -> Vec<&str> {
        value["runs"][0]["tool"]["driver"]["rules"]
            .as_array()
            .expect("rules array")
            .iter()
            .map(|rule| rule["id"].as_str().expect("rule id"))
            .collect()
    }

    fn sarif_result_paths(value: &Value) -> Vec<&str> {
        value["runs"][0]["results"]
            .as_array()
            .expect("results array")
            .iter()
            .map(|result| {
                result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
                    .as_str()
                    .expect("result path")
            })
            .collect()
    }

    fn sarif_result_levels(value: &Value) -> Vec<&str> {
        value["runs"][0]["results"]
            .as_array()
            .expect("results array")
            .iter()
            .map(|result| result["level"].as_str().expect("result level"))
            .collect()
    }

    fn sarif_result_agent_audit_severities(value: &Value) -> Vec<&str> {
        value["runs"][0]["results"]
            .as_array()
            .expect("results array")
            .iter()
            .map(|result| {
                result["properties"]["agentAuditSeverity"]
                    .as_str()
                    .expect("agent audit severity")
            })
            .collect()
    }

    fn sarif_result_tuples(value: &Value) -> Vec<(&str, Option<u64>, &str, &str)> {
        value["runs"][0]["results"]
            .as_array()
            .expect("results array")
            .iter()
            .map(|result| {
                let physical_location = &result["locations"][0]["physicalLocation"];
                let line = physical_location
                    .get("region")
                    .and_then(|region| region["startLine"].as_u64());

                (
                    physical_location["artifactLocation"]["uri"]
                        .as_str()
                        .expect("result path"),
                    line,
                    result["ruleId"].as_str().expect("rule id"),
                    result["message"]["text"].as_str().expect("message text"),
                )
            })
            .collect()
    }

    fn sarif_result_rule_indexes(value: &Value) -> Vec<(&str, usize)> {
        value["runs"][0]["results"]
            .as_array()
            .expect("results array")
            .iter()
            .map(|result| {
                (
                    result["ruleId"].as_str().expect("rule id"),
                    result["ruleIndex"].as_u64().expect("rule index") as usize,
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

    fn assert_in_order(haystack: &str, needles: &[&str]) {
        let mut previous = 0;

        for needle in needles {
            let offset = haystack[previous..]
                .find(needle)
                .unwrap_or_else(|| panic!("missing {needle:?} after byte {previous}"));
            previous += offset + needle.len();
        }
    }
}
