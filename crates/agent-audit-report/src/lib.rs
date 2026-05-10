// SPDX-License-Identifier: Apache-2.0

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt;
use std::str::FromStr;

use agent_audit_core::{FindingCategory, ScanReport, Severity, SkillFinding, SkillPackage};
use agent_audit_rules::{active_rule_metadata, RuleMetadata, RuleSeverity};
use serde_json::{json, Value};

pub const SUPPORTED_REPORT_FORMATS: &[&str] = &["summary", "json", "sarif", "html"];
pub const SUPPORTED_REPORT_FORMATS_HELP: &str = "supported: summary, json, sarif, html";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReportFormat {
    Summary,
    Json,
    Sarif,
    Html,
}

impl ReportFormat {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Summary => "summary",
            Self::Json => "json",
            Self::Sarif => "sarif",
            Self::Html => "html",
        }
    }
}

impl FromStr for ReportFormat {
    type Err = UnsupportedReportFormat;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "summary" => Ok(Self::Summary),
            "json" => Ok(Self::Json),
            "sarif" => Ok(Self::Sarif),
            "html" => Ok(Self::Html),
            _ => Err(UnsupportedReportFormat {
                value: value.to_owned(),
            }),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnsupportedReportFormat {
    value: String,
}

impl UnsupportedReportFormat {
    pub fn value(&self) -> &str {
        &self.value
    }
}

impl fmt::Display for UnsupportedReportFormat {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "unsupported report format '{}' ({})",
            self.value, SUPPORTED_REPORT_FORMATS_HELP
        )
    }
}

impl Error for UnsupportedReportFormat {}

pub fn render_report(report: &ScanReport, format: ReportFormat) -> serde_json::Result<String> {
    let rendered = match format {
        ReportFormat::Summary => render_summary(report),
        ReportFormat::Json => render_json(report)?,
        ReportFormat::Sarif => render_sarif(report)?,
        ReportFormat::Html => render_html(report),
    };

    Ok(with_trailing_newline(rendered))
}

pub fn render_summary(report: &ScanReport) -> String {
    let mut lines = vec![
        "Agent Skill Auditor scan summary".to_owned(),
        format!("Packages: {}", report.summary.package_count),
        format!("Findings: {}", report.summary.finding_count),
        format!(
            "Suppressed findings: {}",
            report.summary.suppressed_finding_count
        ),
        format!(
            "Invalid manifests: {}",
            report.summary.invalid_manifest_count
        ),
        format!(
            "Broken references: {}",
            report.summary.broken_reference_count
        ),
    ];

    let findings = sorted_findings(&report.findings);
    if findings.is_empty() {
        lines.push(String::new());
        lines.push("No findings.".to_owned());
    } else {
        lines.push(String::new());
        lines.push("Finding details:".to_owned());

        for finding in findings {
            lines.push(format!(
                "{} [{}/{}] {}: {}",
                finding.rule_id,
                severity_name(finding.severity),
                category_name(finding.category),
                location_display(&finding.location.path, finding.location.line),
                finding.message
            ));
        }
    }

    lines.join("\n")
}

pub fn render_json(report: &ScanReport) -> serde_json::Result<String> {
    serde_json::to_string_pretty(report)
}

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
        "Suppressed findings",
        report.summary.suppressed_finding_count,
    ));
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

fn with_trailing_newline(mut rendered: String) -> String {
    if !rendered.ends_with('\n') {
        rendered.push('\n');
    }

    rendered
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
    findings_by_rule(findings)
        .values()
        .map(|finding| sarif_rule(finding))
        .collect()
}

fn findings_by_rule<'a>(findings: &[&'a SkillFinding]) -> BTreeMap<&'a str, &'a SkillFinding> {
    findings
        .iter()
        .map(|finding| (finding.rule_id.as_str(), *finding))
        .collect()
}

fn sarif_rule(finding: &SkillFinding) -> Value {
    match active_rule_metadata(&finding.rule_id) {
        Some(metadata) => sarif_rule_from_registry(metadata),
        None => sarif_rule_from_finding(finding),
    }
}

fn sarif_rule_from_registry(metadata: &RuleMetadata) -> Value {
    json!({
        "id": metadata.id.as_str(),
        "name": metadata.title,
        "shortDescription": {
            "text": metadata.title
        },
        "fullDescription": {
            "text": metadata.rationale
        },
        "help": {
            "text": format!("{}\n\n{}", metadata.remediation, metadata.suppression_guidance)
        },
        "defaultConfiguration": {
            "level": sarif_level_for_rule_severity(metadata.severity)
        },
        "properties": {
            "agentAuditSeverity": metadata.severity.as_str(),
            "category": metadata.category.as_str()
        }
    })
}

fn sarif_rule_from_finding(finding: &SkillFinding) -> Value {
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

fn sarif_level_for_rule_severity(severity: RuleSeverity) -> &'static str {
    match severity {
        RuleSeverity::Info => "note",
        RuleSeverity::Low | RuleSeverity::Medium => "warning",
        RuleSeverity::High | RuleSeverity::Critical => "error",
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
        SuppressedFinding, SuppressionMatch,
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
    fn report_format_parses_supported_formats() {
        assert_eq!("summary".parse::<ReportFormat>(), Ok(ReportFormat::Summary));
        assert_eq!("json".parse::<ReportFormat>(), Ok(ReportFormat::Json));
        assert_eq!("sarif".parse::<ReportFormat>(), Ok(ReportFormat::Sarif));
        assert_eq!("html".parse::<ReportFormat>(), Ok(ReportFormat::Html));
    }

    #[test]
    fn report_format_rejects_unsupported_formats_with_supported_list() {
        let error = "xml"
            .parse::<ReportFormat>()
            .expect_err("unsupported format should fail");

        assert_eq!(error.value(), "xml");
        assert_eq!(
            error.to_string(),
            "unsupported report format 'xml' (supported: summary, json, sarif, html)"
        );
    }

    #[test]
    fn report_format_as_str_matches_supported_metadata() {
        let formats = [
            ReportFormat::Summary,
            ReportFormat::Json,
            ReportFormat::Sarif,
            ReportFormat::Html,
        ];

        assert_eq!(
            formats
                .into_iter()
                .map(ReportFormat::as_str)
                .collect::<Vec<_>>(),
            SUPPORTED_REPORT_FORMATS
        );
    }

    #[test]
    fn render_report_dispatches_supported_formats_with_trailing_newline() {
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

        let summary = render_report(&report, ReportFormat::Summary).expect("render summary");
        let json = render_report(&report, ReportFormat::Json).expect("render JSON");
        let sarif = render_report(&report, ReportFormat::Sarif).expect("render SARIF");
        let html = render_report(&report, ReportFormat::Html).expect("render HTML");

        assert!(summary.starts_with("Agent Skill Auditor scan summary\n"));
        assert!(json.starts_with("{\n"));
        assert!(sarif.contains("\"version\": \"2.1.0\""));
        assert!(html.starts_with("<!doctype html>\n"));
        assert!(summary.ends_with('\n'));
        assert!(json.ends_with('\n'));
        assert!(sarif.ends_with('\n'));
        assert!(html.ends_with('\n'));
        assert_eq!(html, render_html(&report));
    }

    #[test]
    fn summary_output_includes_counts_and_no_finding_state() {
        let report = report_with_summary(2, 0, 4, 1, 0);

        let summary = render_summary(&report);

        assert_eq!(
            summary,
            "Agent Skill Auditor scan summary\nPackages: 2\nFindings: 0\nSuppressed findings: 4\nInvalid manifests: 1\nBroken references: 0\n\nNo findings."
        );
    }

    #[test]
    fn summary_output_orders_findings_and_uses_lowercase_metadata() {
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
                "SEC005",
                Severity::High,
                FindingCategory::Security,
                "Use of sudo",
                "Line two.",
                "alpha/SKILL.md",
                Some(2),
            ),
            finding(
                "SKILL010",
                Severity::Low,
                FindingCategory::Compatibility,
                "Broken relative reference",
                "No line sorts before line.",
                "alpha/SKILL.md",
                None,
            ),
            finding(
                "SKILL001",
                Severity::Info,
                FindingCategory::Quality,
                "Missing skill name",
                "Line one.",
                "alpha/SKILL.md",
                Some(1),
            ),
        ]);

        let summary = render_summary(&report);

        assert!(summary.contains("Packages: 0"));
        assert!(summary.contains("Findings: 4"));
        assert!(summary.contains("Suppressed findings: 0"));
        assert!(summary.contains("Invalid manifests: 0"));
        assert!(summary.contains("Broken references: 1"));
        assert_in_order(
            &summary,
            &[
                "SKILL010 [low/compatibility] alpha/SKILL.md: No line sorts before line.",
                "SKILL001 [info/quality] alpha/SKILL.md:1: Line one.",
                "SEC005 [high/security] alpha/SKILL.md:2: Line two.",
                "SKILL020 [medium/spec] zeta/SKILL.md:1: Later path.",
            ],
        );
    }

    #[test]
    fn json_output_uses_report_renderer() {
        let report = report_with_packages_and_findings(
            vec![package(
                "skills/review",
                "skills/review/SKILL.md",
                Some("review-skill"),
                Some("Reviews agent skills."),
            )],
            vec![finding(
                "SKILL002",
                Severity::Low,
                FindingCategory::Spec,
                "Missing skill description",
                "The skill manifest does not declare a description.",
                "skills/review/SKILL.md",
                Some(2),
            )],
        );

        let rendered = render_report(&report, ReportFormat::Json).expect("render JSON");
        let value: Value = serde_json::from_str(&rendered).expect("parse JSON report");

        assert_eq!(value["summary"]["package_count"], 1);
        assert_eq!(value["summary"]["finding_count"], 1);
        assert_eq!(value["packages"][0]["manifest"]["name"], "review-skill");
        assert_eq!(value["findings"][0]["rule_id"], "SKILL002");
        assert!(rendered.ends_with('\n'));
    }

    #[test]
    fn json_and_html_outputs_include_finding_explanation_fields() {
        let report = report_with_findings(vec![finding_with_details(
            "CUSTOM001",
            Severity::Medium,
            FindingCategory::Quality,
            "Custom explanation",
            "Custom finding message.",
            "skills/custom/SKILL.md",
            Some(4),
            "Explain why the custom finding matters.",
            "Explain how to fix the custom finding.",
            "Explain how to suppress the custom finding safely.",
        )]);

        let json = render_json(&report).expect("render JSON");
        let value: Value = serde_json::from_str(&json).expect("parse JSON report");
        let finding = &value["findings"][0];

        assert_eq!(
            finding["rationale"],
            "Explain why the custom finding matters."
        );
        assert_eq!(
            finding["remediation"],
            "Explain how to fix the custom finding."
        );
        assert_eq!(
            finding["suppression"],
            "Explain how to suppress the custom finding safely."
        );

        let html = render_html(&report);

        assert!(html.contains("Explain why the custom finding matters."));
        assert!(html.contains("Explain how to fix the custom finding."));
        assert!(html.contains("Explain how to suppress the custom finding safely."));
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
    fn html_output_renders_all_summary_counts() {
        let report = report_with_summary(2, 3, 4, 1, 2);

        let html = render_html(&report);

        assert!(html.contains("<span class=\"count\">2</span>Packages"));
        assert!(html.contains("<span class=\"count\">3</span>Findings"));
        assert!(html.contains("<span class=\"count\">4</span>Suppressed findings"));
        assert!(html.contains("<span class=\"count\">1</span>Invalid manifests"));
        assert!(html.contains("<span class=\"count\">2</span>Broken references"));
    }

    #[test]
    fn html_output_escapes_every_untrusted_column() {
        let report = report_with_packages_and_findings(
            vec![package(
                "skills/<root>",
                "skills/<manifest>/SKILL.md",
                Some("<name>"),
                Some("\"description\" & 'summary'"),
            )],
            vec![finding_with_details(
                "SEC<001>",
                Severity::High,
                FindingCategory::Security,
                "<x-title>",
                "</td><script>alert('message')</script>",
                "skills/<finding>/SKILL.md",
                Some(7),
                "\"rationale\" & 'risk'",
                "<remediation>",
                "</td><img src=x>",
            )],
        );

        let html = render_html(&report);

        assert!(html.contains("skills/&lt;root&gt;"));
        assert!(html.contains("skills/&lt;manifest&gt;/SKILL.md"));
        assert!(html.contains("&lt;name&gt;"));
        assert!(html.contains("&quot;description&quot; &amp; &#39;summary&#39;"));
        assert!(html.contains("SEC&lt;001&gt;"));
        assert!(html.contains("skills/&lt;finding&gt;/SKILL.md:7"));
        assert!(html.contains("&lt;x-title&gt;"));
        assert!(html.contains("&lt;/td&gt;&lt;script&gt;alert(&#39;message&#39;)&lt;/script&gt;"));
        assert!(html.contains("&quot;rationale&quot; &amp; &#39;risk&#39;"));
        assert!(html.contains("&lt;remediation&gt;"));
        assert!(html.contains("&lt;/td&gt;&lt;img src=x&gt;"));

        for raw in [
            "skills/<root>",
            "skills/<manifest>/SKILL.md",
            "<name>",
            "\"description\" & 'summary'",
            "SEC<001>",
            "skills/<finding>/SKILL.md:7",
            "<x-title>",
            "</td><script>alert('message')</script>",
            "\"rationale\" & 'risk'",
            "<remediation>",
            "</td><img src=x>",
        ] {
            assert!(
                !html.contains(raw),
                "raw dangerous value was rendered: {raw}"
            );
        }
    }

    #[test]
    fn html_output_renders_missing_optional_package_fields_as_empty_cells() {
        let report = report_with_packages_and_findings(
            vec![package("skills/empty", "skills/empty/SKILL.md", None, None)],
            Vec::new(),
        );

        let html = render_html(&report);

        assert!(html.contains(
            "<tr><td></td><td></td><td>skills/empty/SKILL.md</td><td>skills/empty</td></tr>"
        ));
        assert!(!html.contains("None"));
        assert!(!html.contains("Some("));
        assert!(!html.contains("null"));
    }

    #[test]
    fn html_output_orders_findings_by_path_line_rule_id_then_message() {
        let report = report_with_findings(vec![
            finding(
                "SKILL200",
                Severity::Low,
                FindingCategory::Spec,
                "Ordering marker",
                "marker-05 line 2 sorts last.",
                "skills/order/SKILL.md",
                Some(2),
            ),
            finding(
                "SKILL010",
                Severity::Low,
                FindingCategory::Spec,
                "Ordering marker",
                "marker-03 same rule second message.",
                "skills/order/SKILL.md",
                Some(1),
            ),
            finding(
                "SKILL999",
                Severity::Low,
                FindingCategory::Spec,
                "Ordering marker",
                "marker-01 no line sorts first.",
                "skills/order/SKILL.md",
                None,
            ),
            finding(
                "SKILL020",
                Severity::Low,
                FindingCategory::Spec,
                "Ordering marker",
                "marker-04 same line later rule.",
                "skills/order/SKILL.md",
                Some(1),
            ),
            finding(
                "SKILL010",
                Severity::Low,
                FindingCategory::Spec,
                "Ordering marker",
                "marker-02 same rule first message.",
                "skills/order/SKILL.md",
                Some(1),
            ),
        ]);

        let html = render_html(&report);

        assert_in_order(
            &html,
            &[
                "marker-01",
                "marker-02",
                "marker-03",
                "marker-04",
                "marker-05",
            ],
        );
    }

    #[test]
    fn html_output_uses_only_self_contained_markup() {
        let report = report_with_packages_and_findings(
            vec![package(
                "skills/review",
                "skills/review/SKILL.md",
                Some("review"),
                Some("Review skills."),
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

        let html = render_html(&report);

        for forbidden in [
            "src=",
            "href=",
            "@import",
            "url(",
            "integrity=",
            "crossorigin=",
            "http://",
            "https://",
        ] {
            assert!(
                !html.contains(forbidden),
                "HTML should not contain external markup token {forbidden:?}"
            );
        }
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
    fn sarif_output_uses_only_unsuppressed_findings() {
        let mut report = report_with_findings(vec![finding(
            "SKILL002",
            Severity::Low,
            FindingCategory::Spec,
            "Missing skill description",
            "The skill manifest does not declare a description.",
            "SKILL.md",
            Some(1),
        )]);
        report.suppressed_findings = vec![SuppressedFinding {
            finding: finding(
                "SKILL001",
                Severity::Low,
                FindingCategory::Spec,
                "Missing skill name",
                "The skill manifest does not declare a name.",
                "SKILL.md",
                Some(1),
            ),
            suppression: SuppressionMatch {
                matched_rule: "SKILL001".to_owned(),
                matched_path: "SKILL.md".to_owned(),
                reason: "Accepted fixture.".to_owned(),
            },
        }];
        report.summary.suppressed_finding_count = 1;

        let value = render_sarif_value(&report);

        assert_eq!(sarif_rule_ids(&value), vec!["SKILL002"]);
        assert_eq!(
            value["runs"][0]["results"]
                .as_array()
                .expect("results array")
                .len(),
            1
        );
        assert_eq!(value["runs"][0]["results"][0]["ruleId"], "SKILL002");
    }

    #[test]
    fn sarif_rule_descriptor_for_known_rule_comes_from_registry() {
        let report = report_with_findings(vec![finding_with_details(
            "SKILL001",
            Severity::High,
            FindingCategory::Security,
            "Conflicting finding title",
            "Finding-specific message stays on the result.",
            "skills/conflict/SKILL.md",
            Some(9),
            "Conflicting finding rationale.",
            "Conflicting finding remediation.",
            "Conflicting finding suppression.",
        )]);

        let value = render_sarif_value(&report);
        let rule = &value["runs"][0]["tool"]["driver"]["rules"][0];
        let result = &value["runs"][0]["results"][0];

        assert_eq!(rule["id"], "SKILL001");
        assert_eq!(rule["name"], "Missing skill name");
        assert_eq!(rule["shortDescription"]["text"], "Missing skill name");
        assert_eq!(
            rule["fullDescription"]["text"],
            "Skills without stable names are hard to inventory and compare across hosts."
        );
        assert_eq!(
            rule["help"]["text"],
            "Add a non-empty `name` field to frontmatter or a clear top-level heading.\n\nSuppress `SKILL001` only with a documented reason in the project audit config."
        );
        assert_eq!(rule["defaultConfiguration"]["level"], "warning");
        assert_eq!(rule["properties"]["agentAuditSeverity"], "low");
        assert_eq!(rule["properties"]["category"], "spec");

        assert_eq!(result["ruleId"], "SKILL001");
        assert_eq!(
            result["message"]["text"],
            "Finding-specific message stays on the result."
        );
        assert_eq!(result["level"], "error");
        assert_eq!(result["properties"]["agentAuditSeverity"], "high");
        assert_eq!(result["properties"]["category"], "security");
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
    fn sarif_output_falls_back_to_finding_metadata_for_unknown_rule_descriptor() {
        let report = report_with_findings(vec![finding_with_details(
            "CUSTOM900",
            Severity::Critical,
            FindingCategory::Reproducibility,
            "Custom reproducibility rule",
            "The custom rule produced a finding.",
            "custom/SKILL.md",
            Some(3),
            "Custom rationale.",
            "Custom remediation.",
            "Custom suppression.",
        )]);

        let value = render_sarif_value(&report);
        let rule = &value["runs"][0]["tool"]["driver"]["rules"][0];

        assert_eq!(rule["id"], "CUSTOM900");
        assert_eq!(rule["name"], "Custom reproducibility rule");
        assert_eq!(
            rule["shortDescription"]["text"],
            "Custom reproducibility rule"
        );
        assert_eq!(rule["fullDescription"]["text"], "Custom rationale.");
        assert_eq!(
            rule["help"]["text"],
            "Custom remediation.\n\nCustom suppression."
        );
        assert_eq!(rule["defaultConfiguration"]["level"], "error");
        assert_eq!(rule["properties"]["agentAuditSeverity"], "critical");
        assert_eq!(rule["properties"]["category"], "reproducibility");
    }

    #[test]
    fn sarif_output_falls_back_to_finding_metadata_for_reserved_rule_descriptor() {
        let report = report_with_findings(vec![finding_with_details(
            "SKILL050",
            Severity::Medium,
            FindingCategory::Portability,
            "Synthetic host metadata issue",
            "The synthetic reserved rule produced a finding.",
            "reserved/SKILL.md",
            Some(5),
            "Synthetic rationale.",
            "Synthetic remediation.",
            "Synthetic suppression.",
        )]);

        let value = render_sarif_value(&report);
        let rule = &value["runs"][0]["tool"]["driver"]["rules"][0];

        assert_eq!(rule["id"], "SKILL050");
        assert_eq!(rule["name"], "Synthetic host metadata issue");
        assert_eq!(
            rule["shortDescription"]["text"],
            "Synthetic host metadata issue"
        );
        assert_eq!(rule["fullDescription"]["text"], "Synthetic rationale.");
        assert_eq!(
            rule["help"]["text"],
            "Synthetic remediation.\n\nSynthetic suppression."
        );
        assert_eq!(rule["defaultConfiguration"]["level"], "warning");
        assert_eq!(rule["properties"]["agentAuditSeverity"], "medium");
        assert_eq!(rule["properties"]["category"], "portability");
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
    fn sarif_output_uses_deterministic_rule_indexes_for_known_and_unknown_rules() {
        let report = report_with_findings(vec![
            finding(
                "SKILL020",
                Severity::Low,
                FindingCategory::Spec,
                "Conflicting oversized title",
                "Known rule later in descriptor order.",
                "c/SKILL.md",
                Some(1),
            ),
            finding(
                "CUSTOM900",
                Severity::Medium,
                FindingCategory::Quality,
                "Custom rule",
                "Unknown rule sorts first.",
                "a/SKILL.md",
                Some(1),
            ),
            finding(
                "SKILL001",
                Severity::High,
                FindingCategory::Security,
                "Conflicting missing-name title",
                "Known rule sorts between custom and SKILL020.",
                "b/SKILL.md",
                Some(1),
            ),
        ]);

        let value = render_sarif_value(&report);

        assert_eq!(
            sarif_rule_ids(&value),
            vec!["CUSTOM900", "SKILL001", "SKILL020"]
        );
        assert_eq!(
            sarif_result_rule_indexes(&value),
            vec![("CUSTOM900", 0), ("SKILL001", 1), ("SKILL020", 2),]
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

    fn report_with_summary(
        package_count: usize,
        finding_count: usize,
        suppressed_finding_count: usize,
        invalid_manifest_count: usize,
        broken_reference_count: usize,
    ) -> ScanReport {
        ScanReport {
            packages: Vec::new(),
            summary: ScanSummary {
                package_count,
                finding_count,
                suppressed_finding_count,
                invalid_manifest_count,
                broken_reference_count,
            },
            findings: Vec::new(),
            suppressed_findings: Vec::new(),
        }
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
                suppressed_finding_count: 0,
                invalid_manifest_count: 0,
                broken_reference_count: findings
                    .iter()
                    .filter(|finding| finding.rule_id == "SKILL010")
                    .count(),
            },
            findings,
            suppressed_findings: Vec::new(),
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

    fn finding_with_details(
        rule_id: &str,
        severity: Severity,
        category: FindingCategory,
        title: &str,
        message: &str,
        path: &str,
        line: Option<usize>,
        rationale: &str,
        remediation: &str,
        suppression: &str,
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
            rationale: rationale.to_owned(),
            remediation: remediation.to_owned(),
            suppression: suppression.to_owned(),
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
