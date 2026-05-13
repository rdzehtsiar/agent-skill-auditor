// SPDX-License-Identifier: Apache-2.0

use std::borrow::Cow;
use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt;
use std::str::FromStr;

use agent_audit_core::model::AuditMetadata;
use agent_audit_core::{
    build_ecosystem_patterns, build_finding_groups, CompatibilityMatrix,
    DependencyManifestPinningKind, EcosystemPattern, ExternalUrl, FindingCategory,
    FindingConfidence, FindingGroup, OfflineReadinessStatus, PermissionEvidence, PermissionKind,
    ScanReport, Severity, SkillCompatibilityRow, SkillFinding, SkillPackage, SupplyChainInventory,
    SupplyChainSourceKind,
};
use agent_audit_rules::{active_rule_metadata, RuleMetadata, RuleSeverity};
use serde_json::{json, Value};

pub const SUPPORTED_REPORT_FORMATS: &[&str] = &["summary", "json", "public-json", "sarif", "html"];
pub const SUPPORTED_REPORT_FORMATS_HELP: &str =
    "supported: summary, json, public-json, sarif, html";
pub const SUPPORTED_REPORT_MODES: &[&str] = &["default", "verbose", "research", "ci"];
pub const SUPPORTED_REPORT_MODES_HELP: &str = "supported: default, verbose, research, ci";
const SUMMARY_COMPATIBILITY_ROW_LIMIT: usize = 5;
const CI_TOP_GROUP_LIMIT: usize = 5;
const PUBLIC_DATASET_SNIPPET_LIMIT: usize = 240;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReportFormat {
    Summary,
    Json,
    PublicJson,
    Sarif,
    Html,
}

impl ReportFormat {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Summary => "summary",
            Self::Json => "json",
            Self::PublicJson => "public-json",
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
            "public-json" => Ok(Self::PublicJson),
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReportMode {
    Default,
    Verbose,
    Research,
    Ci,
}

impl ReportMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Default => "default",
            Self::Verbose => "verbose",
            Self::Research => "research",
            Self::Ci => "ci",
        }
    }
}

impl FromStr for ReportMode {
    type Err = UnsupportedReportMode;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "default" => Ok(Self::Default),
            "verbose" => Ok(Self::Verbose),
            "research" => Ok(Self::Research),
            "ci" => Ok(Self::Ci),
            _ => Err(UnsupportedReportMode {
                value: value.to_owned(),
            }),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnsupportedReportMode {
    value: String,
}

impl UnsupportedReportMode {
    pub fn value(&self) -> &str {
        &self.value
    }
}

impl fmt::Display for UnsupportedReportMode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "unsupported report mode '{}' ({})",
            self.value, SUPPORTED_REPORT_MODES_HELP
        )
    }
}

impl Error for UnsupportedReportMode {}

pub fn render_report(report: &ScanReport, format: ReportFormat) -> serde_json::Result<String> {
    render_report_with_mode(report, format, ReportMode::Default)
}

pub fn render_report_with_mode(
    report: &ScanReport,
    format: ReportFormat,
    mode: ReportMode,
) -> serde_json::Result<String> {
    let rendered = match format {
        ReportFormat::Summary => render_summary_with_mode(report, mode),
        ReportFormat::Json => render_json(report)?,
        ReportFormat::PublicJson => render_public_json(report)?,
        ReportFormat::Sarif => render_sarif(report)?,
        ReportFormat::Html => render_html_with_mode(report, mode),
    };

    Ok(with_trailing_newline(rendered))
}

pub fn render_summary(report: &ScanReport) -> String {
    render_summary_with_mode(report, ReportMode::Default)
}

pub fn render_summary_with_mode(report: &ScanReport, mode: ReportMode) -> String {
    match mode {
        ReportMode::Default => render_default_summary(report),
        ReportMode::Verbose => render_verbose_summary(report),
        ReportMode::Research => render_research_summary(report),
        ReportMode::Ci => render_ci_summary(report),
    }
}

fn render_default_summary(report: &ScanReport) -> String {
    let mut lines = vec![
        "Agent Skill Auditor scan summary".to_owned(),
        audit_metadata_summary(&report.audit),
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
        format!(
            "Actual secret evidence: {}",
            report.summary.actual_secret_evidence_count
        ),
        format!(
            "Prompt secret exposure signals: {}",
            report.summary.prompt_secret_exposure_count
        ),
    ];

    extend_supply_chain_summary(&mut lines, report);
    extend_compatibility_summary(&mut lines, &report.compatibility);
    extend_ecosystem_patterns_summary(&mut lines, report);

    let finding_groups = effective_finding_groups(report);
    if finding_groups.is_empty() {
        lines.push(String::new());
        lines.push("No findings.".to_owned());
    } else {
        lines.push(String::new());
        lines.push("Finding groups:".to_owned());

        for group in finding_groups.iter() {
            lines.push(format!(
                "{} [{}/{}/{}] x{} packages={}{}: {} fingerprint={}",
                group.rule_id,
                severity_name(group.severity),
                confidence_name(group.confidence),
                category_name(group.category),
                group.finding_count,
                group.affected_package_count,
                summary_group_dimensions(group),
                group.title,
                group.group_fingerprint
            ));
            for sample in &group.evidence_samples {
                lines.push(format!(
                    "  sample: {}: {}",
                    location_display(&sample.location.path, sample.location.line),
                    sample.message
                ));
            }
        }
    }

    lines.join("\n")
}

fn render_verbose_summary(report: &ScanReport) -> String {
    let mut lines = summary_header("Agent Skill Auditor verbose scan summary", report);

    extend_supply_chain_summary(&mut lines, report);
    extend_compatibility_summary(&mut lines, &report.compatibility);
    extend_ecosystem_patterns_summary(&mut lines, report);
    extend_full_findings_summary(&mut lines, report, false);

    lines.join("\n")
}

fn render_research_summary(report: &ScanReport) -> String {
    let mut lines = summary_header("Agent Skill Auditor research scan summary", report);

    extend_supply_chain_summary(&mut lines, report);
    extend_compatibility_summary(&mut lines, &report.compatibility);
    extend_ecosystem_patterns_summary(&mut lines, report);
    extend_research_finding_groups_summary(&mut lines, report);
    extend_full_findings_summary(&mut lines, report, true);

    lines.join("\n")
}

fn render_ci_summary(report: &ScanReport) -> String {
    let severity_counts = severity_counts(&report.findings);
    let category_counts = category_counts(&report.findings);
    let compatibility_counts = compatibility_status_counts(&report.compatibility);
    let readiness_counts = offline_readiness_counts(&report.supply_chain);
    let finding_groups = effective_finding_groups(report);
    let top_groups = ci_top_finding_groups(finding_groups.as_ref());

    let mut lines = summary_header("Agent Skill Auditor CI scan summary", report);
    lines.push(format!(
        "Severity totals: critical={} high={} medium={} low={} info={}",
        severity_counts.critical,
        severity_counts.high,
        severity_counts.medium,
        severity_counts.low,
        severity_counts.info
    ));
    lines.push(format!(
        "Category totals: spec={} compatibility={} security={} quality={} portability={} reproducibility={}",
        category_counts.spec,
        category_counts.compatibility,
        category_counts.security,
        category_counts.quality,
        category_counts.portability,
        category_counts.reproducibility
    ));
    if !report.compatibility.is_empty() {
        lines.push(format!(
            "Compatibility totals: pass={} warn={} fail={} unknown={} untested={}",
            compatibility_counts.pass,
            compatibility_counts.warn,
            compatibility_counts.fail,
            compatibility_counts.unknown,
            compatibility_counts.untested
        ));
    }
    lines.push(format!(
        "Offline audit readiness: ready={} partial={} not-ready={} unknown={}",
        readiness_counts.ready,
        readiness_counts.partial,
        readiness_counts.not_ready,
        readiness_counts.unknown
    ));

    if top_groups.is_empty() {
        lines.push("Top finding groups: none".to_owned());
    } else {
        lines.push(format!(
            "Top finding groups: showing {} of {} canonical groups (filtered for CI log size).",
            top_groups.len(),
            finding_groups.len()
        ));
        for group in top_groups {
            lines.push(format!(
                "{} [{}/{}/{}] x{} packages={}: {} fingerprint={}",
                group.rule_id,
                severity_name(group.severity),
                confidence_name(group.confidence),
                category_name(group.category),
                group.finding_count,
                group.affected_package_count,
                group.title,
                group.group_fingerprint
            ));
        }
    }

    lines.join("\n")
}

fn summary_header(title: &str, report: &ScanReport) -> Vec<String> {
    vec![
        title.to_owned(),
        audit_metadata_summary(&report.audit),
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
        format!(
            "Actual secret evidence: {}",
            report.summary.actual_secret_evidence_count
        ),
        format!(
            "Prompt secret exposure signals: {}",
            report.summary.prompt_secret_exposure_count
        ),
    ]
}

fn audit_metadata_summary(audit: &AuditMetadata) -> String {
    let profiles = if audit.host_profiles.selected.is_empty() {
        "none".to_owned()
    } else {
        audit.host_profiles.selected.join(",")
    };
    let mut parts = vec![
        format!("schema={}", audit.output_schema_version),
        format!("scanner={}/{}", audit.scanner.name, audit.scanner.version),
        format!("ruleset={}({})", audit.ruleset.version, audit.ruleset.hash),
        format!("profiles={profiles}"),
        format!(
            "scan_root={}",
            audit.scan.root.as_deref().unwrap_or("unspecified")
        ),
        format!("timestamp={}", audit.timestamp.as_deref().unwrap_or("null")),
    ];

    if let Some(path) = audit.config.path.as_deref() {
        parts.push(format!("config={path}"));
    }
    if let Some(hash) = audit.config.hash.as_deref() {
        parts.push(format!("config_hash={hash}"));
    }
    if let Some(platform) = audit.platform.as_ref() {
        parts.push(format!(
            "platform={}/{}/{}",
            platform.family, platform.os, platform.arch
        ));
    }
    if let Some(repository) = audit.repository.as_ref() {
        if let Some(commit) = repository.commit.as_deref() {
            parts.push(format!("commit={}", short_commit(commit)));
        }
        if let Some(dirty) = repository.dirty {
            parts.push(format!("dirty={dirty}"));
        }
    }

    format!("Audit: {}", parts.join(" "))
}

fn short_commit(commit: &str) -> &str {
    commit.get(..12).unwrap_or(commit)
}

fn extend_research_finding_groups_summary(lines: &mut Vec<String>, report: &ScanReport) {
    let finding_groups = effective_finding_groups(report);

    if finding_groups.is_empty() {
        lines.push(String::new());
        lines.push("Finding groups: none".to_owned());
        return;
    }

    lines.push(String::new());
    lines.push("Finding groups:".to_owned());
    for group in finding_groups.iter() {
        lines.push(format!(
            "{} group_fingerprint={} confidence={} normalized_key={} evidence_key={} dimensions={} count={} affected_packages={}: {}",
            group.rule_id,
            group.group_fingerprint,
            confidence_name(group.confidence),
            finding_group_normalized_key(group),
            group.evidence_key,
            summary_group_dimensions(group),
            group.finding_count,
            group.affected_package_count,
            group.title
        ));
        for sample in &group.evidence_samples {
            lines.push(format!(
                "  evidence_sample: {}: {}",
                location_display(&sample.location.path, sample.location.line),
                sample.message
            ));
        }
    }
}

fn extend_full_findings_summary(
    lines: &mut Vec<String>,
    report: &ScanReport,
    include_research_keys: bool,
) {
    let findings = sorted_findings(&report.findings);

    lines.push(String::new());
    if findings.is_empty() {
        lines.push("Full findings: none".to_owned());
        return;
    }

    lines.push("Full findings:".to_owned());
    for finding in findings {
        lines.push(format!(
            "{} [{}/{}/{}] {}: {}",
            finding.rule_id,
            severity_name(finding.severity),
            confidence_name(finding.confidence),
            category_name(finding.category),
            location_display(&finding.location.path, finding.location.line),
            finding.title
        ));
        if include_research_keys {
            lines.push(format!(
                "  normalized_key: {}",
                finding_normalized_key(finding)
            ));
        }
        lines.push(format!("  message: {}", finding.message));
        lines.push(format!("  why: {}", finding.rationale));
        lines.push(format!("  fix: {}", finding.remediation));
        lines.push(format!("  suppress: {}", finding.suppression));
    }
}

fn summary_group_dimensions(group: &FindingGroup) -> String {
    if group.dimensions.is_empty() {
        return format!(" evidence={}", group.evidence_key);
    }

    format!(
        " {}",
        group
            .dimensions
            .iter()
            .map(|(key, value)| format!("{key}={value}"))
            .collect::<Vec<_>>()
            .join(" ")
    )
}

fn extend_supply_chain_summary(lines: &mut Vec<String>, report: &ScanReport) {
    let supply_chain = &report.supply_chain;
    let finding_counts = supply_chain_finding_counts(&report.findings);
    let readiness_counts = offline_readiness_counts(supply_chain);
    let manifest_counts = dependency_manifest_counts(supply_chain);
    let install_command_count = install_command_count(supply_chain);

    lines.push(String::new());
    lines.push("Supply chain:".to_owned());
    lines.push(format!(
        "Licenses: {} evidence",
        supply_chain.licenses.len()
    ));
    lines.push(format!(
        "Trust manifests: {} total, {} invalid",
        supply_chain.trust_manifests.len(),
        supply_chain
            .trust_manifests
            .iter()
            .filter(|manifest| manifest.valid == Some(false))
            .count()
    ));
    lines.push(format!(
        "External URLs: {} total, {} mutable",
        supply_chain.external_urls.len(),
        supply_chain
            .external_urls
            .iter()
            .filter(|url| url.pinned == Some(false))
            .count()
    ));
    lines.push(format!(
        "Dependencies: {} observed, {} unpinned",
        supply_chain.remote_dependencies.len(),
        supply_chain
            .remote_dependencies
            .iter()
            .filter(|dependency| dependency.pinned == Some(false))
            .count()
    ));
    lines.push(format!(
        "Dependency manifests: {} total, {} exact-pinned, {} range-based",
        manifest_counts.total, manifest_counts.exact_pinned, manifest_counts.range_based
    ));
    lines.push(format!(
        "Lockfiles: {} evidence",
        supply_chain.lockfiles.len()
    ));
    lines.push(format!(
        "Install commands: {} observed, {} without reproducibility evidence",
        install_command_count, finding_counts.install_without_reproducibility_evidence
    ));
    lines.push(format!(
        "Executables: {} evidence",
        supply_chain.executables.len()
    ));
    lines.push(format!(
        "Binaries: {} evidence",
        supply_chain.binaries.len()
    ));
    lines.push(format!(
        "Checksums: {} evidence",
        supply_chain.checksums.len()
    ));
    lines.push(format!(
        "Permissions: {} evidence, {} conflicts",
        supply_chain.permissions.len(),
        finding_counts.permission_conflicts
    ));
    lines.push(format!(
        "Offline audit readiness: ready={} partial={} not-ready={} unknown={}",
        readiness_counts.ready,
        readiness_counts.partial,
        readiness_counts.not_ready,
        readiness_counts.unknown
    ));
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
struct DependencyManifestCounts {
    total: usize,
    exact_pinned: usize,
    range_based: usize,
}

fn dependency_manifest_counts(supply_chain: &SupplyChainInventory) -> DependencyManifestCounts {
    let mut counts = DependencyManifestCounts {
        total: supply_chain.dependency_manifests.len(),
        ..DependencyManifestCounts::default()
    };

    for manifest in &supply_chain.dependency_manifests {
        match manifest.pinning {
            DependencyManifestPinningKind::ExactPinned => counts.exact_pinned += 1,
            DependencyManifestPinningKind::RangeBased => counts.range_based += 1,
            DependencyManifestPinningKind::Unknown => {}
        }
    }

    counts
}

fn install_command_count(supply_chain: &SupplyChainInventory) -> usize {
    supply_chain
        .package_managers
        .iter()
        .filter(|manager| manager.source == SupplyChainSourceKind::Script)
        .count()
}

#[derive(Default)]
struct SupplyChainFindingCounts {
    install_without_reproducibility_evidence: usize,
    permission_conflicts: usize,
}

fn supply_chain_finding_counts(findings: &[SkillFinding]) -> SupplyChainFindingCounts {
    let mut counts = SupplyChainFindingCounts::default();

    for finding in findings {
        match finding.rule_id.as_str() {
            "SUPPLY003" => counts.install_without_reproducibility_evidence += 1,
            "SUPPLY009" => counts.permission_conflicts += 1,
            _ => {}
        }
    }

    counts
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
struct OfflineReadinessCounts {
    ready: usize,
    partial: usize,
    not_ready: usize,
    unknown: usize,
}

fn offline_readiness_counts(supply_chain: &SupplyChainInventory) -> OfflineReadinessCounts {
    let mut counts = OfflineReadinessCounts::default();

    for readiness in &supply_chain.offline_readiness {
        match readiness.status {
            OfflineReadinessStatus::Ready => counts.ready += 1,
            OfflineReadinessStatus::Partial => counts.partial += 1,
            OfflineReadinessStatus::NotReady => counts.not_ready += 1,
            OfflineReadinessStatus::Unknown => counts.unknown += 1,
        }
    }

    counts
}

fn extend_compatibility_summary(lines: &mut Vec<String>, compatibility: &CompatibilityMatrix) {
    if compatibility.is_empty() {
        return;
    }

    let counts = compatibility_status_counts(compatibility);
    lines.push(String::new());
    lines.push("Compatibility:".to_owned());
    lines.push(format!("Profiles: {}", compatibility.profiles.join(", ")));
    lines.push(format!(
        "Status totals: pass={} warn={} fail={} unknown={} untested={}",
        counts.pass, counts.warn, counts.fail, counts.unknown, counts.untested
    ));
    lines.push("Profile totals:".to_owned());
    for profile in &compatibility.profiles {
        let counts = compatibility_status_counts_for_profile(compatibility, profile);
        lines.push(format!(
            "- {}: pass={} warn={} fail={} unknown={} untested={}",
            profile, counts.pass, counts.warn, counts.fail, counts.unknown, counts.untested
        ));
    }

    if compatibility.matrix.is_empty() {
        return;
    }

    if compatibility.matrix.len() > SUMMARY_COMPATIBILITY_ROW_LIMIT {
        lines.push(format!(
            "Rows: {} packages omitted from summary",
            compatibility.matrix.len()
        ));
        return;
    }

    lines.push("Rows:".to_owned());
    for row in &compatibility.matrix {
        let name = row
            .name
            .as_deref()
            .map(|name| format!(" ({name})"))
            .unwrap_or_default();
        let profile_statuses = row
            .profiles
            .iter()
            .map(|profile| {
                let mut status = format!("{}={}", profile.profile, profile.status.as_str());
                if !profile.finding_ids.is_empty() {
                    status.push('(');
                    status.push_str(&profile.finding_ids.join(","));
                    status.push(')');
                }
                status
            })
            .collect::<Vec<_>>()
            .join(", ");
        lines.push(format!("- {}{}: {}", row.path, name, profile_statuses));
    }
}

fn extend_ecosystem_patterns_summary(lines: &mut Vec<String>, report: &ScanReport) {
    let patterns = effective_ecosystem_patterns(report);
    if patterns.is_empty() {
        return;
    }

    lines.push(String::new());
    lines.push("Observed ecosystem patterns:".to_owned());
    for pattern in patterns.iter() {
        lines.push(format!(
            "- {}: {} count={} packages={}%",
            pattern.title, pattern.summary, pattern.count, pattern.affected_package_percent
        ));
    }
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
struct CompatibilityStatusCounts {
    pass: usize,
    warn: usize,
    fail: usize,
    unknown: usize,
    untested: usize,
}

fn compatibility_status_counts(compatibility: &CompatibilityMatrix) -> CompatibilityStatusCounts {
    let mut counts = CompatibilityStatusCounts::default();

    for row in &compatibility.matrix {
        for profile in &row.profiles {
            add_compatibility_status_count(&mut counts, profile.status.as_str());
        }
    }

    counts
}

fn compatibility_status_counts_for_profile(
    compatibility: &CompatibilityMatrix,
    profile_id: &str,
) -> CompatibilityStatusCounts {
    let mut counts = CompatibilityStatusCounts::default();

    for row in &compatibility.matrix {
        for profile in &row.profiles {
            if profile.profile == profile_id {
                add_compatibility_status_count(&mut counts, profile.status.as_str());
            }
        }
    }

    counts
}

fn add_compatibility_status_count(counts: &mut CompatibilityStatusCounts, status: &str) {
    match status {
        "pass" => counts.pass += 1,
        "warn" => counts.warn += 1,
        "fail" => counts.fail += 1,
        "unknown" => counts.unknown += 1,
        "untested" => counts.untested += 1,
        _ => counts.unknown += 1,
    }
}

pub fn render_json(report: &ScanReport) -> serde_json::Result<String> {
    serde_json::to_string_pretty(report)
}

pub fn render_public_json(report: &ScanReport) -> serde_json::Result<String> {
    serde_json::to_string_pretty(&public_dataset_value(report))
}

fn public_dataset_value(report: &ScanReport) -> Value {
    json!({
        "audit": &report.audit,
        "repository": &report.audit.repository,
        "packages": public_packages(report),
        "findings": public_findings(report),
        "finding_groups": public_finding_groups(report),
        "metrics": public_metrics(report),
        "patterns": &report.patterns,
        "supply_chain": public_supply_chain(report),
    })
}

fn public_packages(report: &ScanReport) -> Vec<Value> {
    report
        .packages
        .iter()
        .map(|package| {
            let frontmatter_keys = package.manifest.frontmatter.keys().collect::<Vec<_>>();
            json!({
                "root": &package.root,
                "manifest_path": &package.manifest_path,
                "name": &package.manifest.name,
                "description": &package.manifest.description,
                "frontmatter_keys": frontmatter_keys,
                "headings": &package.manifest.headings,
                "links": &package.manifest.links,
                "declared_tools": &package.manifest.declared_tools,
                "declared_permissions": &package.manifest.declared_permissions,
                "graph": &package.graph,
            })
        })
        .collect()
}

fn public_findings(report: &ScanReport) -> Vec<Value> {
    report
        .findings
        .iter()
        .map(|finding| {
            json!({
                "rule_id": &finding.rule_id,
                "fingerprint": &finding.fingerprint,
                "severity": finding.severity,
                "confidence": finding.confidence,
                "category": finding.category,
                "title": &finding.title,
                "message": public_snippet(&finding.message),
                "location": &finding.location,
                "rationale": public_snippet(&finding.rationale),
                "remediation": public_snippet(&finding.remediation),
                "suppression": public_snippet(&finding.suppression),
                "evidence_snippet": public_snippet(&finding.message),
            })
        })
        .collect()
}

fn public_finding_groups(report: &ScanReport) -> Vec<Value> {
    effective_finding_groups(report)
        .iter()
        .map(|group| {
            let evidence_samples = group
                .evidence_samples
                .iter()
                .map(|sample| {
                    json!({
                        "location": &sample.location,
                        "message": public_snippet(&sample.message),
                    })
                })
                .collect::<Vec<_>>();

            json!({
                "rule_id": &group.rule_id,
                "group_fingerprint": &group.group_fingerprint,
                "severity": group.severity,
                "confidence": group.confidence,
                "category": group.category,
                "title": &group.title,
                "rationale": public_snippet(&group.rationale),
                "remediation": public_snippet(&group.remediation),
                "suppression": public_snippet(&group.suppression),
                "evidence_key": public_snippet(&group.evidence_key),
                "dimensions": &group.dimensions,
                "finding_count": group.finding_count,
                "affected_package_count": group.affected_package_count,
                "affected_packages": &group.affected_packages,
                "evidence_samples": evidence_samples,
            })
        })
        .collect()
}

fn public_metrics(report: &ScanReport) -> Value {
    json!({
        "summary": &report.summary,
        "supply_chain_counts": {
            "licenses": report.supply_chain.licenses.len(),
            "trust_manifests": report.supply_chain.trust_manifests.len(),
            "external_urls": report.supply_chain.external_urls.len(),
            "remote_dependencies": report.supply_chain.remote_dependencies.len(),
            "dependency_manifests": report.supply_chain.dependency_manifests.len(),
            "package_managers": report.supply_chain.package_managers.len(),
            "lockfiles": report.supply_chain.lockfiles.len(),
            "executables": report.supply_chain.executables.len(),
            "binaries": report.supply_chain.binaries.len(),
            "checksums": report.supply_chain.checksums.len(),
            "permissions": report.supply_chain.permissions.len(),
            "offline_readiness": report.supply_chain.offline_readiness.len(),
        }
    })
}

fn public_supply_chain(report: &ScanReport) -> Value {
    let value =
        serde_json::to_value(&report.supply_chain).expect("serialize supply-chain inventory");
    redact_public_json_value(value)
}

fn redact_public_json_value(value: Value) -> Value {
    match value {
        Value::String(text) => Value::String(public_snippet(&text)),
        Value::Array(values) => {
            Value::Array(values.into_iter().map(redact_public_json_value).collect())
        }
        Value::Object(entries) => Value::Object(
            entries
                .into_iter()
                .map(|(key, value)| (key, redact_public_json_value(value)))
                .collect(),
        ),
        other => other,
    }
}

fn public_snippet(value: &str) -> String {
    let mut chars = value.chars();
    let snippet = chars
        .by_ref()
        .take(PUBLIC_DATASET_SNIPPET_LIMIT)
        .collect::<String>();

    if chars.next().is_some() {
        format!("{snippet}... [truncated]")
    } else {
        snippet
    }
}

pub fn render_html(report: &ScanReport) -> String {
    render_html_with_mode(report, ReportMode::Default)
}

pub fn render_html_with_mode(report: &ScanReport, mode: ReportMode) -> String {
    let view_model = HtmlReportViewModel::from_report(report);
    let mut html = String::from(
        r#"<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Agent Skill Auditor Report</title>
<style>
:root{color-scheme:light;--text:#17202a;--muted:#52616f;--border:#d8e0e8;--soft:#f5f7fa;--head:#edf2f7;--critical:#7f1d1d;--high:#9a3412;--medium:#854d0e;--low:#1d4ed8;--info:#475569;--pass:#166534;--warn:#92400e;--fail:#991b1b;--unknown:#475569}
body{font-family:system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;line-height:1.5;margin:0;color:var(--text);background:#ffffff}
main{max-width:1180px;margin:0 auto;padding:2rem}
h1{font-size:2rem;line-height:1.2;margin:0 0 .5rem}
h2{font-size:1.35rem;line-height:1.25;margin:2rem 0 .75rem}
h3{font-size:1.05rem;line-height:1.3;margin:1.25rem 0 .5rem}
p{margin:.25rem 0 1rem}
table{border-collapse:collapse;width:100%;margin:.75rem 0 1.25rem}
th,td{border:1px solid var(--border);padding:.5rem;text-align:left;vertical-align:top}
th{background:var(--head)}
tbody tr:nth-child(even){background:var(--soft)}
.summary{display:grid;grid-template-columns:repeat(auto-fit,minmax(12rem,1fr));gap:.75rem;margin:1rem 0}
.summary div{border:1px solid var(--border);padding:.75rem;background:var(--soft)}
.count{display:block;font-size:1.5rem;font-weight:700}
.muted{color:var(--muted)}
.status,.severity{font-weight:700}
.severity-critical{color:var(--critical)}
.severity-high{color:var(--high)}
.severity-medium{color:var(--medium)}
.severity-low{color:var(--low)}
.severity-info{color:var(--info)}
.status-pass{color:var(--pass)}
.status-warn{color:var(--warn)}
.status-fail{color:var(--fail)}
.status-unknown{color:var(--unknown)}
.finding-ids{font-size:.875rem;color:var(--muted)}
.skill-detail{border-top:1px solid var(--border);padding-top:.75rem}
.nowrap{white-space:nowrap}
</style>
</head>
<body>
<main>
<h1>Agent Skill Auditor Report</h1>
"#,
    );

    if mode == ReportMode::Ci {
        extend_html_audit_metadata(&mut html, &report.audit);
        extend_html_executive_summary(&mut html, report, &view_model);
        extend_html_ecosystem_patterns(&mut html, report);
        extend_html_ci_summary(&mut html, report, &view_model);
        html.push_str("</main>\n</body>\n</html>\n");
        return html;
    }

    extend_html_audit_metadata(&mut html, &report.audit);
    extend_html_executive_summary(&mut html, report, &view_model);
    extend_html_ecosystem_patterns(&mut html, report);
    extend_html_risk_distribution(&mut html, &view_model);
    extend_html_compatibility(&mut html, report, &view_model);
    extend_html_top_risky_skills(&mut html, &view_model);
    extend_html_broken_references(&mut html, &view_model);
    extend_html_external_urls(&mut html, &view_model);
    extend_html_secret_usage(&mut html, &view_model);
    extend_html_offline_readiness(&mut html, report, &view_model);
    extend_html_packages(&mut html, report);
    match mode {
        ReportMode::Default => extend_html_findings(&mut html, report),
        ReportMode::Verbose => extend_html_full_findings(&mut html, report, false),
        ReportMode::Research => {
            extend_html_findings(&mut html, report);
            extend_html_full_findings(&mut html, report, true);
        }
        ReportMode::Ci => unreachable!("CI mode returns before full report sections"),
    }
    extend_html_skill_details(&mut html, &view_model, mode);
    html.push_str("</main>\n</body>\n</html>\n");

    html
}

fn effective_finding_groups(report: &ScanReport) -> Cow<'_, [FindingGroup]> {
    if report.finding_groups.is_empty() && !report.findings.is_empty() {
        Cow::Owned(build_finding_groups(
            &report.packages,
            &report.findings,
            &report.compatibility,
        ))
    } else {
        Cow::Borrowed(&report.finding_groups)
    }
}

fn effective_ecosystem_patterns(report: &ScanReport) -> Cow<'_, [EcosystemPattern]> {
    if report.patterns.is_empty() && !report.packages.is_empty() {
        let finding_groups = effective_finding_groups(report);
        Cow::Owned(build_ecosystem_patterns(
            &report.packages,
            &report.findings,
            finding_groups.as_ref(),
            &report.supply_chain,
        ))
    } else {
        Cow::Borrowed(&report.patterns)
    }
}

fn ci_top_finding_groups(groups: &[FindingGroup]) -> Vec<&FindingGroup> {
    let mut groups = groups.iter().collect::<Vec<_>>();
    groups.sort_by(|left, right| {
        ci_finding_group_order_key(left).cmp(&ci_finding_group_order_key(right))
    });
    groups.truncate(CI_TOP_GROUP_LIMIT);
    groups
}

fn ci_finding_group_order_key(
    group: &FindingGroup,
) -> (
    std::cmp::Reverse<usize>,
    std::cmp::Reverse<usize>,
    &str,
    &str,
) {
    (
        std::cmp::Reverse(severity_weight(group.severity)),
        std::cmp::Reverse(group.finding_count),
        group.rule_id.as_str(),
        group.evidence_key.as_str(),
    )
}

fn finding_group_normalized_key(group: &FindingGroup) -> String {
    format!(
        "{}|{}|{}|{}|{}",
        group.rule_id,
        severity_name(group.severity),
        category_name(group.category),
        group.evidence_key,
        group
            .dimensions
            .iter()
            .map(|(key, value)| format!("{key}={value}"))
            .collect::<Vec<_>>()
            .join(",")
    )
}

fn finding_normalized_key(finding: &SkillFinding) -> String {
    format!(
        "{}|{}|{}|{}|{}|{}",
        finding.location.path,
        finding.location.line.unwrap_or(0),
        finding.rule_id,
        severity_name(finding.severity),
        category_name(finding.category),
        finding.message
    )
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

fn extend_html_audit_metadata(html: &mut String, audit: &AuditMetadata) {
    html.push_str("<section aria-labelledby=\"audit-metadata\"><h2 id=\"audit-metadata\">Audit Metadata</h2><table><tbody>");
    extend_html_metadata_row(html, "Output schema", &audit.output_schema_version);
    extend_html_metadata_row(
        html,
        "Scanner",
        &format!("{}/{}", audit.scanner.name, audit.scanner.version),
    );
    extend_html_metadata_row(
        html,
        "Ruleset",
        &format!("{} ({})", audit.ruleset.version, audit.ruleset.hash),
    );
    extend_html_metadata_row(
        html,
        "Host profiles",
        &audit.host_profiles.selected.join(", "),
    );
    extend_html_metadata_row(html, "Scan root", audit.scan.root.as_deref().unwrap_or(""));
    extend_html_metadata_row(
        html,
        "Timestamp",
        audit.timestamp.as_deref().unwrap_or("null"),
    );

    if let Some(path) = audit.config.path.as_deref() {
        extend_html_metadata_row(html, "Config path", path);
    }
    if let Some(hash) = audit.config.hash.as_deref() {
        extend_html_metadata_row(html, "Config hash", hash);
    }
    if let Some(platform) = audit.platform.as_ref() {
        extend_html_metadata_row(
            html,
            "Platform",
            &format!("{}/{}/{}", platform.family, platform.os, platform.arch),
        );
    }
    if let Some(repository) = audit.repository.as_ref() {
        if let Some(remote_url) = repository.remote_url.as_deref() {
            extend_html_metadata_row(html, "Repository remote", remote_url);
        }
        if let Some(commit) = repository.commit.as_deref() {
            extend_html_metadata_row(html, "Repository commit", commit);
        }
        if let Some(dirty) = repository.dirty {
            extend_html_metadata_row(html, "Repository dirty", &dirty.to_string());
        }
    }

    html.push_str("</tbody></table></section>\n");
}

fn extend_html_metadata_row(html: &mut String, label: &str, value: &str) {
    html.push_str("<tr><th>");
    html.push_str(&escape_html(label));
    html.push_str("</th><td>");
    html.push_str(&escape_html(value));
    html.push_str("</td></tr>");
}

fn extend_html_executive_summary(
    html: &mut String,
    report: &ScanReport,
    view_model: &HtmlReportViewModel<'_>,
) {
    html.push_str("<section aria-labelledby=\"summary\"><h2 id=\"summary\">Executive Summary</h2><div class=\"summary\">");
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
    html.push_str(&summary_count(
        "External URLs",
        view_model.external_urls.len(),
    ));
    html.push_str(&summary_count(
        "Actual secret evidence",
        report.summary.actual_secret_evidence_count,
    ));
    html.push_str(&summary_count(
        "Prompt secret exposure signals",
        report.summary.prompt_secret_exposure_count,
    ));
    html.push_str("</div></section>\n");
}

fn extend_html_ecosystem_patterns(html: &mut String, report: &ScanReport) {
    let patterns = effective_ecosystem_patterns(report);
    if patterns.is_empty() {
        return;
    }

    html.push_str("<section aria-labelledby=\"ecosystem-patterns\"><h2 id=\"ecosystem-patterns\">Observed Ecosystem Patterns</h2><table><thead><tr><th>Pattern</th><th>Summary</th><th>Count</th><th>Affected packages</th><th>Evidence</th></tr></thead><tbody>");
    for pattern in patterns.iter() {
        html.push_str("<tr><td>");
        html.push_str(&escape_html(&pattern.title));
        html.push_str("</td><td>");
        html.push_str(&escape_html(&pattern.summary));
        html.push_str("</td><td>");
        html.push_str(&pattern.count.to_string());
        html.push_str("</td><td>");
        html.push_str(&escape_html(&format!(
            "{} ({}%)",
            pattern.affected_package_count, pattern.affected_package_percent
        )));
        html.push_str("</td><td>");
        html.push_str(&escape_html(
            &pattern
                .evidence
                .iter()
                .map(|evidence| format!("{}={}", evidence.kind, evidence.count))
                .collect::<Vec<_>>()
                .join(", "),
        ));
        html.push_str("</td></tr>");
    }
    html.push_str("</tbody></table></section>\n");
}

fn extend_html_risk_distribution(html: &mut String, view_model: &HtmlReportViewModel<'_>) {
    html.push_str("<section aria-labelledby=\"risk-distribution\"><h2 id=\"risk-distribution\">Risk Distribution</h2>");
    html.push_str(
        "<table><thead><tr><th>Severity</th><th>Active findings</th></tr></thead><tbody>",
    );
    for (severity, count) in [
        ("critical", view_model.severity_counts.critical),
        ("high", view_model.severity_counts.high),
        ("medium", view_model.severity_counts.medium),
        ("low", view_model.severity_counts.low),
        ("info", view_model.severity_counts.info),
    ] {
        html.push_str("<tr><td>");
        html.push_str(&html_severity(severity));
        html.push_str("</td><td>");
        html.push_str(&count.to_string());
        html.push_str("</td></tr>");
    }
    html.push_str("</tbody></table>");

    html.push_str(
        "<table><thead><tr><th>Category</th><th>Active findings</th></tr></thead><tbody>",
    );
    for (category, count) in [
        ("spec", view_model.category_counts.spec),
        ("compatibility", view_model.category_counts.compatibility),
        ("security", view_model.category_counts.security),
        ("quality", view_model.category_counts.quality),
        ("portability", view_model.category_counts.portability),
        (
            "reproducibility",
            view_model.category_counts.reproducibility,
        ),
    ] {
        html.push_str("<tr><td>");
        html.push_str(category);
        html.push_str("</td><td>");
        html.push_str(&count.to_string());
        html.push_str("</td></tr>");
    }
    html.push_str("</tbody></table></section>\n");
}

fn extend_html_ci_summary(
    html: &mut String,
    report: &ScanReport,
    view_model: &HtmlReportViewModel<'_>,
) {
    let finding_groups = effective_finding_groups(report);
    let top_groups = ci_top_finding_groups(finding_groups.as_ref());

    html.push_str("<section aria-labelledby=\"ci-summary\"><h2 id=\"ci-summary\">CI Summary</h2>");
    html.push_str("<table><thead><tr><th>Signal</th><th>Counts</th></tr></thead><tbody>");
    html.push_str("<tr><td>Severity totals</td><td>");
    html.push_str(&escape_html(&format!(
        "critical={} high={} medium={} low={} info={}",
        view_model.severity_counts.critical,
        view_model.severity_counts.high,
        view_model.severity_counts.medium,
        view_model.severity_counts.low,
        view_model.severity_counts.info
    )));
    html.push_str("</td></tr><tr><td>Category totals</td><td>");
    html.push_str(&escape_html(&format!(
        "spec={} compatibility={} security={} quality={} portability={} reproducibility={}",
        view_model.category_counts.spec,
        view_model.category_counts.compatibility,
        view_model.category_counts.security,
        view_model.category_counts.quality,
        view_model.category_counts.portability,
        view_model.category_counts.reproducibility
    )));
    html.push_str("</td></tr><tr><td>Offline audit readiness</td><td>");
    html.push_str(&escape_html(&format!(
        "ready={} partial={} not-ready={} unknown={}",
        view_model.offline_readiness_totals.ready,
        view_model.offline_readiness_totals.partial,
        view_model.offline_readiness_totals.not_ready,
        view_model.offline_readiness_totals.unknown
    )));
    html.push_str("</td></tr>");
    if !report.compatibility.is_empty() {
        html.push_str("<tr><td>Compatibility totals</td><td>");
        html.push_str(&escape_html(&format!(
            "pass={} warn={} fail={} unknown={} untested={}",
            view_model.compatibility_totals.pass,
            view_model.compatibility_totals.warn,
            view_model.compatibility_totals.fail,
            view_model.compatibility_totals.unknown,
            view_model.compatibility_totals.untested
        )));
        html.push_str("</td></tr>");
    }
    html.push_str("</tbody></table>");

    html.push_str("<h3>Top Finding Groups</h3><p>");
    html.push_str(&escape_html(&format!(
        "Showing {} of {} canonical groups; filtered for CI log size.",
        top_groups.len(),
        finding_groups.len()
    )));
    html.push_str("</p><table><thead><tr><th>Rule</th><th>Fingerprint</th><th>Severity</th><th>Confidence</th><th>Category</th><th>Findings</th><th>Affected packages</th><th>Title</th></tr></thead><tbody>");
    if top_groups.is_empty() {
        html.push_str("<tr><td colspan=\"8\">No findings.</td></tr>");
    }
    for group in top_groups {
        html.push_str("<tr><td>");
        html.push_str(&escape_html(&group.rule_id));
        html.push_str("</td><td>");
        html.push_str(&escape_html(&group.group_fingerprint));
        html.push_str("</td><td>");
        html.push_str(&html_severity(severity_name(group.severity)));
        html.push_str("</td><td>");
        html.push_str(confidence_name(group.confidence));
        html.push_str("</td><td>");
        html.push_str(category_name(group.category));
        html.push_str("</td><td>");
        html.push_str(&group.finding_count.to_string());
        html.push_str("</td><td>");
        html.push_str(&group.affected_package_count.to_string());
        html.push_str("</td><td>");
        html.push_str(&escape_html(&group.title));
        html.push_str("</td></tr>");
    }
    html.push_str("</tbody></table></section>\n");
}

fn extend_html_top_risky_skills(html: &mut String, view_model: &HtmlReportViewModel<'_>) {
    html.push_str("<section aria-labelledby=\"top-risky-skills\"><h2 id=\"top-risky-skills\">Top Risky Skills</h2><table><thead><tr><th>Skill</th><th>Manifest</th><th>Findings</th><th>Risk score</th></tr></thead><tbody>");
    if view_model.top_risky_skills.is_empty() {
        html.push_str("<tr><td colspan=\"4\">No risky skills identified.</td></tr>");
    }

    for skill in &view_model.top_risky_skills {
        html.push_str("<tr><td>");
        html.push_str(&escape_html(
            skill
                .package
                .as_ref()
                .and_then(|package| package.name.as_deref())
                .unwrap_or("Unmatched findings"),
        ));
        html.push_str("</td><td>");
        html.push_str(&escape_html(
            skill
                .package
                .as_ref()
                .map(|package| package.manifest_path.as_str())
                .unwrap_or(""),
        ));
        html.push_str("</td><td>");
        html.push_str(&skill.finding_count.to_string());
        html.push_str("</td><td>");
        html.push_str(&skill.score.to_string());
        html.push_str("</td></tr>");
    }
    html.push_str("</tbody></table></section>\n");
}

fn extend_html_broken_references(html: &mut String, view_model: &HtmlReportViewModel<'_>) {
    html.push_str("<section aria-labelledby=\"broken-references\"><h2 id=\"broken-references\">Broken References</h2><table><thead><tr><th>Location</th><th>Rule</th><th>Message</th><th>How to fix</th></tr></thead><tbody>");
    if view_model.broken_references.is_empty() {
        html.push_str("<tr><td colspan=\"4\">No broken references found.</td></tr>");
    }

    for finding in &view_model.broken_references {
        html.push_str("<tr><td>");
        html.push_str(&escape_html(&location_display(
            &finding.location.path,
            finding.location.line,
        )));
        html.push_str("</td><td>");
        html.push_str(&escape_html(&finding.rule_id));
        html.push_str("</td><td>");
        html.push_str(&escape_html(&finding.message));
        html.push_str("</td><td>");
        html.push_str(&escape_html(&finding.remediation));
        html.push_str("</td></tr>");
    }
    html.push_str("</tbody></table></section>\n");
}

fn extend_html_external_urls(html: &mut String, view_model: &HtmlReportViewModel<'_>) {
    html.push_str("<section aria-labelledby=\"external-urls\"><h2 id=\"external-urls\">External URLs</h2><table><thead><tr><th>Location</th><th>Kind</th><th>URL</th><th>Pinned</th><th>Source</th></tr></thead><tbody>");
    if view_model.external_urls.is_empty() {
        html.push_str("<tr><td colspan=\"5\">No external URLs observed.</td></tr>");
    }

    for url in &view_model.external_urls {
        html.push_str("<tr><td>");
        html.push_str(&escape_html(&location_display(&url.path, url.line)));
        html.push_str("</td><td>");
        html.push_str(external_url_kind_name(url.kind));
        html.push_str("</td><td>");
        html.push_str(&escape_html(&url.normalized));
        html.push_str("</td><td>");
        html.push_str(pinned_name(url.pinned));
        html.push_str("</td><td>");
        html.push_str(supply_chain_source_name(url.source));
        html.push_str("</td></tr>");
    }
    html.push_str("</tbody></table></section>\n");
}

fn extend_html_secret_usage(html: &mut String, view_model: &HtmlReportViewModel<'_>) {
    html.push_str("<section aria-labelledby=\"secret-usage\"><h2 id=\"secret-usage\">Secret Usage</h2><p class=\"section-note\">Actual secret evidence is separate from prompt-risk text that mentions secret exposure.</p><table><thead><tr><th>Location</th><th>Source</th><th>Evidence</th><th>Detail</th></tr></thead><tbody>");
    if view_model.actual_secret_evidence.is_empty() {
        html.push_str("<tr><td colspan=\"4\">No secret usage evidence observed.</td></tr>");
    }

    for evidence in &view_model.actual_secret_evidence {
        match evidence {
            SecretSecurityEvidence::Finding(finding) => {
                html.push_str("<tr><td>");
                html.push_str(&escape_html(&location_display(
                    &finding.location.path,
                    finding.location.line,
                )));
                html.push_str("</td><td>finding</td><td>");
                html.push_str(&escape_html(&finding.rule_id));
                html.push_str("</td><td>");
                html.push_str(&escape_html(&finding.message));
                html.push_str("</td></tr>");
            }
            SecretSecurityEvidence::Permission(permission) => {
                html.push_str("<tr><td>");
                html.push_str(&escape_html(&location_display(
                    &permission.path,
                    permission.line,
                )));
                html.push_str("</td><td>permission</td><td>");
                html.push_str(&escape_html(&permission.normalized));
                html.push_str("</td><td>");
                html.push_str(permission_evidence_name(permission.evidence));
                html.push_str("</td></tr>");
            }
        }
    }
    html.push_str("</tbody></table>");
    html.push_str("<h3>Prompt Secret Exposure Signals</h3><table><thead><tr><th>Location</th><th>Finding</th><th>Detail</th></tr></thead><tbody>");
    if view_model.prompt_secret_exposure_findings.is_empty() {
        html.push_str(
            "<tr><td colspan=\"3\">No prompt-risk secret exposure signals observed.</td></tr>",
        );
    }
    for finding in &view_model.prompt_secret_exposure_findings {
        html.push_str("<tr><td>");
        html.push_str(&escape_html(&location_display(
            &finding.location.path,
            finding.location.line,
        )));
        html.push_str("</td><td>");
        html.push_str(&escape_html(&finding.rule_id));
        html.push_str("</td><td>");
        html.push_str(&escape_html(&finding.message));
        html.push_str("</td></tr>");
    }
    html.push_str("</tbody></table></section>\n");
}

fn extend_html_offline_readiness(
    html: &mut String,
    report: &ScanReport,
    view_model: &HtmlReportViewModel<'_>,
) {
    html.push_str("<section aria-labelledby=\"offline-readiness\"><h2 id=\"offline-readiness\">Offline Audit Readiness</h2><p class=\"section-note\">Static auditability signal from local evidence; not a runtime offline capability claim.</p><div class=\"summary\">");
    html.push_str(&summary_count(
        "Ready",
        view_model.offline_readiness_totals.ready,
    ));
    html.push_str(&summary_count(
        "Partial",
        view_model.offline_readiness_totals.partial,
    ));
    html.push_str(&summary_count(
        "Not ready",
        view_model.offline_readiness_totals.not_ready,
    ));
    html.push_str(&summary_count(
        "Unknown",
        view_model.offline_readiness_totals.unknown,
    ));
    html.push_str("</div><table><thead><tr><th>Path</th><th>Status</th><th>Score</th><th>Reasons</th></tr></thead><tbody>");

    let mut readiness = report
        .supply_chain
        .offline_readiness
        .iter()
        .collect::<Vec<_>>();
    readiness.sort();
    if readiness.is_empty() {
        html.push_str("<tr><td colspan=\"4\">No offline audit readiness evidence.</td></tr>");
    }

    for item in readiness {
        html.push_str("<tr><td>");
        html.push_str(&escape_html(&item.path));
        html.push_str("</td><td>");
        html.push_str(offline_readiness_status_name(item.status));
        html.push_str("</td><td>");
        if let Some(score) = item.score {
            html.push_str(&u8::from(score).to_string());
        }
        html.push_str("</td><td>");
        html.push_str(&escape_html(&item.reasons.join("; ")));
        html.push_str("</td></tr>");
    }
    html.push_str("</tbody></table></section>\n");
}

fn extend_html_packages(html: &mut String, report: &ScanReport) {
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
    html.push_str("</tbody></table>");
    extend_html_package_inventory(html, report);
    html.push_str("</section>\n");
}

fn extend_html_package_inventory(html: &mut String, report: &ScanReport) {
    let manifest_counts = dependency_manifest_counts(&report.supply_chain);
    let finding_counts = supply_chain_finding_counts(&report.findings);
    html.push_str("<h3>Supply Chain Summary</h3><div class=\"summary\">");
    html.push_str(&summary_count(
        "Dependency manifests",
        manifest_counts.total,
    ));
    html.push_str(&summary_count(
        "Exact-pinned manifests",
        manifest_counts.exact_pinned,
    ));
    html.push_str(&summary_count(
        "Range-based manifests",
        manifest_counts.range_based,
    ));
    html.push_str(&summary_count(
        "Lockfiles",
        report.supply_chain.lockfiles.len(),
    ));
    html.push_str(&summary_count(
        "Install commands",
        install_command_count(&report.supply_chain),
    ));
    html.push_str(&summary_count(
        "Without reproducibility evidence",
        finding_counts.install_without_reproducibility_evidence,
    ));
    html.push_str("</div>");
    html.push_str("<h3>Package Inventory</h3><table><thead><tr><th>Type</th><th>Location</th><th>Manager</th><th>Evidence</th><th>Pinned</th></tr></thead><tbody>");

    let mut rows = Vec::new();
    for manifest in &report.supply_chain.dependency_manifests {
        rows.push((
            "dependency manifest",
            location_display(&manifest.path, manifest.line),
            package_manager_name(manifest.manager),
            manifest.normalized.as_str(),
            dependency_manifest_pinning_name(manifest.pinning),
        ));
    }
    for dependency in &report.supply_chain.remote_dependencies {
        rows.push((
            "dependency",
            location_display(&dependency.path, dependency.line),
            dependency
                .package_manager
                .map(package_manager_name)
                .unwrap_or(""),
            dependency.normalized.as_str(),
            pinned_name(dependency.pinned),
        ));
    }
    for manager in &report.supply_chain.package_managers {
        rows.push((
            if manager.source == SupplyChainSourceKind::Script {
                "install command"
            } else {
                "package manager"
            },
            location_display(&manager.path, manager.line),
            package_manager_name(manager.manager),
            manager.normalized.as_str(),
            "",
        ));
    }
    for lockfile in &report.supply_chain.lockfiles {
        rows.push((
            "lockfile",
            location_display(&lockfile.path, lockfile.line),
            package_manager_name(lockfile.manager),
            lockfile.normalized.as_str(),
            "",
        ));
    }
    rows.sort();

    if rows.is_empty() {
        html.push_str("<tr><td colspan=\"5\">No package inventory evidence.</td></tr>");
    }

    for (kind, location, manager, evidence, pinned) in rows {
        html.push_str("<tr><td>");
        html.push_str(kind);
        html.push_str("</td><td>");
        html.push_str(&escape_html(&location));
        html.push_str("</td><td>");
        html.push_str(manager);
        html.push_str("</td><td>");
        html.push_str(&escape_html(evidence));
        html.push_str("</td><td>");
        html.push_str(pinned);
        html.push_str("</td></tr>");
    }
    html.push_str("</tbody></table>");
}

fn extend_html_findings(html: &mut String, report: &ScanReport) {
    let finding_groups = effective_finding_groups(report);

    html.push_str(
        "<section aria-labelledby=\"findings\"><h2 id=\"findings\">Finding Groups</h2><table><thead><tr><th>Rule</th><th>Fingerprint</th><th>Severity</th><th>Confidence</th><th>Category</th><th>Findings</th><th>Affected packages</th><th>Evidence</th><th>Dimensions</th><th>Samples</th><th>Title</th><th>Why it matters</th><th>How to fix</th><th>Suppression</th></tr></thead><tbody>",
    );
    if finding_groups.is_empty() {
        html.push_str("<tr><td colspan=\"14\">No findings.</td></tr>");
    }
    for group in finding_groups.iter() {
        extend_html_finding_group_row(html, group);
    }
    html.push_str("</tbody></table></section>\n");
}

fn extend_html_full_findings(html: &mut String, report: &ScanReport, include_research_keys: bool) {
    let findings = sorted_findings(&report.findings);
    let heading = if include_research_keys {
        "Full Finding Evidence"
    } else {
        "Findings"
    };
    let heading_id = if include_research_keys {
        "full-finding-evidence"
    } else {
        "findings"
    };
    let key_header = if include_research_keys {
        "<th>Normalized key</th>"
    } else {
        ""
    };
    let colspan = if include_research_keys { 11 } else { 10 };

    html.push_str("<section aria-labelledby=\"");
    html.push_str(heading_id);
    html.push_str("\"><h2 id=\"");
    html.push_str(heading_id);
    html.push_str("\">");
    html.push_str(heading);
    html.push_str("</h2><table><thead><tr>");
    html.push_str(key_header);
    html.push_str("<th>Rule</th><th>Severity</th><th>Confidence</th><th>Category</th><th>Location</th><th>Title</th><th>Message</th><th>Why it matters</th><th>How to fix</th><th>Suppression</th></tr></thead><tbody>");
    if findings.is_empty() {
        html.push_str(&format!(
            "<tr><td colspan=\"{colspan}\">No findings.</td></tr>"
        ));
    }
    for finding in findings {
        html.push_str("<tr>");
        if include_research_keys {
            html.push_str("<td>");
            html.push_str(&escape_html(&finding_normalized_key(finding)));
            html.push_str("</td>");
        }
        html.push_str("<td>");
        html.push_str(&escape_html(&finding.rule_id));
        html.push_str("</td><td>");
        html.push_str(&html_severity(severity_name(finding.severity)));
        html.push_str("</td><td>");
        html.push_str(confidence_name(finding.confidence));
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
    html.push_str("</tbody></table></section>\n");
}

fn extend_html_finding_group_row(html: &mut String, group: &FindingGroup) {
    html.push_str("<tr><td>");
    html.push_str(&escape_html(&group.rule_id));
    html.push_str("</td><td>");
    html.push_str(&escape_html(&group.group_fingerprint));
    html.push_str("</td><td>");
    html.push_str(&html_severity(severity_name(group.severity)));
    html.push_str("</td><td>");
    html.push_str(confidence_name(group.confidence));
    html.push_str("</td><td>");
    html.push_str(category_name(group.category));
    html.push_str("</td><td>");
    html.push_str(&group.finding_count.to_string());
    html.push_str("</td><td>");
    html.push_str(&group.affected_package_count.to_string());
    if !group.affected_packages.is_empty() {
        html.push_str("<br><span class=\"finding-ids\">");
        html.push_str(&escape_html(&group.affected_packages.join(", ")));
        html.push_str("</span>");
    }
    html.push_str("</td><td>");
    html.push_str(&escape_html(&group.evidence_key));
    html.push_str("</td><td>");
    html.push_str(&escape_html(&html_group_dimensions(group)));
    html.push_str("</td><td>");
    html.push_str(&html_group_samples(group));
    html.push_str("</td><td>");
    html.push_str(&escape_html(&group.title));
    html.push_str("</td><td>");
    html.push_str(&escape_html(&group.rationale));
    html.push_str("</td><td>");
    html.push_str(&escape_html(&group.remediation));
    html.push_str("</td><td>");
    html.push_str(&escape_html(&group.suppression));
    html.push_str("</td></tr>");
}

fn html_group_dimensions(group: &FindingGroup) -> String {
    group
        .dimensions
        .iter()
        .map(|(key, value)| format!("{key}={value}"))
        .collect::<Vec<_>>()
        .join(", ")
}

fn html_group_samples(group: &FindingGroup) -> String {
    group
        .evidence_samples
        .iter()
        .map(|sample| {
            escape_html(&format!(
                "{}: {}",
                location_display(&sample.location.path, sample.location.line),
                sample.message
            ))
        })
        .collect::<Vec<_>>()
        .join("<br>")
}

fn extend_html_skill_details(
    html: &mut String,
    view_model: &HtmlReportViewModel<'_>,
    mode: ReportMode,
) {
    html.push_str(
        "<section aria-labelledby=\"skill-details\"><h2 id=\"skill-details\">Skill Details</h2>",
    );
    if view_model.finding_groups.is_empty() {
        html.push_str("<p class=\"muted\">No per-skill findings to report.</p>");
    }

    for (index, group) in view_model.finding_groups.iter().enumerate() {
        let anchor = format!("skill-detail-{}", index + 1);
        html.push_str("<section class=\"skill-detail\" id=\"");
        html.push_str(&anchor);
        html.push_str("\"><h3>");
        html.push_str(&escape_html(
            group
                .package
                .as_ref()
                .and_then(|package| package.name.as_deref())
                .unwrap_or("Unmatched findings"),
        ));
        html.push_str("</h3><table><tbody>");
        if let Some(package) = &group.package {
            html.push_str("<tr><th>Manifest</th><td>");
            html.push_str(&escape_html(&package.manifest_path));
            html.push_str("</td></tr><tr><th>Root</th><td>");
            html.push_str(&escape_html(&package.root));
            html.push_str("</td></tr>");
        }
        html.push_str("<tr><th>Anchor</th><td>");
        html.push_str(&anchor);
        html.push_str("</td></tr><tr><th>Finding count</th><td>");
        html.push_str(&group.findings.len().to_string());
        html.push_str("</td></tr></tbody></table>");

        let include_details = matches!(mode, ReportMode::Verbose | ReportMode::Research);
        if include_details {
            html.push_str("<table><thead><tr><th>Rule</th><th>Severity</th><th>Confidence</th><th>Location</th><th>Message</th><th>Why it matters</th><th>How to fix</th><th>Suppression</th></tr></thead><tbody>");
        } else {
            html.push_str("<table><thead><tr><th>Rule</th><th>Severity</th><th>Confidence</th><th>Location</th><th>Message</th></tr></thead><tbody>");
        }
        if group.findings.is_empty() {
            let colspan = if include_details { 8 } else { 5 };
            html.push_str(&format!(
                "<tr><td colspan=\"{colspan}\">No findings for this package.</td></tr>"
            ));
        }
        for finding in &group.findings {
            html.push_str("<tr><td>");
            html.push_str(&escape_html(&finding.rule_id));
            html.push_str("</td><td>");
            html.push_str(&html_severity(severity_name(finding.severity)));
            html.push_str("</td><td>");
            html.push_str(confidence_name(finding.confidence));
            html.push_str("</td><td>");
            html.push_str(&escape_html(&location_display(
                &finding.location.path,
                finding.location.line,
            )));
            html.push_str("</td><td>");
            html.push_str(&escape_html(&finding.message));
            if include_details {
                html.push_str("</td><td>");
                html.push_str(&escape_html(&finding.rationale));
                html.push_str("</td><td>");
                html.push_str(&escape_html(&finding.remediation));
                html.push_str("</td><td>");
                html.push_str(&escape_html(&finding.suppression));
            }
            html.push_str("</td></tr>");
        }
        html.push_str("</tbody></table></section>");
    }
    html.push_str("</section>\n");
}

fn html_severity(severity: &str) -> String {
    format!(
        "<span class=\"severity severity-{}\">{}</span>",
        escape_html(severity),
        escape_html(severity)
    )
}

fn pinned_name(pinned: Option<bool>) -> &'static str {
    match pinned {
        Some(true) => "yes",
        Some(false) => "no",
        None => "unknown",
    }
}

fn dependency_manifest_pinning_name(pinning: DependencyManifestPinningKind) -> &'static str {
    match pinning {
        DependencyManifestPinningKind::ExactPinned => "exact-pinned",
        DependencyManifestPinningKind::RangeBased => "range-based",
        DependencyManifestPinningKind::Unknown => "unknown",
    }
}

fn supply_chain_source_name(source: agent_audit_core::SupplyChainSourceKind) -> &'static str {
    match source {
        agent_audit_core::SupplyChainSourceKind::Frontmatter => "frontmatter",
        agent_audit_core::SupplyChainSourceKind::MarkdownLink => "markdown-link",
        agent_audit_core::SupplyChainSourceKind::InlineCode => "inline-code",
        agent_audit_core::SupplyChainSourceKind::CodeBlock => "code-block",
        agent_audit_core::SupplyChainSourceKind::Script => "script",
        agent_audit_core::SupplyChainSourceKind::DependencyManifest => "dependency-manifest",
        agent_audit_core::SupplyChainSourceKind::PackageManifest => "package-manifest",
        agent_audit_core::SupplyChainSourceKind::Lockfile => "lockfile",
        agent_audit_core::SupplyChainSourceKind::TrustManifest => "trust-manifest",
        agent_audit_core::SupplyChainSourceKind::Filesystem => "filesystem",
        agent_audit_core::SupplyChainSourceKind::Inferred => "inferred",
    }
}

fn external_url_kind_name(kind: agent_audit_core::ExternalUrlKind) -> &'static str {
    match kind {
        agent_audit_core::ExternalUrlKind::Documentation => "documentation",
        agent_audit_core::ExternalUrlKind::RemoteScript => "remote-script",
        agent_audit_core::ExternalUrlKind::DownloadedArtifact => "downloaded-artifact",
        agent_audit_core::ExternalUrlKind::PackageRegistry => "package-registry",
        agent_audit_core::ExternalUrlKind::GithubRaw => "github-raw",
        agent_audit_core::ExternalUrlKind::GithubReleaseAsset => "github-release-asset",
        agent_audit_core::ExternalUrlKind::HttpEndpoint => "http-endpoint",
        agent_audit_core::ExternalUrlKind::Localhost => "localhost",
        agent_audit_core::ExternalUrlKind::Internal => "internal",
        agent_audit_core::ExternalUrlKind::Unknown => "unknown",
    }
}

fn package_manager_name(manager: agent_audit_core::PackageManagerKind) -> &'static str {
    match manager {
        agent_audit_core::PackageManagerKind::Npm => "npm",
        agent_audit_core::PackageManagerKind::Yarn => "yarn",
        agent_audit_core::PackageManagerKind::Pnpm => "pnpm",
        agent_audit_core::PackageManagerKind::Pip => "pip",
        agent_audit_core::PackageManagerKind::Poetry => "poetry",
        agent_audit_core::PackageManagerKind::Uv => "uv",
        agent_audit_core::PackageManagerKind::Cargo => "cargo",
        agent_audit_core::PackageManagerKind::Go => "go",
        agent_audit_core::PackageManagerKind::Gem => "gem",
        agent_audit_core::PackageManagerKind::Composer => "composer",
        agent_audit_core::PackageManagerKind::Unknown => "unknown",
    }
}

fn permission_evidence_name(evidence: agent_audit_core::PermissionEvidenceKind) -> &'static str {
    match evidence {
        agent_audit_core::PermissionEvidenceKind::Declared => "declared",
        agent_audit_core::PermissionEvidenceKind::Observed => "observed",
    }
}

fn offline_readiness_status_name(status: OfflineReadinessStatus) -> &'static str {
    match status {
        OfflineReadinessStatus::Ready => "ready",
        OfflineReadinessStatus::Partial => "partial",
        OfflineReadinessStatus::NotReady => "not-ready",
        OfflineReadinessStatus::Unknown => "unknown",
    }
}

fn extend_html_compatibility(
    html: &mut String,
    report: &ScanReport,
    view_model: &HtmlReportViewModel<'_>,
) {
    if report.compatibility.is_empty() {
        return;
    }

    html.push_str(
        "<section aria-labelledby=\"compatibility\"><h2 id=\"compatibility\">Compatibility / Host Support</h2>",
    );
    html.push_str("<div class=\"summary\">");
    html.push_str(&summary_count("Pass", view_model.compatibility_totals.pass));
    html.push_str(&summary_count("Warn", view_model.compatibility_totals.warn));
    html.push_str(&summary_count("Fail", view_model.compatibility_totals.fail));
    html.push_str(&summary_count(
        "Unknown",
        view_model.compatibility_totals.unknown,
    ));
    html.push_str(&summary_count(
        "Untested",
        view_model.compatibility_totals.untested,
    ));
    html.push_str("</div>");

    html.push_str("<h3>Host Support Totals</h3><table><thead><tr><th>Host</th><th>Pass</th><th>Warn</th><th>Fail</th><th>Unknown</th><th>Untested</th></tr></thead><tbody>");
    if view_model.compatibility_host_totals.is_empty() {
        html.push_str("<tr><td colspan=\"6\">No host profiles evaluated.</td></tr>");
    }
    for totals in &view_model.compatibility_host_totals {
        html.push_str("<tr><td>");
        html.push_str(&escape_html(&totals.host));
        html.push_str("</td><td>");
        html.push_str(&totals.counts.pass.to_string());
        html.push_str("</td><td>");
        html.push_str(&totals.counts.warn.to_string());
        html.push_str("</td><td>");
        html.push_str(&totals.counts.fail.to_string());
        html.push_str("</td><td>");
        html.push_str(&totals.counts.unknown.to_string());
        html.push_str("</td><td>");
        html.push_str(&totals.counts.untested.to_string());
        html.push_str("</td></tr>");
    }
    html.push_str("</tbody></table><h3>Compatibility Matrix</h3>");

    html.push_str("<table><thead><tr><th>Package path</th><th>Skill</th>");
    for profile in &report.compatibility.profiles {
        html.push_str("<th>");
        html.push_str(&escape_html(profile));
        html.push_str("</th>");
    }
    html.push_str("</tr></thead><tbody>");

    if report.compatibility.matrix.is_empty() {
        let colspan = report.compatibility.profiles.len() + 2;
        html.push_str(&format!(
            "<tr><td colspan=\"{colspan}\">No compatibility rows.</td></tr>"
        ));
    }

    for row in &report.compatibility.matrix {
        html.push_str("<tr><td>");
        html.push_str(&escape_html(&row.path));
        html.push_str("</td><td>");
        html.push_str(&escape_html(row.name.as_deref().unwrap_or("")));
        html.push_str("</td>");

        for profile_id in &report.compatibility.profiles {
            html.push_str("<td>");
            if let Some(profile) = row
                .profiles
                .iter()
                .find(|profile| &profile.profile == profile_id)
            {
                html.push_str(&html_compatibility_status(profile.status.as_str()));
                if !profile.finding_ids.is_empty() {
                    html.push_str("<br><span class=\"finding-ids\">");
                    html.push_str(&escape_html(&profile.finding_ids.join(", ")));
                    html.push_str("</span>");
                }
            }
            html.push_str("</td>");
        }

        html.push_str("</tr>");
    }
    html.push_str("</tbody></table>");

    extend_html_compatibility_details(html, report);
    html.push_str("</section>\n");
}

fn html_compatibility_status(status: &str) -> String {
    let class = match status {
        "pass" => "status-pass",
        "warn" => "status-warn",
        "fail" => "status-fail",
        "untested" => "status-unknown",
        _ => "status-unknown",
    };

    format!(
        "<span class=\"status {class}\">{}</span>",
        escape_html(status)
    )
}

fn extend_html_compatibility_details(html: &mut String, report: &ScanReport) {
    let has_details = report
        .compatibility
        .matrix
        .iter()
        .flat_map(|row| row.profiles.iter())
        .any(|profile| !profile.finding_ids.is_empty());

    if !has_details {
        return;
    }

    html.push_str("<h3>Compatibility Details</h3><table><thead><tr><th>Package path</th><th>Skill</th><th>Profile</th><th>Status</th><th>Finding</th><th>Context</th></tr></thead><tbody>");

    for row in &report.compatibility.matrix {
        for profile_id in &report.compatibility.profiles {
            let Some(profile) = row
                .profiles
                .iter()
                .find(|profile| &profile.profile == profile_id)
            else {
                continue;
            };

            for finding_id in &profile.finding_ids {
                html.push_str("<tr><td>");
                html.push_str(&escape_html(&row.path));
                html.push_str("</td><td>");
                html.push_str(&escape_html(row.name.as_deref().unwrap_or("")));
                html.push_str("</td><td>");
                html.push_str(&escape_html(&profile.profile));
                html.push_str("</td><td>");
                html.push_str(&escape_html(profile.status.as_str()));
                html.push_str("</td><td>");
                html.push_str(&escape_html(finding_id));
                html.push_str("</td><td>");
                html.push_str(&html_compatibility_finding_contexts(
                    &report.findings,
                    &row.path,
                    finding_id,
                ));
                html.push_str("</td></tr>");
            }
        }
    }

    html.push_str("</tbody></table>");
}

fn html_compatibility_finding_contexts(
    findings: &[SkillFinding],
    path: &str,
    finding_id: &str,
) -> String {
    let contexts = sorted_findings(findings)
        .into_iter()
        .filter(|finding| finding.location.path == path && finding.rule_id == finding_id)
        .map(|finding| {
            escape_html(&format!(
                "{}: {}",
                location_display(&finding.location.path, finding.location.line),
                finding.message
            ))
        })
        .collect::<Vec<_>>();

    if contexts.is_empty() {
        "No matching finding detail.".to_owned()
    } else {
        contexts.join("<br>")
    }
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

#[derive(Debug)]
struct HtmlReportViewModel<'a> {
    severity_counts: SeverityCounts,
    category_counts: CategoryCounts,
    compatibility_totals: CompatibilityStatusCounts,
    compatibility_host_totals: Vec<CompatibilityHostStatusTotals>,
    offline_readiness_totals: OfflineReadinessCounts,
    broken_references: Vec<&'a SkillFinding>,
    external_urls: Vec<&'a ExternalUrl>,
    actual_secret_evidence: Vec<SecretSecurityEvidence<'a>>,
    prompt_secret_exposure_findings: Vec<&'a SkillFinding>,
    finding_groups: Vec<SkillFindingGroup<'a>>,
    top_risky_skills: Vec<TopRiskySkill>,
}

impl<'a> HtmlReportViewModel<'a> {
    fn from_report(report: &'a ScanReport) -> Self {
        let finding_groups = skill_finding_groups(report);

        Self {
            severity_counts: severity_counts(&report.findings),
            category_counts: category_counts(&report.findings),
            compatibility_totals: compatibility_status_counts(&report.compatibility),
            compatibility_host_totals: compatibility_host_status_totals(&report.compatibility),
            offline_readiness_totals: offline_readiness_counts(&report.supply_chain),
            broken_references: broken_references(&report.findings),
            external_urls: external_urls(&report.supply_chain),
            actual_secret_evidence: actual_secret_evidence(report),
            prompt_secret_exposure_findings: prompt_secret_exposure_findings(&report.findings),
            top_risky_skills: top_risky_skills(&finding_groups),
            finding_groups,
        }
    }
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
struct SeverityCounts {
    critical: usize,
    high: usize,
    medium: usize,
    low: usize,
    info: usize,
}

fn severity_counts(findings: &[SkillFinding]) -> SeverityCounts {
    let mut counts = SeverityCounts::default();

    for finding in findings {
        match finding.severity {
            Severity::Critical => counts.critical += 1,
            Severity::High => counts.high += 1,
            Severity::Medium => counts.medium += 1,
            Severity::Low => counts.low += 1,
            Severity::Info => counts.info += 1,
        }
    }

    counts
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
struct CategoryCounts {
    spec: usize,
    compatibility: usize,
    security: usize,
    quality: usize,
    portability: usize,
    reproducibility: usize,
}

fn category_counts(findings: &[SkillFinding]) -> CategoryCounts {
    let mut counts = CategoryCounts::default();

    for finding in findings {
        match finding.category {
            FindingCategory::Spec => counts.spec += 1,
            FindingCategory::Compatibility => counts.compatibility += 1,
            FindingCategory::Security => counts.security += 1,
            FindingCategory::Quality => counts.quality += 1,
            FindingCategory::Portability => counts.portability += 1,
            FindingCategory::Reproducibility => counts.reproducibility += 1,
        }
    }

    counts
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CompatibilityHostStatusTotals {
    host: String,
    counts: CompatibilityStatusCounts,
}

fn compatibility_host_status_totals(
    compatibility: &CompatibilityMatrix,
) -> Vec<CompatibilityHostStatusTotals> {
    compatibility
        .profiles
        .iter()
        .map(|profile| CompatibilityHostStatusTotals {
            host: profile.clone(),
            counts: compatibility_status_counts_for_profile(compatibility, profile),
        })
        .collect()
}

fn broken_references(findings: &[SkillFinding]) -> Vec<&SkillFinding> {
    sorted_findings(findings)
        .into_iter()
        .filter(|finding| finding.rule_id == "SKILL010")
        .collect()
}

fn external_urls(supply_chain: &SupplyChainInventory) -> Vec<&ExternalUrl> {
    let mut urls = supply_chain.external_urls.iter().collect::<Vec<_>>();
    urls.sort();
    urls
}

#[derive(Debug, Clone, Copy)]
enum SecretSecurityEvidence<'a> {
    Finding(&'a SkillFinding),
    Permission(&'a PermissionEvidence),
}

impl SecretSecurityEvidence<'_> {
    fn order_key(&self) -> (&str, Option<usize>, &str, &str) {
        match self {
            Self::Finding(finding) => (
                finding.location.path.as_str(),
                finding.location.line,
                "finding",
                finding.rule_id.as_str(),
            ),
            Self::Permission(permission) => (
                permission.path.as_str(),
                permission.line,
                "permission",
                permission.normalized.as_str(),
            ),
        }
    }
}

fn actual_secret_evidence(report: &ScanReport) -> Vec<SecretSecurityEvidence<'_>> {
    let mut evidence = Vec::new();

    for finding in sorted_findings(&report.findings) {
        if is_actual_secret_evidence_finding(finding) {
            evidence.push(SecretSecurityEvidence::Finding(finding));
        }
    }

    let mut permissions = report
        .supply_chain
        .permissions
        .iter()
        .filter(|permission| permission.kind == PermissionKind::Secrets)
        .collect::<Vec<_>>();
    permissions.sort();

    for permission in permissions {
        evidence.push(SecretSecurityEvidence::Permission(permission));
    }

    evidence.sort_by(|left, right| left.order_key().cmp(&right.order_key()));
    evidence
}

fn is_actual_secret_evidence_finding(finding: &SkillFinding) -> bool {
    finding.rule_id == "SEC002"
        || (finding.rule_id == "SEC003"
            && (contains_secret_word(&finding.title)
                || contains_secret_word(&finding.message)
                || contains_secret_word(&finding.rationale)))
}

fn prompt_secret_exposure_findings(findings: &[SkillFinding]) -> Vec<&SkillFinding> {
    sorted_findings(findings)
        .into_iter()
        .filter(|finding| is_prompt_secret_exposure_finding(finding))
        .collect()
}

fn is_prompt_secret_exposure_finding(finding: &SkillFinding) -> bool {
    matches!(finding.rule_id.as_str(), "SEC011" | "SEC012")
        && (contains_secret_word(&finding.title)
            || contains_secret_word(&finding.message)
            || contains_secret_word(&finding.rationale))
}

fn contains_secret_word(value: &str) -> bool {
    let value = value.to_ascii_lowercase();
    value.contains("secret")
        || value.contains("credential")
        || value.contains("token")
        || value.contains("password")
        || value.contains("api key")
        || value.contains("apikey")
}

#[derive(Debug, Clone)]
struct SkillFindingGroup<'a> {
    package: Option<SkillGroupPackage>,
    findings: Vec<&'a SkillFinding>,
}

impl SkillFindingGroup<'_> {
    fn sort_key(&self) -> (u8, &str, &str) {
        match &self.package {
            Some(package) => (
                0,
                package.manifest_path.as_str(),
                package.name.as_deref().unwrap_or(""),
            ),
            None => (1, "", ""),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SkillGroupPackage {
    root: String,
    manifest_path: String,
    name: Option<String>,
}

fn skill_finding_groups(report: &ScanReport) -> Vec<SkillFindingGroup<'_>> {
    let packages = sorted_packages(&report.packages);
    let mut grouped = BTreeMap::<Option<String>, Vec<&SkillFinding>>::new();

    for package in &packages {
        grouped
            .entry(Some(package.manifest_path.clone()))
            .or_default();
    }

    for finding in sorted_findings(&report.findings) {
        let manifest_path =
            package_for_finding(&packages, finding).map(|package| package.manifest_path.clone());
        grouped.entry(manifest_path).or_default().push(finding);
    }

    let packages_by_manifest = report
        .packages
        .iter()
        .map(|package| (package.manifest_path.as_str(), package))
        .collect::<BTreeMap<_, _>>();

    let mut groups = grouped
        .into_iter()
        .map(|(manifest_path, findings)| SkillFindingGroup {
            package: manifest_path.and_then(|path| {
                packages_by_manifest
                    .get(path.as_str())
                    .map(|package| SkillGroupPackage {
                        root: package.root.clone(),
                        manifest_path: package.manifest_path.clone(),
                        name: package.manifest.name.clone(),
                    })
            }),
            findings,
        })
        .collect::<Vec<_>>();

    groups.sort_by(|left, right| left.sort_key().cmp(&right.sort_key()));
    groups
}

fn package_for_finding<'a>(
    packages: &[&'a SkillPackage],
    finding: &SkillFinding,
) -> Option<&'a SkillPackage> {
    packages
        .iter()
        .copied()
        .find(|package| package.manifest_path == finding.location.path)
        .or_else(|| {
            packages
                .iter()
                .copied()
                .filter(|package| path_has_root_prefix(&finding.location.path, &package.root))
                .max_by(|left, right| {
                    left.root
                        .len()
                        .cmp(&right.root.len())
                        .then_with(|| right.manifest_path.cmp(&left.manifest_path))
                })
        })
}

fn path_has_root_prefix(path: &str, root: &str) -> bool {
    if root.is_empty() || root == "." {
        return true;
    }

    path == root
        || path
            .strip_prefix(root)
            .is_some_and(|suffix| suffix.starts_with('/'))
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct TopRiskySkill {
    package: Option<SkillGroupPackage>,
    score: usize,
    finding_count: usize,
}

impl TopRiskySkill {
    fn sort_key(&self) -> (std::cmp::Reverse<usize>, u8, &str, &str) {
        match &self.package {
            Some(package) => (
                std::cmp::Reverse(self.score),
                0,
                package.manifest_path.as_str(),
                package.name.as_deref().unwrap_or(""),
            ),
            None => (std::cmp::Reverse(self.score), 1, "", ""),
        }
    }
}

fn top_risky_skills(groups: &[SkillFindingGroup<'_>]) -> Vec<TopRiskySkill> {
    let mut ranked = groups
        .iter()
        .filter_map(|group| {
            let score = group
                .findings
                .iter()
                .map(|finding| severity_weight(finding.severity))
                .sum::<usize>();

            (score > 0).then(|| TopRiskySkill {
                package: group.package.clone(),
                score,
                finding_count: group.findings.len(),
            })
        })
        .collect::<Vec<_>>();

    ranked.sort_by(|left, right| left.sort_key().cmp(&right.sort_key()));
    ranked
}

fn severity_weight(severity: Severity) -> usize {
    match severity {
        Severity::Critical => 100,
        Severity::High => 50,
        Severity::Medium => 20,
        Severity::Low => 5,
        Severity::Info => 1,
    }
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
    let mut run = json!({
        "tool": {
            "driver": {
                "name": "Agent Skill Auditor",
                "semanticVersion": env!("CARGO_PKG_VERSION"),
                "informationUri": "https://github.com/openai/agent-skill-auditor",
                "properties": {
                    "agentAudit": sarif_driver_audit_metadata(&report.audit)
                },
                "rules": sarif_rules(&sorted_findings)
            }
        },
        "invocations": [{
            "executionSuccessful": true,
            "properties": {
                "agentAudit": sarif_invocation_audit_metadata(&report.audit)
            }
        }],
        "results": sarif_results(&sorted_findings, &rule_indexes, &report.compatibility)
    });

    run["properties"] = sarif_run_properties(report);

    json!({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [run]
    })
}

fn sarif_run_properties(report: &ScanReport) -> Value {
    let mut properties = json!({
        "agentAudit": sarif_audit_metadata(&report.audit)
    });

    if !report.compatibility.is_empty() {
        properties["compatibility"] = sarif_compatibility_matrix(&report.compatibility);
    }

    properties
}

fn sarif_driver_audit_metadata(audit: &AuditMetadata) -> Value {
    json!({
        "outputSchemaVersion": audit.output_schema_version.as_str(),
        "scanner": {
            "name": audit.scanner.name.as_str(),
            "version": audit.scanner.version.as_str()
        },
        "ruleset": {
            "version": audit.ruleset.version.as_str(),
            "hash": audit.ruleset.hash.as_str()
        },
        "hostProfiles": {
            "selected": &audit.host_profiles.selected,
            "version": audit.host_profiles.version.as_str(),
            "hash": audit.host_profiles.hash.as_str()
        }
    })
}

fn sarif_invocation_audit_metadata(audit: &AuditMetadata) -> Value {
    json!({
        "config": {
            "path": audit.config.path.as_deref(),
            "hash": audit.config.hash.as_deref()
        },
        "scan": {
            "root": audit.scan.root.as_deref()
        },
        "command": {
            "name": audit.command.name.as_deref(),
            "format": audit.command.format.as_deref(),
            "mode": audit.command.mode.as_deref(),
            "profiles": &audit.command.profiles,
            "failOn": &audit.command.fail_on,
            "supplyChain": audit.command.supply_chain,
            "strictSupplyChain": audit.command.strict_supply_chain
        },
        "platform": audit.platform.as_ref(),
        "repository": audit.repository.as_ref(),
        "timestamp": audit.timestamp.as_deref()
    })
}

fn sarif_audit_metadata(audit: &AuditMetadata) -> Value {
    json!({
        "outputSchemaVersion": audit.output_schema_version.as_str(),
        "scanner": {
            "name": audit.scanner.name.as_str(),
            "version": audit.scanner.version.as_str()
        },
        "ruleset": {
            "version": audit.ruleset.version.as_str(),
            "hash": audit.ruleset.hash.as_str()
        },
        "hostProfiles": {
            "selected": &audit.host_profiles.selected,
            "version": audit.host_profiles.version.as_str(),
            "hash": audit.host_profiles.hash.as_str()
        },
        "config": {
            "path": audit.config.path.as_deref(),
            "hash": audit.config.hash.as_deref()
        },
        "scan": {
            "root": audit.scan.root.as_deref()
        },
        "command": {
            "name": audit.command.name.as_deref(),
            "format": audit.command.format.as_deref(),
            "mode": audit.command.mode.as_deref(),
            "profiles": &audit.command.profiles,
            "failOn": &audit.command.fail_on,
            "supplyChain": audit.command.supply_chain,
            "strictSupplyChain": audit.command.strict_supply_chain
        },
        "platform": audit.platform.as_ref(),
        "repository": audit.repository.as_ref(),
        "timestamp": audit.timestamp.as_deref()
    })
}

fn sarif_compatibility_matrix(compatibility: &CompatibilityMatrix) -> Value {
    let totals = compatibility_status_counts(compatibility);

    json!({
        "profiles": compatibility.profiles,
        "statusTotals": {
            "pass": totals.pass,
            "warn": totals.warn,
            "fail": totals.fail,
            "unknown": totals.unknown,
            "untested": totals.untested
        },
        "matrix": compatibility
            .matrix
            .iter()
            .map(sarif_compatibility_row)
            .collect::<Vec<_>>()
    })
}

fn sarif_compatibility_row(row: &SkillCompatibilityRow) -> Value {
    json!({
        "path": row.path,
        "name": row.name,
        "profiles": row
            .profiles
            .iter()
            .map(|profile| {
                json!({
                    "profile": profile.profile,
                    "status": profile.status.as_str(),
                    "findingIds": profile.finding_ids
                })
            })
            .collect::<Vec<_>>()
    })
}

fn sorted_findings(findings: &[SkillFinding]) -> Vec<&SkillFinding> {
    let mut sorted = findings.iter().collect::<Vec<_>>();
    sorted.sort_by(|left, right| compare_findings(left, right));
    sorted
}

fn compare_findings(left: &SkillFinding, right: &SkillFinding) -> std::cmp::Ordering {
    sarif_finding_order_key(left).cmp(&sarif_finding_order_key(right))
}

fn sarif_finding_order_key(finding: &SkillFinding) -> (&str, Option<usize>, &str, &str) {
    (
        finding.location.path.as_str(),
        finding.location.line,
        finding.rule_id.as_str(),
        finding.message.as_str(),
    )
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

fn sarif_results(
    findings: &[&SkillFinding],
    rule_indexes: &BTreeMap<String, usize>,
    compatibility: &CompatibilityMatrix,
) -> Vec<Value> {
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
            let mut properties = json!({
                "agentAuditSeverity": severity_name(finding.severity),
                "agentAuditConfidence": confidence_name(finding.confidence),
                "category": category_name(finding.category)
            });

            if let Some(profiles) = sarif_compatibility_profiles_for_finding(finding, compatibility)
            {
                properties["compatibilityProfiles"] = profiles;
            }

            json!({
                "ruleId": finding.rule_id,
                "ruleIndex": rule_indexes[&finding.rule_id],
                "level": sarif_level(finding.severity),
                "message": {
                    "text": finding.message
                },
                "partialFingerprints": {
                    "agentAuditFindingFingerprint": effective_finding_fingerprint(finding)
                },
                "locations": [
                    {
                        "physicalLocation": physical_location
                    }
                ],
                "properties": properties
            })
        })
        .collect()
}

fn effective_finding_fingerprint(finding: &SkillFinding) -> String {
    if finding.fingerprint.is_empty() {
        agent_audit_core::model::finding_fingerprint(finding)
    } else {
        finding.fingerprint.clone()
    }
}

fn sarif_compatibility_profiles_for_finding(
    finding: &SkillFinding,
    compatibility: &CompatibilityMatrix,
) -> Option<Value> {
    let profiles = compatibility
        .matrix
        .iter()
        .filter(|row| row.path == finding.location.path)
        .flat_map(|row| row.profiles.iter())
        .filter(|profile| {
            profile
                .finding_ids
                .iter()
                .any(|rule_id| rule_id == &finding.rule_id)
        })
        .map(|profile| {
            json!({
                "profile": profile.profile,
                "status": profile.status.as_str()
            })
        })
        .collect::<Vec<_>>();

    if profiles.is_empty() {
        None
    } else {
        Some(Value::Array(profiles))
    }
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

fn confidence_name(confidence: FindingConfidence) -> &'static str {
    match confidence {
        FindingConfidence::Low => "low",
        FindingConfidence::Medium => "medium",
        FindingConfidence::High => "high",
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
        build_finding_groups, FindingConfidence, FindingLocation, MarkdownCodeBlock, SkillFinding,
        SkillGraph, SkillManifest, SkillPackage, SkillReference, SupplyChainInventory,
        SuppressedFinding, SuppressionMatch,
    };
    use std::collections::BTreeMap;
    use std::path::Path;

    #[test]
    fn supported_report_formats_match_phase_one_outputs() {
        assert_eq!(
            SUPPORTED_REPORT_FORMATS,
            &["summary", "json", "public-json", "sarif", "html"]
        );
    }

    #[test]
    fn report_format_parses_supported_formats() {
        assert_eq!("summary".parse::<ReportFormat>(), Ok(ReportFormat::Summary));
        assert_eq!("json".parse::<ReportFormat>(), Ok(ReportFormat::Json));
        assert_eq!(
            "public-json".parse::<ReportFormat>(),
            Ok(ReportFormat::PublicJson)
        );
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
            "unsupported report format 'xml' (supported: summary, json, public-json, sarif, html)"
        );
    }

    #[test]
    fn report_format_as_str_matches_supported_metadata() {
        let formats = [
            ReportFormat::Summary,
            ReportFormat::Json,
            ReportFormat::PublicJson,
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
    fn supported_report_modes_match_scan_output_modes() {
        assert_eq!(
            SUPPORTED_REPORT_MODES,
            &["default", "verbose", "research", "ci"]
        );
    }

    #[test]
    fn report_mode_parses_supported_modes() {
        assert_eq!("default".parse::<ReportMode>(), Ok(ReportMode::Default));
        assert_eq!("verbose".parse::<ReportMode>(), Ok(ReportMode::Verbose));
        assert_eq!("research".parse::<ReportMode>(), Ok(ReportMode::Research));
        assert_eq!("ci".parse::<ReportMode>(), Ok(ReportMode::Ci));
    }

    #[test]
    fn report_mode_rejects_unsupported_modes_with_supported_list() {
        let error = "debug"
            .parse::<ReportMode>()
            .expect_err("unsupported mode should fail");

        assert_eq!(error.value(), "debug");
        assert_eq!(
            error.to_string(),
            "unsupported report mode 'debug' (supported: default, verbose, research, ci)"
        );
    }

    #[test]
    fn report_mode_as_str_matches_supported_metadata() {
        let modes = [
            ReportMode::Default,
            ReportMode::Verbose,
            ReportMode::Research,
            ReportMode::Ci,
        ];

        assert_eq!(
            modes
                .into_iter()
                .map(ReportMode::as_str)
                .collect::<Vec<_>>(),
            SUPPORTED_REPORT_MODES
        );
    }

    #[test]
    fn render_report_dispatches_supported_formats_with_trailing_newline() {
        let report = review_skill_report(
            "SKILL001",
            Severity::Low,
            FindingCategory::Spec,
            "Missing skill name",
            "The skill manifest does not declare a name.",
            Some(1),
        );

        let summary = render_report(&report, ReportFormat::Summary).expect("render summary");
        let json = render_report(&report, ReportFormat::Json).expect("render JSON");
        let public_json =
            render_report(&report, ReportFormat::PublicJson).expect("render public JSON");
        let sarif = render_report(&report, ReportFormat::Sarif).expect("render SARIF");
        let html = render_report(&report, ReportFormat::Html).expect("render HTML");

        assert!(summary.starts_with("Agent Skill Auditor scan summary\n"));
        assert!(json.starts_with("{\n"));
        assert!(public_json.starts_with("{\n"));
        assert!(sarif.contains("\"version\": \"2.1.0\""));
        assert!(html.starts_with("<!doctype html>\n"));
        assert!(summary.ends_with('\n'));
        assert!(json.ends_with('\n'));
        assert!(public_json.ends_with('\n'));
        assert!(sarif.ends_with('\n'));
        assert!(html.ends_with('\n'));
        assert_eq!(html, render_html(&report));
    }

    #[test]
    fn public_json_redacts_manifest_bodies_and_bounds_evidence_snippets() {
        let full_manifest_body = "PUBLIC_DATASET_FULL_MANIFEST_BODY_SHOULD_NOT_APPEAR";
        let full_code_block = "PUBLIC_DATASET_FULL_CODE_BLOCK_SHOULD_NOT_APPEAR";
        let long_tail = "PUBLIC_DATASET_LONG_EVIDENCE_TAIL_SHOULD_NOT_APPEAR";
        let long_message = format!(
            "{}{}",
            "a".repeat(PUBLIC_DATASET_SNIPPET_LIMIT + 20),
            long_tail
        );
        let mut package = review_package();
        package.manifest.body = full_manifest_body.to_owned();
        package.manifest.inline_code = vec![full_code_block.to_owned()];
        package.manifest.code_blocks = vec![MarkdownCodeBlock {
            language: Some("bash".to_owned()),
            content: full_code_block.to_owned(),
            line: Some(8),
        }];

        let report = report_with_packages_and_findings(
            vec![package],
            vec![finding(
                "SEC001",
                Severity::High,
                FindingCategory::Security,
                "Remote content piped into shell",
                &long_message,
                "skills/review/scripts/install.sh",
                Some(4),
            )],
        );

        let rendered = render_public_json(&report).expect("render public JSON");
        let value: Value = serde_json::from_str(&rendered).expect("parse public JSON");

        assert!(!rendered.contains(full_manifest_body));
        assert!(!rendered.contains(full_code_block));
        assert!(!rendered.contains(long_tail));
        assert_eq!(value["audit"], serde_json::to_value(&report.audit).unwrap());
        assert_eq!(value["repository"], serde_json::Value::Null);
        assert_eq!(
            value["packages"][0]["manifest_path"],
            "skills/review/SKILL.md"
        );
        assert_eq!(value["packages"][0]["name"], "review-skill");
        assert!(value["packages"][0]["manifest"].is_null());
        assert!(value["packages"][0]["body"].is_null());
        assert!(value["packages"][0]["code_blocks"].is_null());
        assert_eq!(
            value["findings"][0]["fingerprint"],
            report.findings[0].fingerprint
        );
        assert_eq!(
            value["finding_groups"][0]["group_fingerprint"],
            report.finding_groups[0].group_fingerprint
        );
        assert_eq!(
            value["findings"][0]["evidence_snippet"]
                .as_str()
                .expect("evidence snippet")
                .chars()
                .count(),
            PUBLIC_DATASET_SNIPPET_LIMIT + "... [truncated]".len()
        );
        assert_eq!(value["metrics"]["summary"]["package_count"], 1);
        assert!(value["patterns"].is_array());
    }

    #[test]
    fn render_report_with_mode_preserves_full_json_and_sarif_findings() {
        let report = repeated_finding_report(4);

        for mode in [
            ReportMode::Default,
            ReportMode::Verbose,
            ReportMode::Research,
            ReportMode::Ci,
        ] {
            let json =
                render_report_with_mode(&report, ReportFormat::Json, mode).expect("render JSON");
            let value: Value = serde_json::from_str(&json).expect("parse JSON report");
            assert_eq!(
                value["findings"].as_array().expect("findings array").len(),
                4
            );

            let sarif =
                render_report_with_mode(&report, ReportFormat::Sarif, mode).expect("render SARIF");
            let value: Value = serde_json::from_str(&sarif).expect("parse SARIF report");
            assert_eq!(
                value["runs"][0]["results"]
                    .as_array()
                    .expect("SARIF results array")
                    .len(),
                4
            );
        }
    }

    #[test]
    fn html_view_model_counts_active_finding_status_and_readiness_totals() {
        let mut report = report_with_findings(vec![
            finding(
                "SEC001",
                Severity::Critical,
                FindingCategory::Security,
                "Remote content piped into shell",
                "A remote script is piped into a shell.",
                "alpha/SKILL.md",
                Some(1),
            ),
            finding(
                "SKILL010",
                Severity::Low,
                FindingCategory::Spec,
                "Broken relative reference",
                "The referenced file could not be found.",
                "beta/SKILL.md",
                Some(2),
            ),
            finding(
                "PORT001",
                Severity::Info,
                FindingCategory::Portability,
                "Host-specific path",
                "The skill uses a host-specific path.",
                "beta/SKILL.md",
                Some(3),
            ),
        ]);
        report.compatibility = compatibility_matrix(json!({
            "profiles": ["codex", "generic"],
            "matrix": [
                {
                    "path": "alpha/SKILL.md",
                    "name": "alpha",
                    "profiles": [
                        {"profile": "codex", "status": "fail", "finding_ids": ["SEC001"]},
                        {"profile": "generic", "status": "warn", "finding_ids": []}
                    ]
                },
                {
                    "path": "beta/SKILL.md",
                    "name": "beta",
                    "profiles": [
                        {"profile": "codex", "status": "pass", "finding_ids": []},
                        {"profile": "generic", "status": "unknown", "finding_ids": []}
                    ]
                }
            ]
        }));
        report.supply_chain = supply_chain_inventory(json!({
            "licenses": [],
            "trust_manifests": [],
            "external_urls": [],
            "remote_dependencies": [],
            "package_managers": [],
            "lockfiles": [],
            "executables": [],
            "binaries": [],
            "checksums": [],
            "permissions": [],
            "offline_readiness": [
                {"path": "alpha/SKILL.md", "status": "ready", "score": 100, "reasons": []},
                {"path": "beta/SKILL.md", "status": "partial", "score": 60, "reasons": []},
                {"path": "gamma/SKILL.md", "status": "not-ready", "score": 20, "reasons": []},
                {"path": "delta/SKILL.md", "status": "unknown", "score": null, "reasons": []}
            ]
        }));

        let view_model = HtmlReportViewModel::from_report(&report);

        assert_eq!(
            view_model.severity_counts,
            SeverityCounts {
                critical: 1,
                high: 0,
                medium: 0,
                low: 1,
                info: 1,
            }
        );
        assert_eq!(
            view_model.category_counts,
            CategoryCounts {
                spec: 1,
                compatibility: 0,
                security: 1,
                quality: 0,
                portability: 1,
                reproducibility: 0,
            }
        );
        assert_eq!(
            view_model.compatibility_totals,
            CompatibilityStatusCounts {
                pass: 1,
                warn: 1,
                fail: 1,
                unknown: 1,
                untested: 0,
            }
        );
        assert_eq!(
            view_model
                .compatibility_host_totals
                .iter()
                .map(|total| (total.host.as_str(), total.counts))
                .collect::<Vec<_>>(),
            vec![
                (
                    "codex",
                    CompatibilityStatusCounts {
                        pass: 1,
                        warn: 0,
                        fail: 1,
                        unknown: 0,
                        untested: 0,
                    }
                ),
                (
                    "generic",
                    CompatibilityStatusCounts {
                        pass: 0,
                        warn: 1,
                        fail: 0,
                        unknown: 1,
                        untested: 0,
                    }
                ),
            ]
        );
        assert_eq!(
            view_model.offline_readiness_totals,
            OfflineReadinessCounts {
                ready: 1,
                partial: 1,
                not_ready: 1,
                unknown: 1,
            }
        );
    }

    #[test]
    fn html_view_model_orders_top_risky_skills_by_weight_then_manifest_path() {
        let report = report_with_packages_and_findings(
            vec![
                package("skills/beta", "skills/beta/SKILL.md", Some("beta"), None),
                package("skills/alpha", "skills/alpha/SKILL.md", Some("alpha"), None),
                package("skills/gamma", "skills/gamma/SKILL.md", Some("gamma"), None),
            ],
            vec![
                finding(
                    "SEC001",
                    Severity::High,
                    FindingCategory::Security,
                    "High beta",
                    "High beta finding.",
                    "skills/beta/SKILL.md",
                    Some(1),
                ),
                finding(
                    "SKILL020",
                    Severity::Medium,
                    FindingCategory::Spec,
                    "Medium alpha",
                    "First medium alpha finding.",
                    "skills/alpha/SKILL.md",
                    Some(1),
                ),
                finding(
                    "SKILL021",
                    Severity::Medium,
                    FindingCategory::Spec,
                    "Medium alpha",
                    "Second medium alpha finding.",
                    "skills/alpha/references/guide.md",
                    Some(1),
                ),
                finding(
                    "SKILL030",
                    Severity::Low,
                    FindingCategory::Spec,
                    "Low gamma",
                    "Low gamma finding.",
                    "skills/gamma/SKILL.md",
                    Some(1),
                ),
            ],
        );

        let view_model = HtmlReportViewModel::from_report(&report);

        assert_eq!(
            view_model
                .top_risky_skills
                .iter()
                .map(|skill| (
                    skill
                        .package
                        .as_ref()
                        .map(|package| package.manifest_path.as_str()),
                    skill.score,
                    skill.finding_count
                ))
                .collect::<Vec<_>>(),
            vec![
                (Some("skills/beta/SKILL.md"), 50, 1),
                (Some("skills/alpha/SKILL.md"), 40, 2),
                (Some("skills/gamma/SKILL.md"), 5, 1),
            ]
        );
    }

    #[test]
    fn html_view_model_extracts_broken_references_external_urls_and_secret_evidence() {
        let mut report = report_with_findings(vec![
            finding(
                "SEC002",
                Severity::Medium,
                FindingCategory::Security,
                "Secret-like environment variable access",
                "The script reads REVIEW_TOKEN.",
                "skills/review/scripts/check.sh",
                Some(4),
            ),
            finding(
                "SEC003",
                Severity::High,
                FindingCategory::Security,
                "Data sent to external URL",
                "The script uploads a credential to an external URL.",
                "skills/review/scripts/check.sh",
                Some(5),
            ),
            finding(
                "SKILL010",
                Severity::Low,
                FindingCategory::Spec,
                "Broken relative reference",
                "The referenced file could not be found.",
                "skills/review/SKILL.md",
                Some(8),
            ),
        ]);
        report.supply_chain = supply_chain_inventory(json!({
            "licenses": [],
            "trust_manifests": [],
            "external_urls": [
                {
                    "path": "skills/review/SKILL.md",
                    "line": 9,
                    "source": "markdown-link",
                    "kind": "documentation",
                    "normalized": "https://docs.example/stable",
                    "raw": "https://docs.example/stable",
                    "confidence": "high",
                    "pinned": true
                },
                {
                    "path": "skills/review/scripts/check.sh",
                    "line": 3,
                    "source": "script",
                    "kind": "http-endpoint",
                    "normalized": "https://collector.example/upload",
                    "raw": "https://collector.example/upload",
                    "confidence": "medium",
                    "pinned": false
                }
            ],
            "remote_dependencies": [],
            "package_managers": [],
            "lockfiles": [],
            "executables": [],
            "binaries": [],
            "checksums": [],
            "permissions": [
                {
                    "path": "skills/review/trust.yaml",
                    "line": 6,
                    "source": "trust-manifest",
                    "kind": "secrets",
                    "evidence": "declared",
                    "normalized": "secrets=REVIEW_TOKEN",
                    "raw": "REVIEW_TOKEN",
                    "confidence": "high"
                }
            ],
            "offline_readiness": []
        }));

        let view_model = HtmlReportViewModel::from_report(&report);

        assert_eq!(
            view_model
                .broken_references
                .iter()
                .map(|finding| location_display(&finding.location.path, finding.location.line))
                .collect::<Vec<_>>(),
            vec!["skills/review/SKILL.md:8"]
        );
        assert_eq!(
            view_model
                .external_urls
                .iter()
                .map(|url| url.normalized.as_str())
                .collect::<Vec<_>>(),
            vec![
                "https://docs.example/stable",
                "https://collector.example/upload"
            ]
        );
        assert_eq!(
            view_model
                .actual_secret_evidence
                .iter()
                .map(|evidence| match evidence {
                    SecretSecurityEvidence::Finding(finding) => {
                        format!("finding:{}", finding.rule_id)
                    }
                    SecretSecurityEvidence::Permission(permission) => {
                        format!("permission:{}", permission.normalized)
                    }
                })
                .collect::<Vec<_>>(),
            vec![
                "finding:SEC002",
                "finding:SEC003",
                "permission:secrets=REVIEW_TOKEN",
            ]
        );
        assert_eq!(
            view_model
                .prompt_secret_exposure_findings
                .iter()
                .map(|finding| finding.rule_id.as_str())
                .collect::<Vec<_>>(),
            Vec::<&str>::new()
        );
    }

    #[test]
    fn secret_summary_separates_actual_evidence_from_prompt_risk_text() {
        let report = report_with_packages_and_findings(
            vec![package(
                "skills/review",
                "skills/review/SKILL.md",
                Some("review"),
                Some("Review skills."),
            )],
            vec![
                finding(
                    "SEC002",
                    Severity::Medium,
                    FindingCategory::Security,
                    "Secret-like environment variable access",
                    "The artifact reads secret-like environment variable `SERVICE_TOKEN`.",
                    "skills/review/scripts/check.sh",
                    Some(3),
                ),
                finding(
                    "SEC011",
                    Severity::Medium,
                    FindingCategory::Security,
                    "Prompt-injection-like instruction",
                    "The text asks an agent to ignore policy and expose secrets.",
                    "skills/review/SKILL.md",
                    Some(8),
                ),
            ],
        );

        assert_eq!(report.summary.actual_secret_evidence_count, 1);
        assert_eq!(report.summary.prompt_secret_exposure_count, 1);

        let summary = render_summary(&report);
        assert!(summary.contains("Actual secret evidence: 1"));
        assert!(summary.contains("Prompt secret exposure signals: 1"));

        let value: Value =
            serde_json::from_str(&render_json(&report).expect("render JSON")).expect("parse JSON");
        assert_eq!(value["summary"]["actual_secret_evidence_count"], 1);
        assert_eq!(value["summary"]["prompt_secret_exposure_count"], 1);

        let html = render_html(&report);
        assert!(html.contains("Actual secret evidence"));
        assert!(html.contains("Prompt Secret Exposure Signals"));
        assert!(html.contains("SEC011"));
    }

    #[test]
    fn html_view_model_groups_findings_by_manifest_then_root_prefix_with_unmatched_group() {
        let report = report_with_packages_and_findings(
            vec![
                package(
                    "skills/review",
                    "skills/review/SKILL.md",
                    Some("review"),
                    None,
                ),
                package(
                    "skills/review/nested",
                    "skills/review/nested/SKILL.md",
                    Some("nested"),
                    None,
                ),
                package("skills/other", "skills/other/SKILL.md", Some("other"), None),
            ],
            vec![
                finding(
                    "ROOT",
                    Severity::Low,
                    FindingCategory::Spec,
                    "Root manifest finding",
                    "Root manifest finding.",
                    "skills/review/SKILL.md",
                    Some(1),
                ),
                finding(
                    "NESTED",
                    Severity::High,
                    FindingCategory::Security,
                    "Nested script finding",
                    "Nested script finding.",
                    "skills/review/nested/scripts/run.sh",
                    Some(2),
                ),
                finding(
                    "UNMATCHED",
                    Severity::Info,
                    FindingCategory::Quality,
                    "Workspace finding",
                    "Workspace finding.",
                    "README.md",
                    Some(3),
                ),
            ],
        );

        let view_model = HtmlReportViewModel::from_report(&report);

        assert_eq!(
            view_model
                .finding_groups
                .iter()
                .map(|group| (
                    group
                        .package
                        .as_ref()
                        .map(|package| package.manifest_path.as_str()),
                    group
                        .findings
                        .iter()
                        .map(|finding| finding.rule_id.as_str())
                        .collect::<Vec<_>>()
                ))
                .collect::<Vec<_>>(),
            vec![
                (Some("skills/other/SKILL.md"), vec![]),
                (Some("skills/review/SKILL.md"), vec!["ROOT"]),
                (Some("skills/review/nested/SKILL.md"), vec!["NESTED"]),
                (None, vec!["UNMATCHED"]),
            ]
        );
    }

    #[test]
    fn html_view_model_includes_clean_packages_in_skill_groups() {
        let report = report_with_packages_and_findings(
            vec![
                package("skills/clean", "skills/clean/SKILL.md", Some("clean"), None),
                package("skills/risky", "skills/risky/SKILL.md", Some("risky"), None),
            ],
            vec![finding(
                "SKILL001",
                Severity::Low,
                FindingCategory::Spec,
                "Missing skill name",
                "The skill manifest does not declare a name.",
                "skills/risky/SKILL.md",
                Some(1),
            )],
        );

        let view_model = HtmlReportViewModel::from_report(&report);

        assert_eq!(
            view_model
                .finding_groups
                .iter()
                .map(|group| (
                    group
                        .package
                        .as_ref()
                        .map(|package| package.manifest_path.as_str()),
                    group.findings.len()
                ))
                .collect::<Vec<_>>(),
            vec![
                (Some("skills/clean/SKILL.md"), 0),
                (Some("skills/risky/SKILL.md"), 1),
            ]
        );
    }

    #[test]
    fn summary_output_includes_counts_and_no_finding_state() {
        let report = report_with_summary(2, 0, 4, 1, 0);

        let summary = render_summary(&report);

        assert_eq!(
            summary,
            format!(
                "Agent Skill Auditor scan summary\n{}\nPackages: 2\nFindings: 0\nSuppressed findings: 4\nInvalid manifests: 1\nBroken references: 0\nActual secret evidence: 0\nPrompt secret exposure signals: 0\n\nSupply chain:\nLicenses: 0 evidence\nTrust manifests: 0 total, 0 invalid\nExternal URLs: 0 total, 0 mutable\nDependencies: 0 observed, 0 unpinned\nDependency manifests: 0 total, 0 exact-pinned, 0 range-based\nLockfiles: 0 evidence\nInstall commands: 0 observed, 0 without reproducibility evidence\nExecutables: 0 evidence\nBinaries: 0 evidence\nChecksums: 0 evidence\nPermissions: 0 evidence, 0 conflicts\nOffline audit readiness: ready=0 partial=0 not-ready=0 unknown=0\n\nNo findings.",
                audit_metadata_summary(&report.audit)
            )
        );
        assert!(summary.contains("timestamp=null"));
    }

    #[test]
    fn summary_output_derives_groups_for_legacy_reports_without_finding_groups() {
        let mut report = review_skill_report(
            "SKILL001",
            Severity::Low,
            FindingCategory::Spec,
            "Missing skill name",
            "The skill manifest does not declare a name.",
            Some(1),
        );
        report.finding_groups.clear();

        let summary = render_summary(&report);

        assert!(summary.contains("Findings: 1"));
        assert!(summary.contains("Finding groups:\n"));
        assert!(summary.contains("SKILL001 [low/medium/spec] x1 packages=1"));
        assert!(summary.contains("sample: skills/review/SKILL.md:1"));
        assert!(!summary.contains("\nNo findings."));
    }

    #[test]
    fn json_output_includes_full_supply_chain_inventory_with_stable_keys() {
        let mut report = report_with_summary(0, 0, 0, 0, 0);
        report.supply_chain = supply_chain_inventory(json!({
            "licenses": [
                {
                    "path": "LICENSE",
                    "line": null,
                    "source": "filesystem",
                    "scope": "repository",
                    "normalized": "LICENSE",
                    "raw": null,
                    "confidence": "high"
                }
            ],
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
                    "score": 100,
                    "reasons": ["all referenced local files are present"]
                }
            ]
        }));

        let rendered = render_json(&report).expect("render JSON report");
        let value: Value = serde_json::from_str(&rendered).expect("parse JSON report");
        let supply_chain = value["supply_chain"].as_object().expect("supply_chain");
        let mut keys = supply_chain.keys().cloned().collect::<Vec<_>>();
        keys.sort();

        assert_eq!(
            keys,
            vec![
                "binaries",
                "checksums",
                "dependency_manifests",
                "executables",
                "external_urls",
                "licenses",
                "lockfiles",
                "offline_readiness",
                "package_managers",
                "permissions",
                "remote_dependencies",
                "trust_manifests",
            ]
        );
        assert_eq!(value["supply_chain"]["licenses"][0]["path"], "LICENSE");
        assert_eq!(
            value["supply_chain"]["offline_readiness"][0]["status"],
            "ready"
        );
    }

    #[test]
    fn summary_output_includes_clean_supply_chain_counts() {
        let mut report = report_with_summary(1, 0, 0, 0, 0);
        report.supply_chain = supply_chain_inventory(json!({
            "licenses": [
                {
                    "path": "LICENSE",
                    "line": null,
                    "source": "filesystem",
                    "scope": "repository",
                    "normalized": "LICENSE",
                    "raw": null,
                    "confidence": "high"
                }
            ],
            "trust_manifests": [],
            "external_urls": [],
            "remote_dependencies": [],
            "dependency_manifests": [
                {
                    "path": "requirements.txt",
                    "line": 1,
                    "source": "dependency-manifest",
                    "manager": "pip",
                    "normalized": "requirements.txt",
                    "raw": "requirements.txt",
                    "confidence": "high",
                    "dependency_count": 2,
                    "unpinned_dependency_count": 0,
                    "pinning": "exact-pinned"
                }
            ],
            "package_managers": [],
            "lockfiles": [
                {
                    "path": "package-lock.json",
                    "line": null,
                    "source": "lockfile",
                    "manager": "npm",
                    "normalized": "package-lock.json",
                    "raw": null,
                    "confidence": "high"
                }
            ],
            "executables": [],
            "binaries": [],
            "checksums": [],
            "permissions": [],
            "offline_readiness": [
                {
                    "path": "SKILL.md",
                    "status": "ready",
                    "score": 100,
                    "reasons": ["all referenced local files are present"]
                }
            ]
        }));

        let summary = render_summary(&report);

        assert_in_order(
            &summary,
            &[
                "Supply chain:",
                "Licenses: 1 evidence",
                "Trust manifests: 0 total, 0 invalid",
                "External URLs: 0 total, 0 mutable",
                "Dependencies: 0 observed, 0 unpinned",
                "Dependency manifests: 1 total, 1 exact-pinned, 0 range-based",
                "Lockfiles: 1 evidence",
                "Install commands: 0 observed, 0 without reproducibility evidence",
                "Executables: 0 evidence",
                "Binaries: 0 evidence",
                "Checksums: 0 evidence",
                "Permissions: 0 evidence, 0 conflicts",
                "Offline audit readiness: ready=1 partial=0 not-ready=0 unknown=0",
                "No findings.",
            ],
        );
    }

    #[test]
    fn summary_output_includes_finding_heavy_supply_chain_counts() {
        let mut report = report_with_findings(vec![
            finding(
                "SUPPLY003",
                Severity::Medium,
                FindingCategory::Reproducibility,
                "Install command without matching reproducibility evidence",
                "npm install is not paired with matching reproducibility evidence.",
                "scripts/install.sh",
                Some(2),
            ),
            finding(
                "SUPPLY009",
                Severity::Medium,
                FindingCategory::Security,
                "Observed permission conflicts with trust manifest",
                "Network access conflicts with declared permissions.",
                "scripts/upload.sh",
                Some(4),
            ),
        ]);
        report.supply_chain = supply_chain_inventory(json!({
            "licenses": [],
            "trust_manifests": [
                {
                    "path": "agent-audit.trust.yaml",
                    "line": null,
                    "source": "trust-manifest",
                    "format": "agent-audit",
                    "normalized": "agent-audit.trust.yaml",
                    "raw": null,
                    "confidence": "high",
                    "valid": false,
                    "diagnostics": [],
                    "skill": null,
                    "provenance": null,
                    "permissions": null,
                    "declared_dependencies": {
                        "commands": [],
                        "packages": []
                    }
                }
            ],
            "external_urls": [
                {
                    "path": "SKILL.md",
                    "line": 8,
                    "source": "markdown-link",
                    "kind": "github-raw",
                    "normalized": "https://raw.githubusercontent.com/org/repo/main/install.sh",
                    "raw": "https://raw.githubusercontent.com/org/repo/main/install.sh",
                    "confidence": "high",
                    "pinned": false
                }
            ],
            "remote_dependencies": [
                {
                    "path": "package.json",
                    "line": 4,
                    "source": "package-manifest",
                    "kind": "package",
                    "package_manager": "npm",
                    "name": "left-pad",
                    "version": "^1.3.0",
                    "normalized": "left-pad@^1.3.0",
                    "raw": "\"left-pad\": \"^1.3.0\"",
                    "confidence": "high",
                    "pinned": false
                }
            ],
            "dependency_manifests": [
                {
                    "path": "requirements.txt",
                    "line": 1,
                    "source": "dependency-manifest",
                    "manager": "pip",
                    "normalized": "requirements.txt",
                    "raw": "requirements.txt",
                    "confidence": "high",
                    "dependency_count": 1,
                    "unpinned_dependency_count": 1,
                    "pinning": "range-based"
                }
            ],
            "package_managers": [
                {
                    "path": "scripts/install.sh",
                    "line": 2,
                    "source": "script",
                    "manager": "npm",
                    "manifest_path": null,
                    "normalized": "npm install",
                    "raw": "npm install left-pad",
                    "confidence": "high"
                }
            ],
            "lockfiles": [],
            "executables": [
                {
                    "path": "scripts/install.sh",
                    "line": null,
                    "source": "filesystem",
                    "kind": "script",
                    "language": "shell",
                    "reason": "shell script",
                    "referenced": true,
                    "normalized": "scripts/install.sh",
                    "raw": null,
                    "confidence": "high"
                }
            ],
            "binaries": [
                {
                    "path": "bin/helper.exe",
                    "line": null,
                    "source": "filesystem",
                    "kind": "executable",
                    "size_bytes": 4,
                    "referenced": true,
                    "normalized": "bin/helper.exe",
                    "raw": null,
                    "confidence": "high"
                }
            ],
            "checksums": [],
            "permissions": [
                {
                    "path": "scripts/upload.sh",
                    "line": 4,
                    "source": "script",
                    "kind": "network",
                    "evidence": "observed",
                    "normalized": "curl",
                    "raw": "curl https://example.com",
                    "confidence": "high"
                }
            ],
            "offline_readiness": [
                {
                    "path": "SKILL.md",
                    "status": "partial",
                    "score": 55,
                    "reasons": ["1 unpinned remote URL"]
                },
                {
                    "path": "nested/SKILL.md",
                    "status": "not-ready",
                    "score": 0,
                    "reasons": ["downloaded executable has no checksum"]
                }
            ]
        }));

        let summary = render_summary(&report);

        assert_in_order(
            &summary,
            &[
                "Supply chain:",
                "Licenses: 0 evidence",
                "Trust manifests: 1 total, 1 invalid",
                "External URLs: 1 total, 1 mutable",
                "Dependencies: 1 observed, 1 unpinned",
                "Dependency manifests: 1 total, 0 exact-pinned, 1 range-based",
                "Lockfiles: 0 evidence",
                "Install commands: 1 observed, 1 without reproducibility evidence",
                "Executables: 1 evidence",
                "Binaries: 1 evidence",
                "Checksums: 0 evidence",
                "Permissions: 1 evidence, 1 conflicts",
                "Offline audit readiness: ready=0 partial=1 not-ready=1 unknown=0",
                "Finding groups:",
                "SUPPLY003 [medium/medium/reproducibility] x1 packages=0 command_pattern=npm install package_manager=npm: Install command without matching reproducibility evidence",
                "sample: scripts/install.sh:2: npm install is not paired with matching reproducibility evidence.",
                "SUPPLY009 [medium/medium/security] x1 packages=0 evidence=network access conflicts with declared permissions: Observed permission conflicts with trust manifest",
                "sample: scripts/upload.sh:4: Network access conflicts with declared permissions.",
            ],
        );
    }

    #[test]
    fn summary_output_does_not_count_requirements_manifests_as_lockfiles() {
        let mut report = report_with_summary(1, 0, 0, 0, 0);
        report.supply_chain = supply_chain_inventory(json!({
            "licenses": [],
            "trust_manifests": [],
            "external_urls": [],
            "remote_dependencies": [],
            "dependency_manifests": [
                {
                    "path": "requirements.txt",
                    "line": 1,
                    "source": "dependency-manifest",
                    "manager": "pip",
                    "normalized": "requirements.txt",
                    "raw": "requirements.txt",
                    "confidence": "high",
                    "dependency_count": 1,
                    "unpinned_dependency_count": 0,
                    "pinning": "exact-pinned"
                },
                {
                    "path": "range/requirements.txt",
                    "line": 1,
                    "source": "dependency-manifest",
                    "manager": "pip",
                    "normalized": "requirements.txt",
                    "raw": "requirements.txt",
                    "confidence": "high",
                    "dependency_count": 1,
                    "unpinned_dependency_count": 1,
                    "pinning": "range-based"
                }
            ],
            "package_managers": [],
            "lockfiles": [],
            "executables": [],
            "binaries": [],
            "checksums": [],
            "permissions": [],
            "offline_readiness": []
        }));

        let summary = render_summary(&report);

        assert!(summary.contains("Dependency manifests: 2 total, 1 exact-pinned, 1 range-based"));
        assert!(summary.contains("Lockfiles: 0 evidence"));
        assert!(
            summary.contains("Install commands: 0 observed, 0 without reproducibility evidence")
        );
        assert!(!summary.contains("Lockfiles: 2 evidence"));
        assert!(!summary.contains("without nearby lockfile"));
    }

    #[test]
    fn html_package_inventory_distinguishes_dependency_manifests_and_lockfiles() {
        let mut report = report_with_summary(1, 0, 0, 0, 0);
        report.supply_chain = supply_chain_inventory(json!({
            "licenses": [],
            "trust_manifests": [],
            "external_urls": [],
            "remote_dependencies": [],
            "dependency_manifests": [
                {
                    "path": "requirements.txt",
                    "line": 1,
                    "source": "dependency-manifest",
                    "manager": "pip",
                    "normalized": "requirements.txt",
                    "raw": "requirements.txt",
                    "confidence": "high",
                    "dependency_count": 1,
                    "unpinned_dependency_count": 0,
                    "pinning": "exact-pinned"
                }
            ],
            "package_managers": [
                {
                    "path": "scripts/install.sh",
                    "line": 2,
                    "source": "script",
                    "manager": "pip",
                    "manifest_path": null,
                    "normalized": "pip install",
                    "raw": "pip install -r requirements.txt",
                    "confidence": "high"
                }
            ],
            "lockfiles": [
                {
                    "path": "uv.lock",
                    "line": 1,
                    "source": "lockfile",
                    "manager": "uv",
                    "normalized": "uv.lock",
                    "raw": "uv.lock",
                    "confidence": "high"
                }
            ],
            "executables": [],
            "binaries": [],
            "checksums": [],
            "permissions": [],
            "offline_readiness": []
        }));

        let html = render_html(&report);
        let section = html_section(&html, "packages");

        assert!(section.contains("Dependency manifests"));
        assert!(section.contains("Lockfiles"));
        assert!(section.contains("Without reproducibility evidence"));
        assert!(section.contains(">dependency manifest<"));
        assert!(section.contains(">install command<"));
        assert!(section.contains(">lockfile<"));
        assert!(section.contains(">exact-pinned<"));
    }

    #[test]
    fn summary_output_includes_compatibility_totals_and_rows() {
        let mut report = report_with_summary(2, 1, 0, 0, 0);
        report.compatibility = serde_json::from_value(json!({
            "profiles": ["agent-skills-spec", "codex", "generic", "future-host"],
            "matrix": [
                {
                    "path": "alpha/SKILL.md",
                    "name": "alpha",
                    "profiles": [
                        {
                            "profile": "agent-skills-spec",
                            "status": "pass",
                            "finding_ids": []
                        },
                        {
                            "profile": "codex",
                            "status": "warn",
                            "finding_ids": ["SKILL050"]
                        },
                        {
                            "profile": "generic",
                            "status": "pass",
                            "finding_ids": []
                        },
                        {
                            "profile": "future-host",
                            "status": "untested",
                            "finding_ids": []
                        }
                    ]
                },
                {
                    "path": "beta/SKILL.md",
                    "name": null,
                    "profiles": [
                        {
                            "profile": "agent-skills-spec",
                            "status": "fail",
                            "finding_ids": ["SKILL002"]
                        },
                        {
                            "profile": "codex",
                            "status": "unknown",
                            "finding_ids": []
                        },
                        {
                            "profile": "generic",
                            "status": "warn",
                            "finding_ids": ["SKILL040"]
                        },
                        {
                            "profile": "future-host",
                            "status": "untested",
                            "finding_ids": []
                        }
                    ]
                }
            ]
        }))
        .expect("compatibility matrix fixture");

        let summary = render_summary(&report);

        assert_in_order(
            &summary,
            &[
                "Broken references: 0",
                "Compatibility:",
                "Profiles: agent-skills-spec, codex, generic, future-host",
                "Status totals: pass=2 warn=2 fail=1 unknown=1 untested=2",
                "Profile totals:",
                "- agent-skills-spec: pass=1 warn=0 fail=1 unknown=0 untested=0",
                "- codex: pass=0 warn=1 fail=0 unknown=1 untested=0",
                "- generic: pass=1 warn=1 fail=0 unknown=0 untested=0",
                "- future-host: pass=0 warn=0 fail=0 unknown=0 untested=2",
                "Rows:",
                "- alpha/SKILL.md (alpha): agent-skills-spec=pass, codex=warn(SKILL050), generic=pass, future-host=untested",
                "- beta/SKILL.md: agent-skills-spec=fail(SKILL002), codex=unknown, generic=warn(SKILL040), future-host=untested",
                "No findings.",
            ],
        );
    }

    #[test]
    fn summary_output_handles_profile_selection_without_matrix_rows() {
        let mut report = report_with_summary(0, 0, 0, 0, 0);
        report.compatibility = CompatibilityMatrix {
            profiles: vec!["codex".to_owned(), "generic".to_owned()],
            matrix: Vec::new(),
        };

        let summary = render_summary(&report);

        assert!(summary.contains("Profiles: codex, generic"));
        assert!(summary.contains("Status totals: pass=0 warn=0 fail=0 unknown=0 untested=0"));
        assert!(!summary.contains("Rows:\n"));
    }

    #[test]
    fn summary_output_omits_large_compatibility_row_sets() {
        let mut report = report_with_summary(6, 0, 0, 0, 0);
        let matrix = (0..6)
            .map(|index| {
                json!({
                    "path": format!("skill-{index}/SKILL.md"),
                    "name": format!("skill-{index}"),
                    "profiles": [
                        {
                            "profile": "codex",
                            "status": "warn",
                            "finding_ids": []
                        }
                    ]
                })
            })
            .collect::<Vec<_>>();
        report.compatibility = serde_json::from_value(json!({
            "profiles": ["codex"],
            "matrix": matrix
        }))
        .expect("compatibility matrix fixture");

        let summary = render_summary(&report);

        assert!(summary.contains("- codex: pass=0 warn=6 fail=0 unknown=0 untested=0"));
        assert!(summary.contains("Rows: 6 packages omitted from summary"));
        assert!(!summary.contains("skill-0/SKILL.md"));
    }

    #[test]
    fn summary_output_orders_finding_groups_and_uses_lowercase_metadata() {
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
                "Finding groups:",
                "SEC005 [high/medium/security] x1 packages=0 evidence=line two: Use of sudo",
                "sample: alpha/SKILL.md:2: Line two.",
                "SKILL001 [info/medium/quality] x1 packages=0 evidence=line one: Missing skill name",
                "sample: alpha/SKILL.md:1: Line one.",
                "SKILL010 [low/medium/compatibility] x1 packages=0 evidence=no line sorts before line: Broken relative reference",
                "sample: alpha/SKILL.md: No line sorts before line.",
                "SKILL020 [medium/medium/spec] x1 packages=0 evidence=later path: Oversized skill manifest",
                "sample: zeta/SKILL.md:1: Later path.",
            ],
        );
    }

    #[test]
    fn default_summary_mode_keeps_grouped_limited_samples() {
        let report = repeated_finding_report(4);

        let summary = render_summary_with_mode(&report, ReportMode::Default);

        assert!(summary.contains("Agent Skill Auditor scan summary"));
        assert!(summary.contains("Finding groups:"));
        assert!(summary.contains("sample: skills/repeated-0/scripts/install.sh:2"));
        assert!(summary.contains("sample: skills/repeated-1/scripts/install.sh:2"));
        assert!(summary.contains("sample: skills/repeated-2/scripts/install.sh:2"));
        assert!(!summary.contains("skills/repeated-3/scripts/install.sh:2"));
        assert!(!summary.contains("Full findings:"));
    }

    #[test]
    fn default_summary_includes_observed_ecosystem_patterns_when_present() {
        let mut report = repeated_finding_report(4);
        report.patterns = vec![EcosystemPattern {
            id: "dependency-reproducibility-gaps".to_owned(),
            title: "Dependency reproducibility gaps in executable skills".to_owned(),
            summary:
                "Executable dependency setup has reproducibility gaps in 4 of 4 packages (100%)."
                    .to_owned(),
            count: 4,
            affected_package_count: 4,
            affected_package_percent: 100,
            evidence: vec![],
        }];

        let summary = render_summary(&report);

        assert!(summary.contains("Observed ecosystem patterns:"));
        assert!(summary.contains("- Dependency reproducibility gaps in executable skills: Executable dependency setup has reproducibility gaps in 4 of 4 packages (100%). count=4 packages=100%"));
    }

    #[test]
    fn verbose_summary_mode_expands_all_findings() {
        let report = repeated_finding_report(4);

        let summary = render_summary_with_mode(&report, ReportMode::Verbose);

        assert!(summary.contains("Agent Skill Auditor verbose scan summary"));
        assert!(summary.contains("Full findings:"));
        assert!(summary.contains("skills/repeated-0/scripts/install.sh:2"));
        assert!(summary.contains("skills/repeated-1/scripts/install.sh:2"));
        assert!(summary.contains("skills/repeated-2/scripts/install.sh:2"));
        assert!(summary.contains("skills/repeated-3/scripts/install.sh:2"));
        assert!(summary.contains("why: Package install without lockfile rationale."));
        assert!(!summary.contains("Finding groups:"));
    }

    #[test]
    fn research_summary_mode_keeps_groups_and_adds_normalized_full_evidence() {
        let report = repeated_finding_report(4);

        let summary = render_summary_with_mode(&report, ReportMode::Research);

        assert!(summary.contains("Agent Skill Auditor research scan summary"));
        assert!(summary.contains("Audit: "));
        assert!(summary.contains("timestamp=null"));
        assert!(summary.contains("Finding groups:"));
        assert!(summary.contains("normalized_key=SEC009|medium|security|"));
        assert!(summary.contains("evidence_key="));
        assert!(summary.contains("Full findings:"));
        assert!(summary.contains(
            "normalized_key: skills/repeated-3/scripts/install.sh|2|SEC009|medium|security|"
        ));
    }

    #[test]
    fn ci_summary_mode_is_compact_and_reports_top_groups() {
        let report = repeated_finding_report(4);

        let summary = render_summary_with_mode(&report, ReportMode::Ci);

        assert!(summary.contains("Agent Skill Auditor CI scan summary"));
        assert!(summary.contains("Severity totals: critical=0 high=0 medium=4 low=0 info=0"));
        assert!(summary.contains("Category totals: spec=0 compatibility=0 security=4 quality=0 portability=0 reproducibility=0"));
        assert!(summary.contains(
            "Top finding groups: showing 1 of 1 canonical groups (filtered for CI log size)."
        ));
        assert!(summary.contains("filtered for CI log size"));
        assert!(summary.contains("SEC009 [medium/medium/security] x4 packages=4"));
        assert!(summary.contains("fingerprint=fnv1a64:"));
        assert!(!summary.contains("sample:"));
        assert!(!summary.contains("Full findings:"));
        assert!(!summary.contains("Supply chain:"));
    }

    #[test]
    fn json_output_uses_report_renderer() {
        let report = review_skill_report(
            "SKILL002",
            Severity::Low,
            FindingCategory::Spec,
            "Missing skill description",
            "The skill manifest does not declare a description.",
            Some(2),
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
            finding(
                "CUSTOM001",
                Severity::Medium,
                FindingCategory::Quality,
                "Custom explanation",
                "Custom finding message.",
                "skills/custom/SKILL.md",
                Some(4),
            ),
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
        let report = review_skill_report(
            "SKILL010",
            Severity::Low,
            FindingCategory::Spec,
            "Broken relative reference",
            "The referenced file could not be found.",
            Some(12),
        );

        let html = render_html(&report);

        assert!(html.contains("<h2 id=\"summary\">Executive Summary</h2>"));
        assert!(html.contains("<h2 id=\"packages\">Packages</h2>"));
        assert!(html.contains("<h2 id=\"findings\">Finding Groups</h2>"));
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
    fn html_output_places_ecosystem_patterns_near_top() {
        let mut report = repeated_finding_report(2);
        report.patterns = vec![EcosystemPattern {
            id: "dependency-reproducibility-gaps".to_owned(),
            title: "Dependency reproducibility gaps in executable skills".to_owned(),
            summary:
                "Executable dependency setup has reproducibility gaps in 2 of 2 packages (100%)."
                    .to_owned(),
            count: 2,
            affected_package_count: 2,
            affected_package_percent: 100,
            evidence: vec![agent_audit_core::EcosystemPatternEvidence {
                kind: "SEC009".to_owned(),
                count: 2,
            }],
        }];

        let html = render_html(&report);

        assert_in_order(
            &html,
            &[
                "<h2 id=\"summary\">Executive Summary</h2>",
                "<h2 id=\"ecosystem-patterns\">Observed Ecosystem Patterns</h2>",
                "<h2 id=\"risk-distribution\">Risk Distribution</h2>",
            ],
        );
        assert!(html.contains("<td>Dependency reproducibility gaps in executable skills</td>"));
        assert!(html.contains("<td>2 (100%)</td>"));
        assert!(html.contains("SEC009=2"));
    }

    #[test]
    fn html_output_renders_grouped_findings_with_counts_dimensions_and_samples() {
        let report = report_with_packages_and_findings(
            vec![
                package("skills/alpha", "skills/alpha/SKILL.md", Some("alpha"), None),
                package("skills/beta", "skills/beta/SKILL.md", Some("beta"), None),
            ],
            vec![
                finding(
                    "SEC009",
                    Severity::Medium,
                    FindingCategory::Security,
                    "Package install without lockfile",
                    "The artifact runs a JavaScript package install without nearby lockfile evidence.",
                    "skills/alpha/scripts/install.sh",
                    Some(2),
                ),
                finding(
                    "SEC009",
                    Severity::Medium,
                    FindingCategory::Security,
                    "Package install without lockfile",
                    "The artifact runs a JavaScript package install without nearby lockfile evidence.",
                    "skills/beta/scripts/install.sh",
                    Some(3),
                ),
            ],
        );

        let html = render_html(&report);

        assert!(html.contains("<h2 id=\"findings\">Finding Groups</h2>"));
        assert!(html.contains("<td>SEC009</td>"));
        assert!(html.contains("<td>2</td><td>2<br><span class=\"finding-ids\">skills/alpha/SKILL.md, skills/beta/SKILL.md</span></td>"));
        assert!(html.contains("<td>command_pattern=javascript package install</td>"));
        assert!(html.contains("skills/alpha/scripts/install.sh:2: The artifact runs a JavaScript package install without nearby lockfile evidence."));
        assert!(html.contains("skills/beta/scripts/install.sh:3: The artifact runs a JavaScript package install without nearby lockfile evidence."));
    }

    #[test]
    fn html_verbose_mode_renders_expanded_full_findings() {
        let report = repeated_finding_report(4);

        let html = render_html_with_mode(&report, ReportMode::Verbose);

        assert!(html.contains("<h2 id=\"findings\">Findings</h2>"));
        assert!(!html.contains("<h2 id=\"findings\">Finding Groups</h2>"));
        assert!(html.contains("skills/repeated-0/scripts/install.sh:2"));
        assert!(html.contains("skills/repeated-1/scripts/install.sh:2"));
        assert!(html.contains("skills/repeated-2/scripts/install.sh:2"));
        assert!(html.contains("skills/repeated-3/scripts/install.sh:2"));
        assert!(html.contains("Package install without lockfile rationale."));
        assert!(html.contains("Package install without lockfile remediation."));
    }

    #[test]
    fn html_research_mode_renders_groups_and_full_normalized_evidence() {
        let report = repeated_finding_report(4);

        let html = render_html_with_mode(&report, ReportMode::Research);

        assert!(html.contains("<h2 id=\"findings\">Finding Groups</h2>"));
        assert!(html.contains("<h2 id=\"full-finding-evidence\">Full Finding Evidence</h2>"));
        assert!(html.contains("<th>Normalized key</th>"));
        assert!(html.contains("skills/repeated-3/scripts/install.sh|2|SEC009|medium|security|"));
    }

    #[test]
    fn html_ci_mode_renders_log_sized_report() {
        let report = repeated_finding_report(4);

        let html = render_html_with_mode(&report, ReportMode::Ci);

        assert!(html.contains("<h2 id=\"summary\">Executive Summary</h2>"));
        assert!(html.contains("<h2 id=\"ci-summary\">CI Summary</h2>"));
        assert!(html.contains("Top Finding Groups"));
        assert!(html.contains("SEC009"));
        assert!(!html.contains("<h2 id=\"packages\">Packages</h2>"));
        assert!(!html.contains("<h2 id=\"skill-details\">Skill Details</h2>"));
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
        assert!(html.contains("<tr><td colspan=\"14\">No findings.</td></tr>"));
        assert!(!html.contains("<h2 id=\"compatibility\">Compatibility</h2>"));
    }

    #[test]
    fn html_output_includes_compatibility_matrix_and_finding_context() {
        let mut report = report_with_packages_and_findings(
            vec![package(
                "skills/deploy",
                "skills/deploy/SKILL.md",
                Some("deploy-helper"),
                Some("Deploys services."),
            )],
            vec![
                finding(
                    "SKILL050",
                    Severity::Low,
                    FindingCategory::Compatibility,
                    "Ignored host-specific metadata",
                    "Claude Code may ignore the custom metadata.",
                    "skills/deploy/SKILL.md",
                    Some(3),
                ),
                finding(
                    "HOST030",
                    Severity::Medium,
                    FindingCategory::Compatibility,
                    "Unsupported script artifact",
                    "Codex requires script review before use.",
                    "skills/deploy/SKILL.md",
                    Some(9),
                ),
            ],
        );
        report.compatibility = serde_json::from_value(json!({
            "profiles": ["agent-skills-spec", "claude-code", "codex"],
            "matrix": [
                {
                    "path": "skills/deploy/SKILL.md",
                    "name": "deploy-helper",
                    "profiles": [
                        {
                            "profile": "agent-skills-spec",
                            "status": "pass",
                            "finding_ids": []
                        },
                        {
                            "profile": "claude-code",
                            "status": "warn",
                            "finding_ids": ["SKILL050"]
                        },
                        {
                            "profile": "codex",
                            "status": "fail",
                            "finding_ids": ["HOST030"]
                        }
                    ]
                }
            ]
        }))
        .expect("compatibility matrix fixture");

        let html = render_html(&report);

        assert!(html.contains("<h2 id=\"compatibility\">Compatibility / Host Support</h2>"));
        assert!(html.contains("<th>Package path</th><th>Skill</th><th>agent-skills-spec</th><th>claude-code</th><th>codex</th>"));
        assert!(html.contains("<td>skills/deploy/SKILL.md</td><td>deploy-helper</td>"));
        assert!(html.contains("<span class=\"status status-pass\">pass</span>"));
        assert!(html.contains("<span class=\"status status-warn\">warn</span><br><span class=\"finding-ids\">SKILL050</span>"));
        assert!(html.contains("<span class=\"status status-fail\">fail</span><br><span class=\"finding-ids\">HOST030</span>"));
        assert!(html.contains("<h3>Compatibility Details</h3>"));
        assert!(
            html.contains("skills/deploy/SKILL.md:3: Claude Code may ignore the custom metadata.")
        );
        assert!(html.contains("skills/deploy/SKILL.md:9: Codex requires script review before use."));
        assert_in_order(
            &html,
            &[
                "<h2 id=\"compatibility\">Compatibility / Host Support</h2>",
                "<h2 id=\"packages\">Packages</h2>",
                "<h2 id=\"findings\">Finding Groups</h2>",
            ],
        );
    }

    #[test]
    fn html_output_escapes_compatibility_report_strings_as_plain_text() {
        let mut report = report_with_packages_and_findings(
            Vec::new(),
            vec![finding(
                "HOST<script>",
                Severity::Low,
                FindingCategory::Compatibility,
                "<title>",
                "</td><script>alert('context')</script>",
                "skills/<path>/SKILL.md",
                Some(4),
            )],
        );
        report.compatibility = serde_json::from_value(json!({
            "profiles": ["codex<script>"],
            "matrix": [
                {
                    "path": "skills/<path>/SKILL.md",
                    "name": "<skill>",
                    "profiles": [
                        {
                            "profile": "codex<script>",
                            "status": "warn",
                            "finding_ids": ["HOST<script>"]
                        }
                    ]
                }
            ]
        }))
        .expect("compatibility matrix fixture");

        let html = render_html(&report);

        assert!(html.contains("codex&lt;script&gt;"));
        assert!(html.contains("skills/&lt;path&gt;/SKILL.md"));
        assert!(html.contains("&lt;skill&gt;"));
        assert!(html.contains("HOST&lt;script&gt;"));
        assert!(html.contains("skills/&lt;path&gt;/SKILL.md:4: &lt;/td&gt;&lt;script&gt;alert(&#39;context&#39;)&lt;/script&gt;"));

        for raw in [
            "codex<script>",
            "skills/<path>/SKILL.md",
            "<skill>",
            "HOST<script>",
            "</td><script>alert('context')</script>",
        ] {
            assert!(
                !html.contains(raw),
                "raw dangerous compatibility value was rendered: {raw}"
            );
        }
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
                "Later path.",
                "Second message.",
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
        assert!(first.contains("<th>Timestamp</th><td>null</td>"));
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
                finding(
                    "SEC<001>",
                    Severity::High,
                    FindingCategory::Security,
                    "<x-title>",
                    "</td><script>alert('message')</script>",
                    "skills/<finding>/SKILL.md",
                    Some(7),
                ),
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
        let packages = html_section(&html, "packages");

        assert!(packages.contains(
            "<tr><td></td><td></td><td>skills/empty/SKILL.md</td><td>skills/empty</td></tr>"
        ));
        assert!(!packages.contains("None"));
        assert!(!packages.contains("Some("));
        assert!(!packages.contains("null"));
    }

    #[test]
    fn default_summary_uses_canonical_dependency_reproducibility_finding_groups() {
        let report = dependency_reproducibility_report();

        let summary = render_summary(&report);

        assert!(summary.contains("SEC009 [low/medium/security] x1 packages=1"));
        assert!(summary.contains("SUPPLY003 [medium/medium/reproducibility] x1 packages=1"));
        assert!(summary.contains("SUPPLY004 [medium/medium/reproducibility] x1 packages=1"));
        assert!(summary.contains(&report.finding_groups[0].group_fingerprint));
        let headline_lines = summary
            .lines()
            .filter(|line| {
                line.starts_with("SEC009")
                    || line.starts_with("SUPPLY003")
                    || line.starts_with("SUPPLY004")
            })
            .collect::<Vec<_>>();
        assert_eq!(
            headline_lines
                .iter()
                .map(|line| line.split(' ').next().unwrap())
                .collect::<Vec<_>>(),
            vec!["SEC009", "SUPPLY003", "SUPPLY004"]
        );
    }

    #[test]
    fn verbose_summary_preserves_expanded_dependency_reproducibility_findings() {
        let report = dependency_reproducibility_report();

        let summary = render_summary_with_mode(&report, ReportMode::Verbose);

        assert!(summary.contains("SEC009 [low/medium/security] skills/deps/scripts/install.sh:3"));
        assert!(summary.contains(
            "SUPPLY003 [medium/medium/reproducibility] skills/deps/scripts/install.sh:3"
        ));
        assert!(summary
            .contains("SUPPLY004 [medium/medium/reproducibility] skills/deps/package.json:7"));
        assert!(!summary.contains("Dependency install reproducibility risks"));
    }

    #[test]
    fn default_html_uses_canonical_dependency_reproducibility_finding_groups() {
        let report = dependency_reproducibility_report();

        let html = render_html(&report);
        let finding_groups = html_section(&html, "findings");

        assert!(finding_groups.contains("<td>SEC009</td>"));
        assert!(finding_groups.contains("<td>SUPPLY003</td>"));
        assert!(finding_groups.contains("<td>SUPPLY004</td>"));
        for group in &report.finding_groups {
            assert!(finding_groups.contains(&group.group_fingerprint));
        }
        assert!(!finding_groups.contains("SEC009/SUPPLY003/SUPPLY004"));
        assert!(!finding_groups.contains("Dependency install reproducibility risks"));
    }

    #[test]
    fn research_html_preserves_expanded_dependency_reproducibility_findings() {
        let report = dependency_reproducibility_report();

        let html = render_html_with_mode(&report, ReportMode::Research);
        let full_evidence = html_section(&html, "full-finding-evidence");

        assert!(full_evidence.contains("<td>SEC009</td>"));
        assert!(full_evidence.contains("<td>SUPPLY003</td>"));
        assert!(full_evidence.contains("<td>SUPPLY004</td>"));
    }

    #[test]
    fn json_and_sarif_preserve_dependency_reproducibility_findings() {
        let report = dependency_reproducibility_report();

        let json: Value =
            serde_json::from_str(&render_json(&report).expect("render JSON")).expect("parse JSON");
        assert_eq!(
            json["findings"]
                .as_array()
                .expect("findings array")
                .iter()
                .map(|finding| finding["rule_id"].as_str().expect("finding rule"))
                .collect::<Vec<_>>(),
            vec!["SEC009", "SUPPLY003", "SUPPLY004"]
        );
        assert_eq!(
            json["finding_groups"]
                .as_array()
                .expect("finding groups array")
                .iter()
                .map(|group| group["rule_id"].as_str().expect("group rule"))
                .collect::<Vec<_>>(),
            vec!["SEC009", "SUPPLY003", "SUPPLY004"]
        );

        let sarif = render_sarif_value(&report);
        assert_eq!(
            sarif_result_rule_ids(&sarif),
            vec!["SUPPLY004", "SEC009", "SUPPLY003"]
        );
    }

    #[test]
    fn finding_group_ids_and_fingerprints_are_consistent_across_rendered_formats() {
        let report = dependency_reproducibility_report();
        let expected = report
            .finding_groups
            .iter()
            .map(|group| (group.rule_id.as_str(), group.group_fingerprint.as_str()))
            .collect::<Vec<_>>();

        let default_summary = render_summary_with_mode(&report, ReportMode::Default);
        let research_summary = render_summary_with_mode(&report, ReportMode::Research);
        let html = render_html(&report);
        let json: Value =
            serde_json::from_str(&render_json(&report).expect("render JSON")).expect("parse JSON");
        let json_groups = json["finding_groups"].as_array().expect("finding groups");

        assert_eq!(
            summary_group_line_count(&default_summary, &expected),
            expected.len()
        );
        assert_eq!(
            summary_group_line_count(&research_summary, &expected),
            expected.len()
        );
        assert_eq!(html_group_row_count(&html, &expected), expected.len());
        assert_eq!(json_groups.len(), expected.len());

        for (rule_id, fingerprint) in expected {
            assert!(default_summary.contains(rule_id));
            assert!(default_summary.contains(fingerprint));
            assert!(research_summary.contains(rule_id));
            assert!(research_summary.contains(fingerprint));
            assert!(html.contains(&format!("<td>{rule_id}</td>")));
            assert!(html.contains(fingerprint));
            assert!(json_groups.iter().any(|group| {
                group["rule_id"] == rule_id && group["group_fingerprint"] == fingerprint
            }));
        }
        assert!(!default_summary.contains("SEC009/SUPPLY003/SUPPLY004"));
        assert!(!html.contains("SEC009/SUPPLY003/SUPPLY004"));
    }

    #[test]
    fn html_output_orders_finding_groups_by_rule_and_evidence() {
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
                "marker-02",
                "marker-03",
                "marker-04",
                "marker-05",
                "marker-01",
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
        ] {
            assert!(
                !html.contains(forbidden),
                "HTML should not contain external markup token {forbidden:?}"
            );
        }
    }

    #[test]
    fn html_output_includes_milestone_six_sections_in_order() {
        let mut report = report_with_packages_and_findings(
            vec![package(
                "skills/review",
                "skills/review/SKILL.md",
                Some("review"),
                Some("Review skills."),
            )],
            vec![
                finding(
                    "SEC002",
                    Severity::Medium,
                    FindingCategory::Security,
                    "Secret-like environment variable access",
                    "The script reads REVIEW_TOKEN.",
                    "skills/review/scripts/check.sh",
                    Some(4),
                ),
                finding(
                    "SKILL010",
                    Severity::Low,
                    FindingCategory::Spec,
                    "Broken relative reference",
                    "The referenced file could not be found.",
                    "skills/review/SKILL.md",
                    Some(8),
                ),
            ],
        );
        report.supply_chain = supply_chain_inventory(json!({
            "licenses": [],
            "trust_manifests": [],
            "external_urls": [
                {
                    "path": "skills/review/SKILL.md",
                    "line": 9,
                    "source": "markdown-link",
                    "kind": "documentation",
                    "normalized": "https://docs.example/review",
                    "raw": "https://docs.example/review",
                    "confidence": "high",
                    "pinned": true
                }
            ],
            "remote_dependencies": [
                {
                    "path": "skills/review/package.json",
                    "line": null,
                    "source": "package-manifest",
                    "kind": "package",
                    "package_manager": "npm",
                    "name": "zod",
                    "version": "3.22.0",
                    "normalized": "zod@3.22.0",
                    "raw": "zod",
                    "confidence": "high",
                    "pinned": true
                }
            ],
            "package_managers": [],
            "lockfiles": [],
            "executables": [],
            "binaries": [],
            "checksums": [],
            "permissions": [],
            "offline_readiness": [
                {
                    "path": "skills/review/SKILL.md",
                    "status": "partial",
                    "score": 70,
                    "reasons": ["external documentation URL"]
                }
            ]
        }));

        let html = render_html(&report);

        assert_in_order(
            &html,
            &[
                "<h2 id=\"audit-metadata\">Audit Metadata</h2>",
                "<h2 id=\"summary\">Executive Summary</h2>",
                "<h2 id=\"risk-distribution\">Risk Distribution</h2>",
                "<h2 id=\"top-risky-skills\">Top Risky Skills</h2>",
                "<h2 id=\"broken-references\">Broken References</h2>",
                "<h2 id=\"external-urls\">External URLs</h2>",
                "<h2 id=\"secret-usage\">Secret Usage</h2>",
                "<h2 id=\"offline-readiness\">Offline Audit Readiness</h2>",
                "<h2 id=\"packages\">Packages</h2>",
                "<h2 id=\"findings\">Finding Groups</h2>",
                "<h2 id=\"skill-details\">Skill Details</h2>",
            ],
        );
        assert!(html.contains("<th>Timestamp</th><td>null</td>"));
        assert!(html.contains("https://docs.example/review"));
        assert!(html.contains("zod@3.22.0"));
        assert!(html.contains("external documentation URL"));
    }

    #[test]
    fn html_output_renders_external_url_text_without_loading_links_or_assets() {
        let mut report = report_with_packages_and_findings(Vec::new(), Vec::new());
        report.supply_chain = supply_chain_inventory(json!({
            "licenses": [],
            "trust_manifests": [],
            "external_urls": [
                {
                    "path": "skills/review/SKILL.md",
                    "line": 3,
                    "source": "markdown-link",
                    "kind": "documentation",
                    "normalized": "https://docs.example/path?x=1&y=<tag>",
                    "raw": "https://docs.example/path?x=1&y=<tag>",
                    "confidence": "high",
                    "pinned": null
                }
            ],
            "remote_dependencies": [],
            "package_managers": [],
            "lockfiles": [],
            "executables": [],
            "binaries": [],
            "checksums": [],
            "permissions": [],
            "offline_readiness": []
        }));

        let html = render_html(&report);

        assert!(html.contains("https://docs.example/path?x=1&amp;y=&lt;tag&gt;"));
        assert!(!html.contains("<a "));
        assert!(!html.contains("href="));
        assert!(!html.contains("src="));
        assert!(!html.contains("@import"));
        assert!(!html.contains("url("));
    }

    #[test]
    fn html_output_renders_per_skill_detail_anchors_without_links() {
        let report = report_with_packages_and_findings(
            vec![
                package("skills/clean", "skills/clean/SKILL.md", Some("clean"), None),
                package(
                    "skills/review",
                    "skills/review/SKILL.md",
                    Some("review"),
                    None,
                ),
            ],
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

        assert!(html.contains("<section class=\"skill-detail\" id=\"skill-detail-1\">"));
        assert!(html.contains("<h3>clean</h3>"));
        assert!(html.contains("<tr><th>Anchor</th><td>skill-detail-1</td></tr>"));
        assert!(html.contains("<td colspan=\"5\">No findings for this package.</td>"));
        assert!(html.contains("<section class=\"skill-detail\" id=\"skill-detail-2\">"));
        assert!(html.contains("<h3>review</h3>"));
        assert!(html.contains("<tr><th>Anchor</th><td>skill-detail-2</td></tr>"));
        assert!(!html.contains("href="));
    }

    #[test]
    fn html_output_derives_finding_groups_for_legacy_reports_without_finding_groups() {
        let mut report = review_skill_report(
            "SKILL001",
            Severity::Low,
            FindingCategory::Spec,
            "Missing skill name",
            "The skill manifest does not declare a name.",
            Some(1),
        );
        report.finding_groups.clear();

        let html = render_html(&report);

        assert!(html.contains("<h2 id=\"findings\">Finding Groups</h2>"));
        assert!(html.contains("<td>SKILL001</td>"));
        assert!(html.contains("<td>spec</td>"));
        assert!(html.contains(
            "<td>1</td><td>1<br><span class=\"finding-ids\">skills/review/SKILL.md</span></td>"
        ));
        assert!(
            html.contains("skills/review/SKILL.md:1: The skill manifest does not declare a name.")
        );
        assert!(!html.contains("<td colspan=\"14\">No findings.</td>"));
    }

    #[test]
    fn html_output_escapes_new_section_strings() {
        let mut report = report_with_packages_and_findings(
            vec![package(
                "skills/<root>",
                "skills/<root>/SKILL.md",
                Some("<skill>"),
                Some("<description>"),
            )],
            vec![
                finding_with_details(
                    finding(
                        "SKILL010",
                        Severity::Low,
                        FindingCategory::Spec,
                        "<broken>",
                        "</td><script>alert('broken')</script>",
                        "skills/<root>/SKILL.md",
                        Some(2),
                    ),
                    "<rationale>",
                    "<fix>",
                    "<suppress>",
                ),
                finding(
                    "SEC002",
                    Severity::Medium,
                    FindingCategory::Security,
                    "<secret>",
                    "</td><img src=x>",
                    "skills/<root>/scripts/check.sh",
                    Some(3),
                ),
            ],
        );
        report.supply_chain = supply_chain_inventory(json!({
            "licenses": [],
            "trust_manifests": [],
            "external_urls": [
                {
                    "path": "skills/<root>/SKILL.md",
                    "line": 4,
                    "source": "markdown-link",
                    "kind": "documentation",
                    "normalized": "https://docs.example/<unsafe>",
                    "raw": "https://docs.example/<unsafe>",
                    "confidence": "high",
                    "pinned": false
                }
            ],
            "remote_dependencies": [
                {
                    "path": "skills/<root>/package.json",
                    "line": 5,
                    "source": "package-manifest",
                    "kind": "package",
                    "package_manager": "npm",
                    "name": "<pkg>",
                    "version": null,
                    "normalized": "<pkg>@latest",
                    "raw": "<pkg>",
                    "confidence": "high",
                    "pinned": false
                }
            ],
            "package_managers": [],
            "lockfiles": [],
            "executables": [],
            "binaries": [],
            "checksums": [],
            "permissions": [
                {
                    "path": "skills/<root>/trust.yaml",
                    "line": 6,
                    "source": "trust-manifest",
                    "kind": "secrets",
                    "evidence": "declared",
                    "normalized": "secrets=<TOKEN>",
                    "raw": "<TOKEN>",
                    "confidence": "high"
                }
            ],
            "offline_readiness": [
                {
                    "path": "skills/<root>/SKILL.md",
                    "status": "not-ready",
                    "score": 20,
                    "reasons": ["<reason>"]
                }
            ]
        }));

        let html = render_html(&report);

        for escaped in [
            "skills/&lt;root&gt;/SKILL.md",
            "&lt;/td&gt;&lt;script&gt;alert(&#39;broken&#39;)&lt;/script&gt;",
            "&lt;/td&gt;&lt;img src=x&gt;",
            "https://docs.example/&lt;unsafe&gt;",
            "&lt;pkg&gt;@latest",
            "secrets=&lt;TOKEN&gt;",
            "&lt;reason&gt;",
        ] {
            assert!(html.contains(escaped), "missing escaped value {escaped}");
        }

        for raw in [
            "skills/<root>/SKILL.md",
            "</td><script>alert('broken')</script>",
            "</td><img src=x>",
            "https://docs.example/<unsafe>",
            "<pkg>@latest",
            "secrets=<TOKEN>",
            "<reason>",
        ] {
            assert!(
                !html.contains(raw),
                "raw dangerous value was rendered: {raw}"
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
            value["runs"][0]["tool"]["driver"]["properties"]["agentAudit"]["scanner"]["version"],
            env!("CARGO_PKG_VERSION")
        );
        assert_eq!(
            value["runs"][0]["invocations"][0]["properties"]["agentAudit"]["timestamp"],
            Value::Null
        );
        assert_eq!(
            value["runs"][0]["properties"]["agentAudit"]["outputSchemaVersion"],
            "1"
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
    fn sarif_output_includes_compact_compatibility_matrix_when_findings_are_empty() {
        let mut report = report_with_findings(Vec::new());
        report.compatibility = serde_json::from_value(json!({
            "profiles": ["agent-skills-spec", "codex"],
            "matrix": [
                {
                    "path": "skills/portable/SKILL.md",
                    "name": "portable",
                    "profiles": [
                        {
                            "profile": "agent-skills-spec",
                            "status": "pass",
                            "finding_ids": []
                        },
                        {
                            "profile": "codex",
                            "status": "warn",
                            "finding_ids": ["SKILL050"]
                        }
                    ]
                }
            ]
        }))
        .expect("compatibility matrix fixture");

        let value = render_sarif_value(&report);

        assert_eq!(
            value["runs"][0]["properties"]["compatibility"],
            json!({
                "profiles": ["agent-skills-spec", "codex"],
                "statusTotals": {
                    "pass": 1,
                    "warn": 1,
                    "fail": 0,
                    "unknown": 0,
                    "untested": 0
                },
                "matrix": [
                    {
                        "path": "skills/portable/SKILL.md",
                        "name": "portable",
                        "profiles": [
                            {
                                "profile": "agent-skills-spec",
                                "status": "pass",
                                "findingIds": []
                            },
                            {
                                "profile": "codex",
                                "status": "warn",
                                "findingIds": ["SKILL050"]
                            }
                        ]
                    }
                ]
            })
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
                matched_path: Some("SKILL.md".to_owned()),
                matched_match: None,
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
            finding(
                "SKILL001",
                Severity::High,
                FindingCategory::Security,
                "Conflicting finding title",
                "Finding-specific message stays on the result.",
                "skills/conflict/SKILL.md",
                Some(9),
            ),
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
        assert_eq!(result["properties"]["agentAuditConfidence"], "medium");
        assert_eq!(result["properties"]["category"], "security");
        assert!(
            result["partialFingerprints"]["agentAuditFindingFingerprint"]
                .as_str()
                .expect("finding fingerprint")
                .starts_with("fnv1a64:")
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
        assert_eq!(result["properties"]["agentAuditConfidence"], "medium");
        assert_eq!(result["properties"]["category"], "security");
    }

    #[test]
    fn sarif_output_falls_back_to_finding_metadata_for_unknown_rule_descriptor() {
        let report = report_with_findings(vec![finding_with_details(
            finding(
                "CUSTOM900",
                Severity::Critical,
                FindingCategory::Reproducibility,
                "Custom reproducibility rule",
                "The custom rule produced a finding.",
                "custom/SKILL.md",
                Some(3),
            ),
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
    fn sarif_rule_descriptor_for_skill050_comes_from_active_registry_metadata() {
        let report = report_with_findings(vec![finding_with_details(
            finding(
                "SKILL050",
                Severity::Medium,
                FindingCategory::Portability,
                "Synthetic host metadata issue",
                "The synthetic host metadata issue produced a finding.",
                "host/SKILL.md",
                Some(5),
            ),
            "Synthetic rationale.",
            "Synthetic remediation.",
            "Synthetic suppression.",
        )]);

        let value = render_sarif_value(&report);
        let rule = &value["runs"][0]["tool"]["driver"]["rules"][0];

        assert_eq!(rule["id"], "SKILL050");
        assert_eq!(rule["name"], "Ignored host-specific metadata");
        assert_eq!(
            rule["shortDescription"]["text"],
            "Ignored host-specific metadata"
        );
        assert_eq!(
            rule["fullDescription"]["text"],
            "Host-specific metadata fields that the selected profile is likely to ignore can create a false sense that tool or permission settings will be enforced."
        );
        assert_eq!(
            rule["help"]["text"],
            "Use metadata supported by the selected profile, move advisory settings into the Markdown body, or remove fields that the profile marks as ignored.\n\nSuppress `SKILL050` only when a documented wrapper, host version, or project policy intentionally accepts the ignored metadata, and include that context in the reason."
        );
        assert_eq!(rule["defaultConfiguration"]["level"], "warning");
        assert_eq!(rule["properties"]["agentAuditSeverity"], "low");
        assert_eq!(rule["properties"]["category"], "compatibility");
    }

    #[test]
    fn sarif_output_includes_supply_findings_as_normal_rule_results() {
        let report = report_with_findings(vec![finding(
            "SUPPLY005",
            Severity::Medium,
            FindingCategory::Security,
            "Mutable GitHub raw URL reference",
            "The skill references a mutable GitHub raw URL.",
            "SKILL.md",
            Some(8),
        )]);

        let value = render_sarif_value(&report);
        let rule = &value["runs"][0]["tool"]["driver"]["rules"][0];
        let result = &value["runs"][0]["results"][0];

        assert_eq!(sarif_rule_ids(&value), vec!["SUPPLY005"]);
        assert_eq!(rule["id"], "SUPPLY005");
        assert_eq!(rule["properties"]["category"], "security");
        assert_eq!(rule["properties"]["agentAuditSeverity"], "medium");
        assert_eq!(result["ruleId"], "SUPPLY005");
        assert_eq!(result["level"], "warning");
        assert_eq!(result["properties"]["category"], "security");
        assert_eq!(result["properties"]["agentAuditSeverity"], "medium");
        assert!(value["runs"][0].get("supply_chain").is_none());
    }

    #[test]
    fn sarif_compatibility_results_include_profile_context_from_matrix() {
        let mut report = report_with_findings(vec![
            finding(
                "SKILL050",
                Severity::Low,
                FindingCategory::Compatibility,
                "Ignored host-specific metadata",
                "Codex and Generic profile context should be attached.",
                "skills/beta/SKILL.md",
                Some(3),
            ),
            finding(
                "SKILL040",
                Severity::Low,
                FindingCategory::Compatibility,
                "Host-specific or unrecognized metadata field",
                "Claude context should be attached.",
                "skills/alpha/SKILL.md",
                Some(2),
            ),
        ]);
        report.compatibility = serde_json::from_value(json!({
            "profiles": ["claude-code", "codex", "generic"],
            "matrix": [
                {
                    "path": "skills/beta/SKILL.md",
                    "name": "beta",
                    "profiles": [
                        {
                            "profile": "claude-code",
                            "status": "pass",
                            "finding_ids": []
                        },
                        {
                            "profile": "codex",
                            "status": "warn",
                            "finding_ids": ["SKILL050"]
                        },
                        {
                            "profile": "generic",
                            "status": "unknown",
                            "finding_ids": ["SKILL050"]
                        }
                    ]
                },
                {
                    "path": "skills/alpha/SKILL.md",
                    "name": "alpha",
                    "profiles": [
                        {
                            "profile": "claude-code",
                            "status": "warn",
                            "finding_ids": ["SKILL040"]
                        },
                        {
                            "profile": "codex",
                            "status": "pass",
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
        }))
        .expect("compatibility matrix fixture");

        let value = render_sarif_value(&report);
        let results = value["runs"][0]["results"]
            .as_array()
            .expect("results array");

        assert_eq!(
            sarif_result_paths(&value),
            vec!["skills/alpha/SKILL.md", "skills/beta/SKILL.md"]
        );
        assert_eq!(
            results[0]["properties"]["compatibilityProfiles"],
            json!([
                {
                    "profile": "claude-code",
                    "status": "warn"
                }
            ])
        );
        assert_eq!(
            results[1]["properties"]["compatibilityProfiles"],
            json!([
                {
                    "profile": "codex",
                    "status": "warn"
                },
                {
                    "profile": "generic",
                    "status": "unknown"
                }
            ])
        );
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
                "Host-specific or unrecognized metadata field",
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
        assert_eq!(
            value["runs"][0]["properties"]["agentAudit"]["timestamp"],
            Value::Null
        );
        assert!(!first.contains("generated_at"));
    }

    fn report_with_findings(findings: Vec<SkillFinding>) -> ScanReport {
        report_with_packages_and_findings(Vec::new(), findings)
    }

    fn dependency_reproducibility_report() -> ScanReport {
        report_with_packages_and_findings(
            vec![package(
                "skills/deps",
                "skills/deps/SKILL.md",
                Some("deps"),
                Some("Installs dependencies."),
            )],
            vec![
                finding(
                    "SEC009",
                    Severity::Low,
                    FindingCategory::Security,
                    "Package install without lockfile",
                    "The script runs `npm install left-pad` without nearby lockfile evidence.",
                    "skills/deps/scripts/install.sh",
                    Some(3),
                ),
                finding(
                    "SUPPLY003",
                    Severity::Medium,
                    FindingCategory::Reproducibility,
                    "Install command without matching reproducibility evidence",
                    "The npm install command does not have matching reproducibility evidence.",
                    "skills/deps/scripts/install.sh",
                    Some(3),
                ),
                finding(
                    "SUPPLY004",
                    Severity::Medium,
                    FindingCategory::Reproducibility,
                    "Unpinned package dependency",
                    "The npm dependency `left-pad` uses an unpinned version range.",
                    "skills/deps/package.json",
                    Some(7),
                ),
            ],
        )
    }

    fn repeated_finding_report(count: usize) -> ScanReport {
        let packages = (0..count)
            .map(|index| {
                package(
                    &format!("skills/repeated-{index}"),
                    &format!("skills/repeated-{index}/SKILL.md"),
                    Some(&format!("repeated-{index}")),
                    None,
                )
            })
            .collect::<Vec<_>>();
        let findings = (0..count)
            .map(|index| {
                finding(
                    "SEC009",
                    Severity::Medium,
                    FindingCategory::Security,
                    "Package install without lockfile",
                    "The artifact runs a JavaScript package install without nearby lockfile evidence.",
                    &format!("skills/repeated-{index}/scripts/install.sh"),
                    Some(2),
                )
            })
            .collect::<Vec<_>>();

        report_with_packages_and_findings(packages, findings)
    }

    fn report_with_summary(
        package_count: usize,
        finding_count: usize,
        suppressed_finding_count: usize,
        invalid_manifest_count: usize,
        broken_reference_count: usize,
    ) -> ScanReport {
        ScanReport {
            audit: AuditMetadata::default(),
            packages: Vec::new(),
            summary: ScanSummary {
                package_count,
                finding_count,
                suppressed_finding_count,
                invalid_manifest_count,
                broken_reference_count,
                actual_secret_evidence_count: 0,
                prompt_secret_exposure_count: 0,
            },
            findings: Vec::new(),
            finding_groups: Vec::new(),
            patterns: Vec::new(),
            suppressed_findings: Vec::new(),
            supply_chain: SupplyChainInventory::default(),
            compatibility: CompatibilityMatrix::default(),
        }
    }

    fn report_with_packages_and_findings(
        packages: Vec<SkillPackage>,
        findings: Vec<SkillFinding>,
    ) -> ScanReport {
        let package_count = packages.len();

        let compatibility = CompatibilityMatrix::default();
        let finding_groups = build_finding_groups(&packages, &findings, &compatibility);

        ScanReport {
            audit: AuditMetadata::default(),
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
                actual_secret_evidence_count: findings
                    .iter()
                    .filter(|finding| is_actual_secret_evidence_finding(finding))
                    .count(),
                prompt_secret_exposure_count: findings
                    .iter()
                    .filter(|finding| is_prompt_secret_exposure_finding(finding))
                    .count(),
            },
            findings,
            finding_groups,
            patterns: Vec::new(),
            suppressed_findings: Vec::new(),
            supply_chain: SupplyChainInventory::default(),
            compatibility,
        }
    }

    fn review_skill_report(
        rule_id: &str,
        severity: Severity,
        category: FindingCategory,
        title: &str,
        message: &str,
        line: Option<usize>,
    ) -> ScanReport {
        report_with_packages_and_findings(
            vec![review_package()],
            vec![finding(
                rule_id,
                severity,
                category,
                title,
                message,
                "skills/review/SKILL.md",
                line,
            )],
        )
    }

    fn review_package() -> SkillPackage {
        package(
            "skills/review",
            "skills/review/SKILL.md",
            Some("review-skill"),
            Some("Reviews agent skills."),
        )
    }

    fn supply_chain_inventory(value: Value) -> SupplyChainInventory {
        serde_json::from_value(value).expect("supply-chain inventory fixture")
    }

    fn compatibility_matrix(value: Value) -> CompatibilityMatrix {
        serde_json::from_value(value).expect("compatibility matrix fixture")
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
            fingerprint: String::new(),
            severity,
            confidence: FindingConfidence::Medium,
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
        mut finding: SkillFinding,
        rationale: &str,
        remediation: &str,
        suppression: &str,
    ) -> SkillFinding {
        finding.rationale = rationale.to_owned();
        finding.remediation = remediation.to_owned();
        finding.suppression = suppression.to_owned();
        finding
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

    fn sarif_result_rule_ids(value: &Value) -> Vec<&str> {
        value["runs"][0]["results"]
            .as_array()
            .expect("results array")
            .iter()
            .map(|result| result["ruleId"].as_str().expect("result rule id"))
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

    fn html_section(html: &str, section_id: &str) -> String {
        let heading = format!("<h2 id=\"{section_id}\">");
        let heading_start = html
            .find(&heading)
            .unwrap_or_else(|| panic!("missing section heading {section_id}"));
        let section_start = html[..heading_start]
            .rfind("<section")
            .unwrap_or(heading_start);
        let section_end = html[heading_start..]
            .find("</section>")
            .map(|offset| heading_start + offset + "</section>".len())
            .unwrap_or(html.len());

        html[section_start..section_end].to_owned()
    }

    fn summary_group_line_count(summary: &str, groups: &[(&str, &str)]) -> usize {
        summary
            .lines()
            .filter(|line| {
                groups.iter().any(|(rule_id, fingerprint)| {
                    line.starts_with(rule_id) && line.contains(fingerprint)
                })
            })
            .count()
    }

    fn html_group_row_count(html: &str, groups: &[(&str, &str)]) -> usize {
        let finding_groups = html_section(html, "findings");

        groups
            .iter()
            .filter(|(rule_id, fingerprint)| {
                finding_groups.contains(&format!("<td>{rule_id}</td>"))
                    && finding_groups.contains(*fingerprint)
            })
            .count()
    }
}
