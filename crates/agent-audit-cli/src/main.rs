// SPDX-License-Identifier: Apache-2.0

use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::Command as ProcessCommand;

use agent_audit_core::model::{
    stable_audit_hash, AuditCommandMetadata, AuditConfigMetadata, AuditMethodologyMetadata,
    AuditPlatformMetadata, AuditRepositoryMetadata,
};
use agent_audit_core::{
    parse_audit_config, parse_severity, report_matches_fail_on, scan_path, AuditConfig, AuditError,
    ScanOptions, ScanReport, Severity, SupplyChainPolicy,
};
use agent_audit_hosts::{canonical_host_profile, HOST_PROFILES};
use agent_audit_report::{
    render_report_with_mode, ReportFormat, ReportMode, UnsupportedReportFormat,
    UnsupportedReportMode, SUPPORTED_REPORT_FORMATS_HELP, SUPPORTED_REPORT_MODES_HELP,
};
use anyhow::{anyhow, Context, Result};
use clap::Parser;

#[derive(Debug, Parser)]
#[command(name = "agent-audit")]
#[command(about = "Offline security and compatibility auditor for AI agent skills.")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, clap::Subcommand)]
enum Command {
    Scan(ScanCommand),
}

#[derive(Debug, Parser)]
struct ScanCommand {
    #[arg(default_value = ".")]
    path: PathBuf,
    #[arg(
        long,
        visible_alias = "report",
        value_parser = parse_report_format,
        default_value = "summary",
        value_name = "FORMAT",
        help = SUPPORTED_REPORT_FORMATS_HELP
    )]
    format: ReportFormat,
    #[arg(
        long,
        value_parser = parse_report_mode,
        default_value = "default",
        value_name = "MODE",
        help = SUPPORTED_REPORT_MODES_HELP
    )]
    mode: ReportMode,
    #[arg(
        long,
        value_name = "PATH",
        help = "Read and validate an explicit config file before scanning"
    )]
    config: Option<PathBuf>,
    #[arg(
        long,
        value_parser = parse_fail_on_severity,
        value_name = "SEVERITY",
        help = "Fail when an unsuppressed finding exactly matches severity; repeat for multiple severities"
    )]
    fail_on: Vec<Severity>,
    #[arg(
        long,
        value_name = "PATH",
        help = "Write the rendered report to a file instead of stdout"
    )]
    output: Option<PathBuf>,
    #[arg(
        long,
        help = "Open an HTML report after writing it to an explicit output file"
    )]
    open: bool,
    #[arg(
        long = "profile",
        value_parser = parse_scan_profile,
        value_delimiter = ',',
        value_name = "PROFILE",
        help = "Select compatibility profile(s); repeat or comma-separate values; use 'all' for every supported profile"
    )]
    profiles: Vec<String>,
    #[arg(
        long,
        help = "Compatibility no-op; supply-chain inventory and rules already run by default"
    )]
    supply_chain: bool,
    #[arg(
        long,
        help = "Require local trust manifest and license evidence, emitting missing metadata findings"
    )]
    strict_supply_chain: bool,
    #[arg(
        long,
        value_name = "NAME",
        help = "Attach optional public-audit corpus name metadata"
    )]
    corpus_name: Option<String>,
    #[arg(
        long,
        value_name = "ID",
        help = "Attach optional public-audit corpus entry ID metadata"
    )]
    corpus_entry_id: Option<String>,
    #[arg(
        long,
        value_name = "VERSION",
        help = "Attach optional public-audit methodology version metadata"
    )]
    methodology_version: Option<String>,
    #[arg(
        long = "inclusion-tag",
        value_delimiter = ',',
        value_name = "TAG",
        help = "Attach optional public-audit inclusion tag metadata; repeat or comma-separate values"
    )]
    inclusion_tags: Vec<String>,
    #[arg(
        long,
        value_name = "CLASSIFICATION",
        help = "Attach optional public-audit repository classification metadata"
    )]
    repo_classification: Option<String>,
    #[arg(
        long,
        value_name = "ID",
        help = "Attach optional public-audit scan batch ID metadata"
    )]
    scan_batch_id: Option<String>,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Command::Scan(command) => run_scan(command),
    }
}

fn run_scan(command: ScanCommand) -> Result<()> {
    let stdout = io::stdout();
    let mut writer = stdout.lock();

    run_scan_with_writer(command, &mut writer)
}

fn run_scan_with_writer(command: ScanCommand, writer: &mut impl Write) -> Result<()> {
    run_scan_with_writer_and_opener(command, writer, open_report_file)
}

fn run_scan_with_writer_and_opener(
    command: ScanCommand,
    writer: &mut impl Write,
    opener: impl FnOnce(&Path) -> Result<()>,
) -> Result<()> {
    validate_output_options(&command)?;

    let loaded_config = command
        .config
        .as_deref()
        .map(load_explicit_config)
        .transpose()?;
    let _supply_chain_requested = command.supply_chain;
    let fail_on = effective_fail_on(
        &command.fail_on,
        loaded_config.as_ref().map(|loaded| &loaded.config),
    )
    .to_vec();
    let config_metadata = loaded_config
        .as_ref()
        .map(|loaded| loaded.metadata.clone())
        .unwrap_or_default();
    let config_methodology = loaded_config
        .as_ref()
        .and_then(|loaded| loaded.config.methodology.clone());
    let config = effective_config(
        loaded_config.map(|loaded| loaded.config),
        &command.profiles,
        command.strict_supply_chain,
    );

    let mut report = scan_path(
        &command.path,
        &ScanOptions {
            config,
            ..ScanOptions::default()
        },
    )?;
    enrich_report_audit_metadata(
        &mut report,
        &command,
        &fail_on,
        config_metadata,
        config_methodology,
    );
    write_report_apply_fail_on_and_maybe_open(&report, &command, &fail_on, writer, opener)
}

fn write_report_apply_fail_on_and_maybe_open(
    report: &ScanReport,
    command: &ScanCommand,
    fail_on: &[Severity],
    writer: &mut impl Write,
    opener: impl FnOnce(&Path) -> Result<()>,
) -> Result<()> {
    let rendered = render_report_with_mode(report, command.format, command.mode)?;

    if let Some(output_path) = command.output.as_deref() {
        write_output_file(output_path, &rendered)?;
    } else {
        writer.write_all(rendered.as_bytes())?;
        writer.flush()?;
    }

    if report_matches_fail_on(report, fail_on) {
        return Err(anyhow!(
            "scan failed because fail_on matched an unsuppressed finding severity"
        ));
    }

    if command.open {
        let output_path = command
            .output
            .as_deref()
            .expect("--open validation should require --output");
        opener(output_path)?;
    }

    Ok(())
}

fn validate_output_options(command: &ScanCommand) -> Result<()> {
    if command.open && command.output.is_none() {
        return Err(anyhow!(
            "--open requires --output because there is no HTML report file to open"
        ));
    }

    if command.open && command.format != ReportFormat::Html {
        return Err(anyhow!("--open can only be used with --format html"));
    }

    if let Some(output_path) = command.output.as_deref() {
        if output_path.is_dir() {
            return Err(anyhow!(
                "--output target is an existing directory: {}",
                output_path.display()
            ));
        }
    }

    Ok(())
}

fn write_output_file(output_path: &Path, rendered: &str) -> Result<()> {
    if let Some(parent) = output_path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent).with_context(|| {
                format!(
                    "failed to create output parent directory {}",
                    parent.display()
                )
            })?;
        }
    }

    fs::write(output_path, rendered)
        .with_context(|| format!("failed to write report {}", output_path.display()))
}

fn open_report_file(path: &Path) -> Result<()> {
    let status = platform_open_command(path)
        .status()
        .with_context(|| format!("failed to open report {}", path.display()))?;

    if !status.success() {
        return Err(anyhow!(
            "failed to open report {}: opener exited with {}",
            path.display(),
            status
        ));
    }

    Ok(())
}

#[cfg(target_os = "windows")]
fn platform_open_command(path: &Path) -> ProcessCommand {
    let mut command = ProcessCommand::new("cmd");
    command.arg("/C").arg("start").arg("").arg(path);
    command
}

#[cfg(target_os = "macos")]
fn platform_open_command(path: &Path) -> ProcessCommand {
    let mut command = ProcessCommand::new("open");
    command.arg(path);
    command
}

#[cfg(all(unix, not(target_os = "macos")))]
fn platform_open_command(path: &Path) -> ProcessCommand {
    let mut command = ProcessCommand::new("xdg-open");
    command.arg(path);
    command
}

#[cfg(test)]
fn write_report_and_apply_fail_on(
    report: &ScanReport,
    format: ReportFormat,
    fail_on: &[Severity],
    writer: &mut impl Write,
) -> Result<()> {
    let command = ScanCommand {
        path: PathBuf::from("."),
        format,
        mode: ReportMode::Default,
        config: None,
        fail_on: fail_on.to_vec(),
        output: None,
        open: false,
        profiles: Vec::new(),
        supply_chain: false,
        strict_supply_chain: false,
        corpus_name: None,
        corpus_entry_id: None,
        methodology_version: None,
        inclusion_tags: Vec::new(),
        repo_classification: None,
        scan_batch_id: None,
    };

    write_report_apply_fail_on_and_maybe_open(report, &command, fail_on, writer, |_| Ok(()))
}

fn effective_fail_on<'a>(
    cli_fail_on: &'a [Severity],
    config: Option<&'a AuditConfig>,
) -> &'a [Severity] {
    if !cli_fail_on.is_empty() {
        return cli_fail_on;
    }

    config.map_or(&[], |config| config.fail_on.as_slice())
}

fn effective_config(
    config: Option<AuditConfig>,
    cli_profiles: &[String],
    strict_supply_chain: bool,
) -> Option<AuditConfig> {
    if cli_profiles.is_empty() && !strict_supply_chain {
        return config;
    }

    Some(match config {
        Some(mut config) => {
            if !cli_profiles.is_empty() {
                config.profiles = effective_cli_profiles(cli_profiles);
            }
            if strict_supply_chain {
                config.supply_chain.policy = SupplyChainPolicy::Strict;
            }
            config
        }
        None => {
            let mut config = AuditConfig::empty();
            if !cli_profiles.is_empty() {
                config.profiles = effective_cli_profiles(cli_profiles);
            }
            if strict_supply_chain {
                config.supply_chain.policy = SupplyChainPolicy::Strict;
            }
            config
        }
    })
}

fn effective_cli_profiles(cli_profiles: &[String]) -> Vec<String> {
    if cli_profiles.iter().any(|profile| profile == "all") {
        return all_supported_profiles();
    }

    cli_profiles.to_vec()
}

fn all_supported_profiles() -> Vec<String> {
    HOST_PROFILES
        .iter()
        .map(|profile| (*profile).to_owned())
        .collect()
}

#[derive(Debug)]
struct LoadedAuditConfig {
    config: AuditConfig,
    metadata: AuditConfigMetadata,
}

fn load_explicit_config(config_path: &Path) -> Result<LoadedAuditConfig> {
    let content = fs::read_to_string(config_path)
        .with_context(|| format!("failed to read config {}", config_path.display()))?;

    let config =
        parse_audit_config(&content).map_err(|error| config_error_with_path(config_path, error))?;

    Ok(LoadedAuditConfig {
        config,
        metadata: AuditConfigMetadata {
            path: Some(path_metadata_string(config_path)),
            hash: Some(stable_audit_hash(&content)),
        },
    })
}

fn config_error_with_path(config_path: &Path, error: AuditError) -> anyhow::Error {
    match error {
        AuditError::ConfigParse { .. } => {
            anyhow!("failed to parse config {}: {error}", config_path.display())
        }
        AuditError::ConfigValidation { .. } => {
            anyhow!("invalid config {}: {error}", config_path.display())
        }
        _ => anyhow!("failed to load config {}: {error}", config_path.display()),
    }
}

fn parse_report_format(value: &str) -> Result<ReportFormat, UnsupportedReportFormat> {
    value.parse()
}

fn parse_report_mode(value: &str) -> Result<ReportMode, UnsupportedReportMode> {
    value.parse()
}

fn parse_fail_on_severity(value: &str) -> Result<Severity, String> {
    parse_severity(value).ok_or_else(|| {
        format!("unknown severity `{value}`; expected one of: info, low, medium, high, critical")
    })
}

fn parse_scan_profile(value: &str) -> Result<String, String> {
    let profile = value.trim();

    if let Some(canonical_profile) = canonical_scan_profile(profile) {
        return Ok(canonical_profile.to_owned());
    }

    Err(format!(
        "unknown profile `{profile}`; expected one of: all, {}",
        HOST_PROFILES.join(", ")
    ))
}

fn canonical_scan_profile(profile: &str) -> Option<&'static str> {
    match profile {
        "all" => Some("all"),
        profile => canonical_host_profile(profile),
    }
}

fn enrich_report_audit_metadata(
    report: &mut ScanReport,
    command: &ScanCommand,
    effective_fail_on: &[Severity],
    config: AuditConfigMetadata,
    config_methodology: Option<AuditMethodologyMetadata>,
) {
    report.audit.config = config;
    report.audit.scan.root = Some(path_metadata_string(&command.path));
    report.audit.command = AuditCommandMetadata {
        name: Some("scan".to_owned()),
        format: Some(command.format.as_str().to_owned()),
        mode: Some(command.mode.as_str().to_owned()),
        output: command.output.as_deref().map(path_metadata_string),
        profiles: command.profiles.clone(),
        fail_on: effective_fail_on.iter().map(severity_label).collect(),
        supply_chain: command.supply_chain,
        strict_supply_chain: command.strict_supply_chain,
    };
    report.audit.methodology = effective_methodology_metadata(command, config_methodology);
    report.audit.platform = Some(AuditPlatformMetadata {
        os: std::env::consts::OS.to_owned(),
        arch: std::env::consts::ARCH.to_owned(),
        family: std::env::consts::FAMILY.to_owned(),
    });
    report.audit.repository = detect_repository_metadata(&command.path);
}

fn effective_methodology_metadata(
    command: &ScanCommand,
    config_methodology: Option<AuditMethodologyMetadata>,
) -> Option<AuditMethodologyMetadata> {
    let mut methodology = config_methodology.unwrap_or_default();

    override_optional_string(&mut methodology.corpus_name, command.corpus_name.as_deref());
    override_optional_string(
        &mut methodology.corpus_entry_id,
        command.corpus_entry_id.as_deref(),
    );
    override_optional_string(
        &mut methodology.methodology_version,
        command.methodology_version.as_deref(),
    );
    override_optional_string(
        &mut methodology.repo_classification,
        command.repo_classification.as_deref(),
    );
    override_optional_string(
        &mut methodology.scan_batch_id,
        command.scan_batch_id.as_deref(),
    );

    if !command.inclusion_tags.is_empty() {
        methodology.inclusion_tags = normalized_cli_values(&command.inclusion_tags);
    }

    if methodology.is_empty() {
        None
    } else {
        Some(methodology)
    }
}

fn override_optional_string(target: &mut Option<String>, value: Option<&str>) {
    let Some(value) = value.map(str::trim).filter(|value| !value.is_empty()) else {
        return;
    };

    *target = Some(value.to_owned());
}

fn normalized_cli_values(values: &[String]) -> Vec<String> {
    let mut values = values
        .iter()
        .map(|value| value.trim())
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
        .collect::<Vec<_>>();
    values.sort();
    values.dedup();
    values
}

fn detect_repository_metadata(scan_root: &Path) -> Option<AuditRepositoryMetadata> {
    let worktree_root = git_output(scan_root, &["rev-parse", "--show-toplevel"])?;
    if !paths_match(scan_root, Path::new(&worktree_root)) {
        return None;
    }

    let remote_url = git_output(scan_root, &["config", "--get", "remote.origin.url"]);
    let commit = git_output(scan_root, &["rev-parse", "HEAD"]);
    let dirty = git_output(scan_root, &["status", "--porcelain"]).map(|status| !status.is_empty());

    if remote_url.is_none() && commit.is_none() && dirty.is_none() {
        return None;
    }

    Some(AuditRepositoryMetadata {
        remote_url,
        commit,
        dirty,
    })
}

fn paths_match(left: &Path, right: &Path) -> bool {
    let Ok(left) = left.canonicalize() else {
        return false;
    };
    let Ok(right) = right.canonicalize() else {
        return false;
    };

    left == right
}

fn git_output(scan_root: &Path, args: &[&str]) -> Option<String> {
    let output = ProcessCommand::new("git")
        .args(["-C"])
        .arg(scan_root)
        .args(args)
        .output()
        .ok()?;

    if !output.status.success() {
        return None;
    }

    let value = String::from_utf8(output.stdout).ok()?.trim().to_owned();
    if value.is_empty() {
        None
    } else {
        Some(value)
    }
}

fn path_metadata_string(path: &Path) -> String {
    let value = path.to_string_lossy().replace('\\', "/");

    if value.is_empty() {
        ".".to_owned()
    } else {
        value
    }
}

fn severity_label(severity: &Severity) -> String {
    match severity {
        Severity::Info => "info",
        Severity::Low => "low",
        Severity::Medium => "medium",
        Severity::High => "high",
        Severity::Critical => "critical",
    }
    .to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;
    use agent_audit_core::model::{CompatibilityMatrix, ScanSummary, SupplyChainInventory};
    use agent_audit_core::{
        FindingCategory, FindingLocation, SkillFinding, SuppressedFinding, SuppressionMatch,
    };
    use clap::CommandFactory;
    use std::cell::Cell;
    use std::fs;
    use std::path::Path;
    use std::sync::atomic::{AtomicUsize, Ordering};

    static NEXT_WORKSPACE_ID: AtomicUsize = AtomicUsize::new(0);

    #[test]
    fn scan_help_lists_supported_report_formats() {
        let mut command = Cli::command();
        let help = command
            .find_subcommand_mut("scan")
            .expect("scan subcommand should be registered")
            .render_long_help()
            .to_string();

        assert!(help.contains("summary"));
        assert!(help.contains("json"));
        assert!(help.contains("public-json"));
        assert!(help.contains("sarif"));
        assert!(help.contains("html"));
    }

    #[test]
    fn scan_help_lists_report_alias_for_format() {
        let mut command = Cli::command();
        let help = command
            .find_subcommand_mut("scan")
            .expect("scan subcommand should be registered")
            .render_long_help()
            .to_string();

        assert!(help.contains("--format <FORMAT>"));
        assert!(help.contains("[aliases: --report]"));
    }

    #[test]
    fn scan_help_lists_supported_report_modes() {
        let mut command = Cli::command();
        let help = command
            .find_subcommand_mut("scan")
            .expect("scan subcommand should be registered")
            .render_long_help()
            .to_string();

        assert!(help.contains("--mode <MODE>"));
        assert!(help.contains("default"));
        assert!(help.contains("verbose"));
        assert!(help.contains("research"));
        assert!(help.contains("ci"));
    }

    #[test]
    fn scan_help_lists_explicit_config_option() {
        let mut command = Cli::command();
        let help = command
            .find_subcommand_mut("scan")
            .expect("scan subcommand should be registered")
            .render_long_help()
            .to_string();

        assert!(help.contains("--config <PATH>"));
        assert!(help.contains("Read and validate an explicit config file before scanning"));
    }

    #[test]
    fn scan_help_lists_fail_on_option_and_matching_wording() {
        let mut command = Cli::command();
        let help = command
            .find_subcommand_mut("scan")
            .expect("scan subcommand should be registered")
            .render_long_help()
            .to_string();

        assert!(help.contains("--fail-on <SEVERITY>"));
        assert!(help.contains("Fail when an unsuppressed finding exactly matches severity"));
        assert!(help.contains("repeat for multiple severities"));
    }

    #[test]
    fn scan_help_lists_profile_option() {
        let mut command = Cli::command();
        let help = command
            .find_subcommand_mut("scan")
            .expect("scan subcommand should be registered")
            .render_long_help()
            .to_string();

        assert!(help.contains("--profile <PROFILE>"));
        assert!(help.contains("Select compatibility profile(s)"));
        assert!(help.contains("comma-separate"));
        assert!(help.contains("use 'all'"));
    }

    #[test]
    fn scan_help_lists_supply_chain_policy_options() {
        let mut command = Cli::command();
        let help = command
            .find_subcommand_mut("scan")
            .expect("scan subcommand should be registered")
            .render_long_help()
            .to_string();

        assert!(help.contains("--supply-chain"));
        assert!(help.contains("Compatibility no-op"));
        assert!(help.contains("supply-chain inventory and rules already run by default"));
        assert!(help.contains("--strict-supply-chain"));
        assert!(help.contains("Require local trust manifest and license evidence"));
    }

    #[test]
    fn scan_help_lists_methodology_metadata_options() {
        let mut command = Cli::command();
        let help = command
            .find_subcommand_mut("scan")
            .expect("scan subcommand should be registered")
            .render_long_help()
            .to_string();

        for option in [
            "--corpus-name <NAME>",
            "--corpus-entry-id <ID>",
            "--methodology-version <VERSION>",
            "--inclusion-tag <TAG>",
            "--repo-classification <CLASSIFICATION>",
            "--scan-batch-id <ID>",
        ] {
            assert!(help.contains(option), "help should contain {option}");
        }
    }

    #[test]
    fn scan_help_lists_output_and_open_options() {
        let mut command = Cli::command();
        let help = command
            .find_subcommand_mut("scan")
            .expect("scan subcommand should be registered")
            .render_long_help()
            .to_string();

        assert!(help.contains("--output <PATH>"));
        assert!(help.contains("Write the rendered report to a file instead of stdout"));
        assert!(help.contains("--open"));
        assert!(help.contains("Open an HTML report after writing it to an explicit output file"));
    }

    #[test]
    fn parses_default_scan_command() {
        let cli = Cli::parse_from(["agent-audit", "scan"]);

        match cli.command {
            Command::Scan(command) => {
                assert_eq!(command.path, PathBuf::from("."));
                assert_eq!(command.format, ReportFormat::Summary);
                assert_eq!(command.mode, ReportMode::Default);
                assert_eq!(command.config, None);
                assert_eq!(command.fail_on, Vec::<Severity>::new());
                assert_eq!(command.output, None);
                assert!(!command.open);
                assert_eq!(command.profiles, Vec::<String>::new());
                assert!(!command.supply_chain);
                assert!(!command.strict_supply_chain);
                assert_eq!(command.corpus_name, None);
                assert_eq!(command.corpus_entry_id, None);
                assert_eq!(command.methodology_version, None);
                assert_eq!(command.inclusion_tags, Vec::<String>::new());
                assert_eq!(command.repo_classification, None);
                assert_eq!(command.scan_batch_id, None);
            }
        }
    }

    #[test]
    fn parses_methodology_metadata_options() {
        let cli = Cli::parse_from([
            "agent-audit",
            "scan",
            "fixtures/spec/basic",
            "--corpus-name",
            "v0.8 public audit",
            "--corpus-entry-id",
            "repo-001",
            "--methodology-version",
            "2026-05",
            "--inclusion-tag",
            "public,executable",
            "--inclusion-tag",
            "security",
            "--repo-classification",
            "oss-skill-repo",
            "--scan-batch-id",
            "batch-2026-05",
        ]);

        match cli.command {
            Command::Scan(command) => {
                assert_eq!(command.corpus_name.as_deref(), Some("v0.8 public audit"));
                assert_eq!(command.corpus_entry_id.as_deref(), Some("repo-001"));
                assert_eq!(command.methodology_version.as_deref(), Some("2026-05"));
                assert_eq!(
                    command.inclusion_tags,
                    vec!["public", "executable", "security"]
                );
                assert_eq!(
                    command.repo_classification.as_deref(),
                    Some("oss-skill-repo")
                );
                assert_eq!(command.scan_batch_id.as_deref(), Some("batch-2026-05"));
            }
        }
    }

    #[test]
    fn parses_supply_chain_selection_flags() {
        let cli = Cli::parse_from([
            "agent-audit",
            "scan",
            "fixtures/spec/basic",
            "--supply-chain",
            "--strict-supply-chain",
        ]);

        match cli.command {
            Command::Scan(command) => {
                assert!(command.supply_chain);
                assert!(command.strict_supply_chain);
            }
        }
    }

    #[test]
    fn parses_explicit_scan_config() {
        let cli = Cli::parse_from([
            "agent-audit",
            "scan",
            "fixtures/spec/basic",
            "--config",
            "audit.yaml",
        ]);

        match cli.command {
            Command::Scan(command) => {
                assert_eq!(command.path, PathBuf::from("fixtures/spec/basic"));
                assert_eq!(command.config, Some(PathBuf::from("audit.yaml")));
                assert_eq!(command.fail_on, Vec::<Severity>::new());
                assert_eq!(command.output, None);
                assert!(!command.open);
                assert_eq!(command.profiles, Vec::<String>::new());
            }
        }
    }

    #[test]
    fn parses_scan_output_and_open_options() {
        let cli = Cli::parse_from([
            "agent-audit",
            "scan",
            "fixtures/spec/basic",
            "--format",
            "html",
            "--output",
            "reports/report.html",
            "--open",
        ]);

        match cli.command {
            Command::Scan(command) => {
                assert_eq!(command.format, ReportFormat::Html);
                assert_eq!(command.output, Some(PathBuf::from("reports/report.html")));
                assert!(command.open);
            }
        }
    }

    #[test]
    fn parses_report_alias_for_scan_format() {
        let cli = Cli::parse_from([
            "agent-audit",
            "scan",
            "fixtures/spec/basic",
            "--report",
            "html",
        ]);

        match cli.command {
            Command::Scan(command) => {
                assert_eq!(command.path, PathBuf::from("fixtures/spec/basic"));
                assert_eq!(command.format, ReportFormat::Html);
            }
        }
    }

    #[test]
    fn parses_repeatable_scan_fail_on() {
        let cli = Cli::parse_from([
            "agent-audit",
            "scan",
            "fixtures/spec/basic",
            "--fail-on",
            "low",
            "--fail-on",
            "high",
        ]);

        match cli.command {
            Command::Scan(command) => {
                assert_eq!(command.path, PathBuf::from("fixtures/spec/basic"));
                assert_eq!(command.fail_on, vec![Severity::Low, Severity::High]);
                assert_eq!(command.profiles, Vec::<String>::new());
            }
        }
    }

    #[test]
    fn parses_single_scan_profile() {
        let cli = Cli::parse_from([
            "agent-audit",
            "scan",
            "fixtures/spec/basic",
            "--profile",
            "codex",
        ]);

        match cli.command {
            Command::Scan(command) => {
                assert_eq!(command.profiles, vec!["codex"]);
            }
        }
    }

    #[test]
    fn parses_repeatable_scan_profiles() {
        let cli = Cli::parse_from([
            "agent-audit",
            "scan",
            "fixtures/spec/basic",
            "--profile",
            "codex",
            "--profile",
            "generic",
        ]);

        match cli.command {
            Command::Scan(command) => {
                assert_eq!(command.profiles, vec!["codex", "generic"]);
            }
        }
    }

    #[test]
    fn parses_comma_separated_scan_profiles() {
        let cli = Cli::parse_from([
            "agent-audit",
            "scan",
            "fixtures/spec/basic",
            "--profile",
            "generic,codex",
        ]);

        match cli.command {
            Command::Scan(command) => {
                assert_eq!(command.profiles, vec!["generic", "codex"]);
            }
        }
    }

    #[test]
    fn parses_comma_separated_scan_profile_aliases_as_canonical_profiles() {
        let cli = Cli::parse_from([
            "agent-audit",
            "scan",
            "fixtures/spec/basic",
            "--profile",
            "claude,codex,copilot",
        ]);

        match cli.command {
            Command::Scan(command) => {
                assert_eq!(
                    command.profiles,
                    vec!["claude-code", "codex", "github-copilot"]
                );
            }
        }
    }

    #[test]
    fn parses_all_scan_profile_marker() {
        let cli = Cli::parse_from([
            "agent-audit",
            "scan",
            "fixtures/spec/basic",
            "--profile",
            "all",
        ]);

        match cli.command {
            Command::Scan(command) => {
                assert_eq!(command.profiles, vec!["all"]);
            }
        }
    }

    #[test]
    fn rejects_invalid_scan_profile_with_supported_names() {
        let error = Cli::try_parse_from([
            "agent-audit",
            "scan",
            "fixtures/spec/basic",
            "--profile",
            "unknown-host",
        ])
        .expect_err("invalid profile should fail");
        let message = error.to_string();

        assert!(message.contains("unknown profile `unknown-host`"));
        assert!(message.contains("all, agent-skills-spec, claude-code, codex"));
        assert!(message.contains("github-copilot, vscode-copilot, generic"));
    }

    #[test]
    fn rejects_invalid_scan_profile_alias_with_supported_names() {
        let error = Cli::try_parse_from([
            "agent-audit",
            "scan",
            "fixtures/spec/basic",
            "--profile",
            "github",
        ])
        .expect_err("invalid profile alias should fail");
        let message = error.to_string();

        assert!(message.contains("unknown profile `github`"));
        assert!(message.contains("all, agent-skills-spec, claude-code, codex"));
        assert!(message.contains("github-copilot, vscode-copilot, generic"));
    }

    #[test]
    fn rejects_invalid_scan_fail_on_severity() {
        let error = Cli::try_parse_from([
            "agent-audit",
            "scan",
            "fixtures/spec/basic",
            "--fail-on",
            "warning",
        ])
        .expect_err("invalid fail-on severity should fail");
        let message = error.to_string();

        assert!(message.contains("unknown severity `warning`"));
        assert!(message.contains("info, low, medium, high, critical"));
    }

    #[test]
    fn rejects_uppercase_scan_fail_on_severity_with_lowercase_names() {
        let error = Cli::try_parse_from([
            "agent-audit",
            "scan",
            "fixtures/spec/basic",
            "--fail-on",
            "LOW",
        ])
        .expect_err("uppercase fail-on severity should fail");
        let message = error.to_string();

        assert!(message.contains("unknown severity `LOW`"));
        assert!(message.contains("expected one of: info, low, medium, high, critical"));
    }

    #[test]
    fn parses_json_scan_format() {
        assert_parsed_scan_format("json", ReportFormat::Json);
    }

    #[test]
    fn parses_public_json_scan_format() {
        assert_parsed_scan_format("public-json", ReportFormat::PublicJson);
    }

    #[test]
    fn parses_sarif_scan_format() {
        assert_parsed_scan_format("sarif", ReportFormat::Sarif);
    }

    #[test]
    fn parses_html_scan_format() {
        assert_parsed_scan_format("html", ReportFormat::Html);
    }

    #[test]
    fn parses_scan_report_modes() {
        assert_parsed_report_mode("default", ReportMode::Default);
        assert_parsed_report_mode("verbose", ReportMode::Verbose);
        assert_parsed_report_mode("research", ReportMode::Research);
        assert_parsed_report_mode("ci", ReportMode::Ci);
    }

    fn assert_parsed_scan_format(value: &str, expected: ReportFormat) {
        let cli = Cli::parse_from([
            "agent-audit",
            "scan",
            "fixtures/spec/basic",
            "--format",
            value,
        ]);

        match cli.command {
            Command::Scan(command) => {
                assert_eq!(command.path, PathBuf::from("fixtures/spec/basic"));
                assert_eq!(command.format, expected);
                assert_eq!(command.mode, ReportMode::Default);
                assert_eq!(command.config, None);
                assert_eq!(command.fail_on, Vec::<Severity>::new());
                assert_eq!(command.output, None);
                assert!(!command.open);
            }
        }
    }

    fn assert_parsed_report_mode(value: &str, expected: ReportMode) {
        let cli = Cli::parse_from([
            "agent-audit",
            "scan",
            "fixtures/spec/basic",
            "--mode",
            value,
        ]);

        match cli.command {
            Command::Scan(command) => {
                assert_eq!(command.path, PathBuf::from("fixtures/spec/basic"));
                assert_eq!(command.format, ReportFormat::Summary);
                assert_eq!(command.mode, expected);
            }
        }
    }

    #[test]
    fn rejects_unsupported_scan_format_with_clear_message() {
        let error = Cli::try_parse_from([
            "agent-audit",
            "scan",
            "fixtures/spec/basic",
            "--format",
            "xml",
        ])
        .expect_err("unsupported format should fail");

        let message = error.to_string();

        assert!(message.contains("unsupported report format 'xml'"));
        assert!(message.contains("supported: summary, json, public-json, sarif, html"));
    }

    #[test]
    fn rejects_unsupported_scan_mode_with_clear_message() {
        let error = Cli::try_parse_from([
            "agent-audit",
            "scan",
            "fixtures/spec/basic",
            "--mode",
            "debug",
        ])
        .expect_err("unsupported mode should fail");

        let message = error.to_string();

        assert!(message.contains("unsupported report mode 'debug'"));
        assert!(message.contains("supported: default, verbose, research, ci"));
    }

    #[test]
    fn runs_scan_with_summary_output() {
        let workspace = CliTestWorkspace::new("summary-output");
        workspace.write_file(
            "SKILL.md",
            r#"---
name: summary-output
description: Summary output fixture.
---

# Summary Output
"#,
        );

        workspace.write_file("missing-reference.md", "# Present\n");
        workspace.write_file(
            "references/guide.md",
            "# Guide\n\nSee [missing](../not-found.md).\n",
        );

        let output = run_scan_output(scan_command(&workspace, ReportFormat::Summary))
            .expect("run summary scan");

        assert!(output.starts_with("Agent Skill Auditor scan summary\n"));
        assert!(output.contains("Audit: "));
        assert!(output.contains("timestamp=null"));
        assert!(output.contains("Packages: 1\n"));
        assert!(output.contains("Findings: "));
        assert!(output.contains("Compatibility:\n"));
        assert!(output.contains(
            "Profiles: agent-skills-spec, claude-code, codex, github-copilot, vscode-copilot, generic"
        ));
        assert!(output.contains("- SKILL.md (summary-output): agent-skills-spec=pass"));
        assert!(output.ends_with('\n'));
    }

    #[test]
    fn runs_scan_with_json_output() {
        let workspace = CliTestWorkspace::new("json-output");
        workspace.write_file(
            "SKILL.md",
            r#"---
name: json-output
description: JSON output fixture.
---

# JSON Output
"#,
        );

        let output =
            run_scan_output(scan_command(&workspace, ReportFormat::Json)).expect("run JSON scan");

        assert!(output.starts_with("{\n"));
        assert!(output.contains("\"packages\""));
        assert!(output.contains("\"summary\""));
        assert!(output.contains("\"json-output\""));
        assert!(output.ends_with('\n'));

        let value: serde_json::Value = serde_json::from_str(&output).expect("parse JSON output");
        assert_eq!(value["audit"]["output_schema_version"], "1");
        assert_eq!(
            value["audit"]["scanner"]["version"],
            env!("CARGO_PKG_VERSION")
        );
        assert_eq!(value["audit"]["timestamp"], serde_json::Value::Null);
        assert_eq!(
            value["audit"]["command"]["format"],
            serde_json::json!("json")
        );
        assert_eq!(
            value["audit"]["command"]["mode"],
            serde_json::json!("default")
        );
        assert_audit_path_metadata_present(&value["audit"]["scan"]["root"]);
        assert_eq!(value["audit"]["repository"], serde_json::Value::Null);
        assert_platform_metadata_shape(&value["audit"]["platform"]);
        assert_eq!(
            value["audit"]["host_profiles"]["selected"],
            serde_json::json!(HOST_PROFILES)
        );
        assert!(value["audit"].get("methodology").is_none());
    }

    #[test]
    fn run_scan_includes_config_methodology_metadata_in_json() {
        let workspace = CliTestWorkspace::new("config-methodology-json");
        workspace.write_file("SKILL.md", valid_skill("config-methodology-json"));
        workspace.write_file(
            "agent-audit.yaml",
            r#"
methodology:
  corpus_name: v0.8 public audit
  corpus_entry_id: repo-001
  methodology_version: 2026-05
  inclusion_tags:
    - security
    - public
  repo_classification: oss-skill-repo
  scan_batch_id: batch-2026-05
"#,
        );

        let output = run_scan_output(configured_scan_command(
            &workspace,
            ReportFormat::Json,
            "agent-audit.yaml",
        ))
        .expect("run JSON scan");
        let value: serde_json::Value = serde_json::from_str(&output).expect("parse JSON output");
        let methodology = &value["audit"]["methodology"];

        assert_eq!(methodology["corpus_name"], "v0.8 public audit");
        assert_eq!(methodology["corpus_entry_id"], "repo-001");
        assert_eq!(methodology["methodology_version"], "2026-05");
        assert_eq!(
            methodology["inclusion_tags"],
            serde_json::json!(["public", "security"])
        );
        assert_eq!(methodology["repo_classification"], "oss-skill-repo");
        assert_eq!(methodology["scan_batch_id"], "batch-2026-05");
    }

    #[test]
    fn run_scan_cli_methodology_overrides_config_metadata() {
        let workspace = CliTestWorkspace::new("cli-methodology-json");
        workspace.write_file("SKILL.md", valid_skill("cli-methodology-json"));
        workspace.write_file(
            "agent-audit.yaml",
            r#"
methodology:
  corpus_name: config corpus
  inclusion_tags:
    - config
  repo_classification: internal
"#,
        );

        let output = run_scan_output(ScanCommand {
            corpus_name: Some("cli corpus".to_owned()),
            inclusion_tags: vec!["zeta".to_owned(), "alpha".to_owned(), "zeta".to_owned()],
            repo_classification: Some("oss".to_owned()),
            ..configured_scan_command(&workspace, ReportFormat::Json, "agent-audit.yaml")
        })
        .expect("run JSON scan");
        let value: serde_json::Value = serde_json::from_str(&output).expect("parse JSON output");
        let methodology = &value["audit"]["methodology"];

        assert_eq!(methodology["corpus_name"], "cli corpus");
        assert_eq!(
            methodology["inclusion_tags"],
            serde_json::json!(["alpha", "zeta"])
        );
        assert_eq!(methodology["repo_classification"], "oss");
    }

    #[test]
    fn runs_scan_with_public_json_output_without_manifest_body() {
        let workspace = CliTestWorkspace::new("public-json-output");
        workspace.write_file(
            "SKILL.md",
            r#"---
name: public-json-output
description: Public JSON output fixture.
---

# Public JSON Output

PUBLIC_JSON_FULL_MANIFEST_BODY_SHOULD_NOT_APPEAR
"#,
        );

        let output = run_scan_output(scan_command(&workspace, ReportFormat::PublicJson))
            .expect("run public JSON scan");

        assert!(output.starts_with("{\n"));
        assert!(output.ends_with('\n'));
        assert!(!output.contains("PUBLIC_JSON_FULL_MANIFEST_BODY_SHOULD_NOT_APPEAR"));

        let value: serde_json::Value =
            serde_json::from_str(&output).expect("parse public JSON output");
        assert_eq!(
            value["audit"]["command"]["format"],
            serde_json::json!("public-json")
        );
        assert_eq!(value["packages"][0]["name"], "public-json-output");
        assert!(value["packages"][0]["manifest"].is_null());
        assert!(value["packages"][0]["body"].is_null());
        assert!(value["metrics"]["summary"]["package_count"].is_number());
        assert!(value["findings"].is_array());
        assert!(value["finding_groups"].is_array());
        assert!(value["patterns"].is_array());
    }

    #[test]
    fn run_scan_includes_cli_methodology_metadata_in_public_json() {
        let workspace = CliTestWorkspace::new("public-json-methodology");
        workspace.write_file("SKILL.md", valid_skill("public-json-methodology"));

        let output = run_scan_output(ScanCommand {
            corpus_name: Some("v0.8 public audit".to_owned()),
            corpus_entry_id: Some("repo-002".to_owned()),
            methodology_version: Some("2026-05".to_owned()),
            inclusion_tags: vec!["public".to_owned()],
            scan_batch_id: Some("batch-2026-05".to_owned()),
            ..scan_command(&workspace, ReportFormat::PublicJson)
        })
        .expect("run public JSON scan");
        let value: serde_json::Value =
            serde_json::from_str(&output).expect("parse public JSON output");

        assert_eq!(
            value["audit"]["methodology"]["corpus_name"],
            "v0.8 public audit"
        );
        assert_eq!(value["audit"]["methodology"]["corpus_entry_id"], "repo-002");
        assert_eq!(
            value["audit"]["methodology"]["methodology_version"],
            "2026-05"
        );
        assert_eq!(
            value["audit"]["methodology"]["inclusion_tags"],
            serde_json::json!(["public"])
        );
        assert_eq!(
            value["audit"]["methodology"]["scan_batch_id"],
            "batch-2026-05"
        );
    }

    #[test]
    fn run_scan_audit_paths_preserve_user_provided_relative_paths() {
        let scan_root = PathBuf::from("../../fixtures/compatibility/valid/spec-basic");
        let config_path =
            PathBuf::from("../../fixtures/spec/phase2/config/valid/empty.agent-audit.yaml");

        let output = run_scan_output(ScanCommand {
            path: scan_root.clone(),
            config: Some(config_path.clone()),
            format: ReportFormat::Json,
            ..scan_path_command(scan_root.clone(), ReportFormat::Json)
        })
        .expect("run scan with relative paths");
        let value: serde_json::Value = serde_json::from_str(&output).expect("parse JSON output");

        assert_eq!(
            value["audit"]["scan"]["root"],
            path_metadata_string(&scan_root)
        );
        assert_eq!(
            value["audit"]["config"]["path"],
            path_metadata_string(&config_path)
        );
        assert_eq!(value["audit"]["repository"], serde_json::Value::Null);
    }

    #[test]
    fn runs_scan_with_sarif_output() {
        let workspace = CliTestWorkspace::new("sarif-output");
        workspace.write_file(
            "SKILL.md",
            r#"---
name: sarif-output
description: SARIF output fixture.
---

# SARIF Output
"#,
        );

        let output =
            run_scan_output(scan_command(&workspace, ReportFormat::Sarif)).expect("run SARIF scan");

        assert!(output.starts_with("{\n"));
        assert!(output.contains("\"version\": \"2.1.0\""));
        assert!(output.contains("\"Agent Skill Auditor\""));
        assert!(output.contains("\"invocations\""));
        assert!(output.contains("\"agentAudit\""));
        assert!(output.ends_with('\n'));
    }

    #[test]
    fn runs_scan_with_html_output() {
        let workspace = CliTestWorkspace::new("html-output");
        workspace.write_file(
            "SKILL.md",
            r#"---
name: html-output
description: HTML output fixture.
---

# HTML Output
"#,
        );

        let output =
            run_scan_output(scan_command(&workspace, ReportFormat::Html)).expect("run HTML scan");

        assert!(output.starts_with("<!doctype html>\n"));
        assert!(output.contains("<h1>Agent Skill Auditor Report</h1>"));
        assert!(output.contains("<h2 id=\"audit-metadata\">Audit Metadata</h2>"));
        assert!(output.contains("<th>Timestamp</th><td>null</td>"));
        assert!(output.contains("html-output"));
        assert!(output.ends_with('\n'));
    }

    #[test]
    fn run_scan_includes_methodology_metadata_in_html_when_provided() {
        let workspace = CliTestWorkspace::new("html-methodology");
        workspace.write_file("SKILL.md", valid_skill("html-methodology"));

        let output = run_scan_output(ScanCommand {
            corpus_name: Some("v0.8 public audit".to_owned()),
            corpus_entry_id: Some("repo-html".to_owned()),
            inclusion_tags: vec!["public".to_owned(), "html".to_owned()],
            repo_classification: Some("fixture".to_owned()),
            ..scan_command(&workspace, ReportFormat::Html)
        })
        .expect("run HTML scan");

        assert!(output.contains("<th>Corpus name</th><td>v0.8 public audit</td>"));
        assert!(output.contains("<th>Corpus entry ID</th><td>repo-html</td>"));
        assert!(output.contains("<th>Inclusion tags</th><td>html, public</td>"));
        assert!(output.contains("<th>Repository classification</th><td>fixture</td>"));
    }

    #[test]
    fn run_scan_output_omitted_preserves_stdout_behavior() {
        let workspace = CliTestWorkspace::new("stdout-unchanged");
        workspace.write_file("SKILL.md", valid_skill("stdout-unchanged"));

        let first = run_scan_output(scan_command(&workspace, ReportFormat::Summary))
            .expect("run first stdout scan");
        let second = run_scan_output(ScanCommand {
            output: None,
            ..scan_command(&workspace, ReportFormat::Summary)
        })
        .expect("run second stdout scan");

        assert_eq!(first, second);
        assert!(second.starts_with("Agent Skill Auditor scan summary\n"));
    }

    #[test]
    fn run_scan_writes_output_file_and_suppresses_report_stdout() {
        let workspace = CliTestWorkspace::new("file-output");
        workspace.write_file("SKILL.md", valid_skill("file-output"));
        let output_path = workspace.root.join("reports/nested/report.json");
        let mut stdout = Vec::new();

        run_scan_with_writer(
            ScanCommand {
                output: Some(output_path.clone()),
                ..scan_command(&workspace, ReportFormat::Json)
            },
            &mut stdout,
        )
        .expect("run scan with file output");

        assert!(stdout.is_empty());
        let report = fs::read_to_string(output_path).expect("read report file");
        assert!(report.starts_with("{\n"));
        assert!(report.contains("\"file-output\""));
    }

    #[test]
    fn run_scan_ci_output_reports_policy_path_and_fail_on_exit_behavior() {
        let workspace = CliTestWorkspace::new("ci-policy-output");
        workspace.write_file("SKILL.md", missing_name_skill());
        let output_path = workspace.root.join("reports/ci.txt");
        let mut stdout = Vec::new();

        let result = run_scan_with_writer(
            ScanCommand {
                mode: ReportMode::Ci,
                output: Some(output_path.clone()),
                fail_on: vec![Severity::Low],
                ..scan_command(&workspace, ReportFormat::Summary)
            },
            &mut stdout,
        );
        let error = result.expect_err("CI fail_on low should fail after writing report");

        assert!(stdout.is_empty());
        assert!(error
            .to_string()
            .contains("fail_on matched an unsuppressed finding severity"));
        let report = fs::read_to_string(&output_path).expect("read CI report file");
        assert!(report.starts_with("Agent Skill Auditor CI scan summary\n"));
        assert!(report.contains("CI policy: fail_on=low blocking_groups=1"));
        assert!(report.contains(&format!(
            "Report output: {} (format=summary)",
            path_metadata_string(&output_path)
        )));
        assert!(report.contains("Exit code behavior: returns 1 after rendering"));
        assert!(report.contains("Top blocking groups: showing 1 of 1 canonical blocking groups."));
        assert!(report.ends_with('\n'));
    }

    #[test]
    fn run_scan_rejects_existing_directory_output_target() {
        let workspace = CliTestWorkspace::new("directory-output-target");
        workspace.write_file("SKILL.md", valid_skill("directory-output-target"));
        let mut stdout = Vec::new();

        let error = run_scan_with_writer(
            ScanCommand {
                output: Some(workspace.root.clone()),
                ..scan_command(&workspace, ReportFormat::Json)
            },
            &mut stdout,
        )
        .expect_err("directory output target should fail");
        let message = error.to_string();

        assert!(stdout.is_empty());
        assert!(message.contains("--output target is an existing directory"));
        assert!(message.contains("directory-output-target"));
    }

    #[test]
    fn run_scan_applies_fail_on_after_successful_output_file_write() {
        let workspace = CliTestWorkspace::new("fail-on-after-file-write");
        workspace.write_file("SKILL.md", missing_name_skill());
        let output_path = workspace.root.join("reports/report.json");
        let mut stdout = Vec::new();

        let error = run_scan_with_writer(
            ScanCommand {
                fail_on: vec![Severity::Low],
                output: Some(output_path.clone()),
                ..scan_command(&workspace, ReportFormat::Json)
            },
            &mut stdout,
        )
        .expect_err("fail_on should fail after output write");
        let report = fs::read_to_string(output_path).expect("report should be written");

        assert!(stdout.is_empty());
        assert!(report.contains("\"rule_id\": \"SKILL001\""));
        assert!(error
            .to_string()
            .contains("fail_on matched an unsuppressed finding severity"));
    }

    #[test]
    fn run_scan_rejects_open_without_output_before_scanning() {
        let workspace = CliTestWorkspace::new("open-without-output");
        let mut stdout = Vec::new();

        let error = run_scan_with_writer(
            ScanCommand {
                path: workspace.root.join("missing-scan-target"),
                format: ReportFormat::Html,
                open: true,
                ..scan_command(&workspace, ReportFormat::Html)
            },
            &mut stdout,
        )
        .expect_err("--open without output should fail before scanning");

        assert!(stdout.is_empty());
        assert!(error.to_string().contains("--open requires --output"));
    }

    #[test]
    fn run_scan_rejects_open_with_non_html_format_before_scanning() {
        let workspace = CliTestWorkspace::new("open-non-html");
        let mut stdout = Vec::new();

        let error = run_scan_with_writer(
            ScanCommand {
                path: workspace.root.join("missing-scan-target"),
                output: Some(workspace.root.join("report.json")),
                open: true,
                ..scan_command(&workspace, ReportFormat::Json)
            },
            &mut stdout,
        )
        .expect_err("--open with non-html format should fail before scanning");

        assert!(stdout.is_empty());
        assert!(error
            .to_string()
            .contains("--open can only be used with --format html"));
    }

    #[test]
    fn run_scan_opens_html_output_after_successful_fail_on_check() {
        let workspace = CliTestWorkspace::new("open-html-output");
        workspace.write_file("SKILL.md", valid_skill("open-html-output"));
        let output_path = workspace.root.join("report.html");
        let opened = Cell::new(false);
        let mut stdout = Vec::new();

        run_scan_with_writer_and_opener(
            ScanCommand {
                output: Some(output_path.clone()),
                open: true,
                ..scan_command(&workspace, ReportFormat::Html)
            },
            &mut stdout,
            |path| {
                assert_eq!(path, output_path.as_path());
                opened.set(true);
                Ok(())
            },
        )
        .expect("HTML output should open after successful scan");

        assert!(stdout.is_empty());
        assert!(opened.get());
        assert!(fs::read_to_string(output_path)
            .expect("read HTML report")
            .starts_with("<!doctype html>\n"));
    }

    #[test]
    fn run_scan_does_not_call_opener_when_fail_on_matches() {
        let workspace = CliTestWorkspace::new("open-skipped-on-fail-on");
        workspace.write_file("SKILL.md", missing_name_skill());
        let output_path = workspace.root.join("report.html");
        let opened = Cell::new(false);
        let mut stdout = Vec::new();

        let error = run_scan_with_writer_and_opener(
            ScanCommand {
                fail_on: vec![Severity::Low],
                output: Some(output_path.clone()),
                open: true,
                ..scan_command(&workspace, ReportFormat::Html)
            },
            &mut stdout,
            |_| {
                opened.set(true);
                Ok(())
            },
        )
        .expect_err("fail_on should prevent opening");

        assert!(stdout.is_empty());
        assert!(!opened.get());
        assert!(fs::read_to_string(output_path)
            .expect("read HTML report")
            .contains("SKILL001"));
        assert!(error
            .to_string()
            .contains("fail_on matched an unsuppressed finding severity"));
    }

    #[test]
    fn run_scan_renders_malformed_frontmatter_findings() {
        let workspace = CliTestWorkspace::new("parse-error");
        workspace.write_file(
            "SKILL.md",
            r#"---
name: [unterminated
---

# Malformed
"#,
        );

        let output = run_scan_output(scan_command(&workspace, ReportFormat::Summary))
            .expect("malformed frontmatter should render report");

        assert!(output.starts_with("Agent Skill Auditor scan summary\n"));
        assert!(output.contains("Packages: 1\n"));
        assert!(output.contains("Invalid manifests: 1\n"));
        assert!(output.contains("SKILL041 [low/high/spec] x1 packages=1"));
        assert!(output.contains("The skill manifest frontmatter could not be parsed:"));
        assert!(output.ends_with('\n'));
    }

    fn run_scan_output(command: ScanCommand) -> Result<String> {
        let (output, result) = run_scan_attempt(command);

        result?;

        Ok(output)
    }

    fn run_scan_attempt(command: ScanCommand) -> (String, Result<()>) {
        let mut output = Vec::new();

        let result = run_scan_with_writer(command, &mut output);

        (
            String::from_utf8(output).expect("scan output should be UTF-8"),
            result,
        )
    }

    #[test]
    fn run_scan_with_writer_writes_summary_findings_from_report_renderer() {
        let workspace = CliTestWorkspace::new("summary-finding-output");
        workspace.write_file(
            "SKILL.md",
            r#"---
description: Missing name fixture.
---

This manifest intentionally starts with a paragraph so the scanner cannot derive a heading fallback name.
"#,
        );

        let output = run_scan_output(scan_command(&workspace, ReportFormat::Summary))
            .expect("run summary scan");

        assert!(output.contains("Finding groups:\n"));
        assert!(output.contains("[low/high/spec]"));
        assert!(output.contains("SKILL.md:"));
        assert!(output.contains("The skill manifest does not declare a name."));
        assert!(output.ends_with('\n'));
    }

    #[test]
    fn run_scan_passes_report_mode_to_renderer() {
        let workspace = CliTestWorkspace::new("verbose-mode-output");
        workspace.write_file("SKILL.md", missing_name_skill());

        let output = run_scan_output(ScanCommand {
            mode: ReportMode::Verbose,
            ..scan_command(&workspace, ReportFormat::Summary)
        })
        .expect("run verbose summary scan");

        assert!(output.starts_with("Agent Skill Auditor verbose scan summary\n"));
        assert!(output.contains("Full findings:"));
        assert!(output.contains("The skill manifest does not declare a name."));
    }

    #[test]
    fn run_scan_default_does_not_fail_on_low_findings() {
        let workspace = CliTestWorkspace::new("default-non-failing");
        workspace.write_file("SKILL.md", missing_name_skill());

        let output = run_scan_output(scan_command(&workspace, ReportFormat::Summary))
            .expect("default scan should render low findings without failing");

        assert!(output.contains("SKILL001 [low/high/spec] x1 packages=1"));
    }

    #[test]
    fn run_scan_config_fail_low_triggers_after_output() {
        let workspace = CliTestWorkspace::new("config-fail-low");
        workspace.write_file("SKILL.md", missing_name_skill());
        workspace.write_file(
            "agent-audit.yaml",
            r#"
fail_on:
  - low
"#,
        );

        let (output, result) = run_scan_attempt(configured_scan_command(
            &workspace,
            ReportFormat::Summary,
            "agent-audit.yaml",
        ));
        let error = result.expect_err("low fail_on should fail after rendering");

        assert!(output.starts_with("Agent Skill Auditor scan summary\n"));
        assert!(output.contains("SKILL001 [low/high/spec] x1 packages=1"));
        assert!(error
            .to_string()
            .contains("fail_on matched an unsuppressed finding severity"));
    }

    #[test]
    fn run_scan_multiple_config_fail_on_values_match_low_findings() {
        let workspace = CliTestWorkspace::new("config-multiple-fail-low");
        workspace.write_file("SKILL.md", missing_name_skill());
        workspace.write_file(
            "agent-audit.yaml",
            r#"
fail_on:
  - medium
  - low
"#,
        );

        let (output, result) = run_scan_attempt(configured_scan_command(
            &workspace,
            ReportFormat::Summary,
            "agent-audit.yaml",
        ));
        let error = result.expect_err("multiple config fail_on values should match low finding");

        assert!(output.contains("SKILL001 [low/high/spec] x1 packages=1"));
        assert!(error
            .to_string()
            .contains("fail_on matched an unsuppressed finding severity"));
    }

    #[test]
    fn run_scan_config_high_does_not_fail_low_findings() {
        let workspace = CliTestWorkspace::new("config-high-low-finding");
        workspace.write_file("SKILL.md", missing_name_skill());
        workspace.write_file(
            "agent-audit.yaml",
            r#"
fail_on:
  - high
"#,
        );

        let output = run_scan_output(configured_scan_command(
            &workspace,
            ReportFormat::Summary,
            "agent-audit.yaml",
        ))
        .expect("high fail_on should not match low finding");

        assert!(output.contains("SKILL001 [low/high/spec] x1 packages=1"));
    }

    #[test]
    fn run_scan_multiple_config_fail_on_values_do_not_match_low_findings() {
        let workspace = CliTestWorkspace::new("config-multiple-no-low");
        workspace.write_file("SKILL.md", missing_name_skill());
        workspace.write_file(
            "agent-audit.yaml",
            r#"
fail_on:
  - medium
  - high
"#,
        );

        let output = run_scan_output(configured_scan_command(
            &workspace,
            ReportFormat::Summary,
            "agent-audit.yaml",
        ))
        .expect("multiple config fail_on values should not match low finding");

        assert!(output.contains("SKILL001 [low/high/spec] x1 packages=1"));
    }

    #[test]
    fn run_scan_suppressed_low_does_not_fail() {
        let workspace = CliTestWorkspace::new("suppressed-low-fail-on");
        workspace.write_file("SKILL.md", missing_name_skill());
        workspace.write_file(
            "agent-audit.yaml",
            r#"
fail_on:
  - low
ignore:
  - rule: SKILL001
    path: SKILL.md
    reason: Accepted missing name fixture.
"#,
        );

        let output = run_scan_output(configured_scan_command(
            &workspace,
            ReportFormat::Json,
            "agent-audit.yaml",
        ))
        .expect("suppressed low finding should not trigger fail_on");
        let value: serde_json::Value = serde_json::from_str(&output).expect("parse JSON output");

        assert_eq!(value["summary"]["finding_count"], 0);
        assert_eq!(value["summary"]["suppressed_finding_count"], 1);
        assert_eq!(
            value["suppressed_findings"][0]["finding"]["rule_id"],
            "SKILL001"
        );
    }

    #[test]
    fn write_report_ignores_suppressed_high_findings_for_fail_on() {
        let report = ScanReport {
            audit: agent_audit_core::model::AuditMetadata::default(),
            packages: Vec::new(),
            summary: ScanSummary {
                package_count: 0,
                finding_count: 0,
                suppressed_finding_count: 1,
                invalid_manifest_count: 0,
                broken_reference_count: 0,
                actual_secret_evidence_count: 0,
                prompt_secret_exposure_count: 0,
            },
            findings: Vec::new(),
            finding_groups: Vec::new(),
            patterns: Vec::new(),
            suppressed_findings: vec![SuppressedFinding {
                finding: test_finding("SEC005", Severity::High),
                suppression: SuppressionMatch {
                    matched_rule: "SEC005".to_owned(),
                    matched_path: Some("SKILL.md".to_owned()),
                    matched_match: None,
                    reason: "Accepted privileged setup fixture.".to_owned(),
                },
            }],
            supply_chain: SupplyChainInventory::default(),
            compatibility: CompatibilityMatrix::default(),
        };
        let mut output = Vec::new();

        write_report_and_apply_fail_on(&report, ReportFormat::Json, &[Severity::High], &mut output)
            .expect("suppressed high finding should not trigger fail_on");
        let output = String::from_utf8(output).expect("scan output should be UTF-8");
        let value: serde_json::Value = serde_json::from_str(&output).expect("parse JSON output");

        assert_eq!(value["summary"]["finding_count"], 0);
        assert_eq!(value["summary"]["suppressed_finding_count"], 1);
        assert_eq!(
            value["suppressed_findings"][0]["finding"]["severity"],
            "high"
        );
        assert_eq!(
            value["suppressed_findings"][0]["finding"]["rule_id"],
            "SEC005"
        );
    }

    #[test]
    fn run_scan_cli_fail_low_works_without_config() {
        let workspace = CliTestWorkspace::new("cli-fail-low");
        workspace.write_file("SKILL.md", missing_name_skill());

        let (output, result) = run_scan_attempt(failing_scan_command(
            &workspace,
            ReportFormat::Summary,
            vec![Severity::Low],
        ));

        result.expect_err("CLI fail_on low should fail without config");
        assert!(output.contains("SKILL001 [low/high/spec] x1 packages=1"));
    }

    #[test]
    fn run_scan_multiple_cli_fail_on_values_match_low_findings() {
        let workspace = CliTestWorkspace::new("cli-multiple-fail-low");
        workspace.write_file("SKILL.md", missing_name_skill());

        let (output, result) = run_scan_attempt(failing_scan_command(
            &workspace,
            ReportFormat::Summary,
            vec![Severity::Medium, Severity::Low],
        ));
        let error = result.expect_err("multiple CLI fail_on values should match low finding");

        assert!(output.contains("SKILL001 [low/high/spec] x1 packages=1"));
        assert!(error
            .to_string()
            .contains("fail_on matched an unsuppressed finding severity"));
    }

    #[test]
    fn run_scan_cli_high_overrides_config_low() {
        let workspace = CliTestWorkspace::new("cli-overrides-config");
        workspace.write_file("SKILL.md", missing_name_skill());
        workspace.write_file(
            "agent-audit.yaml",
            r#"
fail_on:
  - low
"#,
        );

        let mut command =
            configured_scan_command(&workspace, ReportFormat::Json, "agent-audit.yaml");
        command.fail_on = vec![Severity::High];
        let output =
            run_scan_output(command).expect("CLI fail_on high should override config fail_on low");
        let value: serde_json::Value = serde_json::from_str(&output).expect("parse JSON output");

        assert_eq!(value["findings"][0]["rule_id"], "SKILL001");
        assert_eq!(
            value["audit"]["command"]["fail_on"],
            serde_json::json!(["high"])
        );
    }

    #[test]
    fn run_scan_phase2_fail_on_low_fixture_fails_after_output() {
        let fixture = phase2_fail_on_fixture("low-unsuppressed");

        let (output, result) = run_scan_attempt(configured_path_scan_command(
            fixture,
            ReportFormat::Summary,
            "agent-audit.yaml",
        ));
        let error = result.expect_err("low fail_on fixture should fail");

        assert!(output.contains("SKILL001 [low/high/spec] x1 packages=1"));
        assert!(error
            .to_string()
            .contains("fail_on matched an unsuppressed finding severity"));
    }

    #[test]
    fn run_scan_phase2_suppressed_low_fixture_does_not_fail() {
        let fixture = phase2_fail_on_fixture("suppressed-low");

        let output = run_scan_output(configured_path_scan_command(
            fixture,
            ReportFormat::Json,
            "agent-audit.yaml",
        ))
        .expect("suppressed low fixture should not fail");
        let value: serde_json::Value = serde_json::from_str(&output).expect("parse JSON output");

        assert_eq!(value["summary"]["finding_count"], 0);
        assert_eq!(value["summary"]["suppressed_finding_count"], 1);
        assert_eq!(
            value["suppressed_findings"][0]["finding"]["rule_id"],
            "SKILL001"
        );
    }

    #[test]
    fn run_scan_phase2_high_threshold_fixture_does_not_fail_low_finding() {
        let fixture = phase2_fail_on_fixture("high-threshold");

        let output = run_scan_output(configured_path_scan_command(
            fixture,
            ReportFormat::Summary,
            "agent-audit.yaml",
        ))
        .expect("high threshold should not fail low findings");

        assert!(output.contains("SKILL001 [low/high/spec] x1 packages=1"));
    }

    #[test]
    fn run_scan_fail_on_low_matches_active_compatibility_finding_after_json_output() {
        let workspace = CliTestWorkspace::new("compatibility-fail-on-low");
        workspace.write_file("SKILL.md", compatibility_unknown_frontmatter_skill());

        let (output, result) = run_scan_attempt(failing_scan_command(
            &workspace,
            ReportFormat::Json,
            vec![Severity::Low],
        ));
        let error = result.expect_err("low fail_on should match compatibility finding");
        let value: serde_json::Value =
            serde_json::from_str(&output).expect("JSON output should be written before fail_on");

        assert_eq!(value["findings"][0]["rule_id"], "SKILL040");
        assert_eq!(value["findings"][0]["severity"], "low");
        assert_eq!(value["findings"][0]["category"], "compatibility");
        assert!(error
            .to_string()
            .contains("fail_on matched an unsuppressed finding severity"));
    }

    #[test]
    fn run_scan_fail_on_medium_does_not_match_low_compatibility_finding() {
        let workspace = CliTestWorkspace::new("compatibility-fail-on-medium");
        workspace.write_file("SKILL.md", compatibility_unknown_frontmatter_skill());

        let output = run_scan_output(failing_scan_command(
            &workspace,
            ReportFormat::Json,
            vec![Severity::Medium],
        ))
        .expect("medium fail_on should not match low compatibility finding");
        let value: serde_json::Value = serde_json::from_str(&output).expect("parse JSON output");

        assert_eq!(value["findings"][0]["rule_id"], "SKILL040");
        assert_eq!(value["findings"][0]["severity"], "low");
        assert_eq!(value["findings"][0]["category"], "compatibility");
    }

    #[test]
    fn run_scan_fail_on_low_ignores_suppressed_compatibility_finding() {
        let workspace = CliTestWorkspace::new("compatibility-fail-on-suppressed");
        workspace.write_file("SKILL.md", compatibility_unknown_frontmatter_skill());
        workspace.write_file(
            "agent-audit.yaml",
            r#"
fail_on:
  - low
ignore:
  - rule: SKILL040
    path: SKILL.md
    reason: Host metadata is accepted for this compatibility fixture.
"#,
        );

        let output = run_scan_output(configured_scan_command(
            &workspace,
            ReportFormat::Json,
            "agent-audit.yaml",
        ))
        .expect("suppressed compatibility finding should not trigger fail_on");
        let value: serde_json::Value = serde_json::from_str(&output).expect("parse JSON output");

        assert_eq!(value["summary"]["finding_count"], 0);
        assert_eq!(value["summary"]["suppressed_finding_count"], 1);
        assert_eq!(
            value["suppressed_findings"][0]["finding"]["rule_id"],
            "SKILL040"
        );
        assert_eq!(
            value["suppressed_findings"][0]["finding"]["category"],
            "compatibility"
        );
    }

    #[test]
    fn run_scan_fail_on_low_matches_active_security_finding_after_json_output() {
        let workspace = CliTestWorkspace::new("security-fail-on-low");
        workspace.write_file("SKILL.md", security_package_install_skill());
        workspace.write_file(
            "scripts/install.sh",
            "# SPDX-License-Identifier: Apache-2.0\n\nnpm install left-pad\n",
        );

        let (output, result) = run_scan_attempt(failing_scan_command(
            &workspace,
            ReportFormat::Json,
            vec![Severity::Low],
        ));
        let error = result.expect_err("low fail_on should match security finding");
        let value: serde_json::Value =
            serde_json::from_str(&output).expect("JSON output should be written before fail_on");

        assert_eq!(value["findings"][0]["rule_id"], "SEC009");
        assert_eq!(value["findings"][0]["severity"], "low");
        assert_eq!(value["findings"][0]["category"], "security");
        assert!(error
            .to_string()
            .contains("fail_on matched an unsuppressed finding severity"));
    }

    #[test]
    fn run_scan_fail_on_medium_does_not_match_low_security_finding() {
        let workspace = CliTestWorkspace::new("security-fail-on-medium");
        workspace.write_file("SKILL.md", security_package_install_skill());
        workspace.write_file(
            "scripts/install.sh",
            "# SPDX-License-Identifier: Apache-2.0\n\nnpm install left-pad\n",
        );

        let (output, result) = run_scan_attempt(failing_scan_command(
            &workspace,
            ReportFormat::Json,
            vec![Severity::Medium],
        ));
        let error = result.expect_err("medium fail_on should match supply-chain findings");
        let value: serde_json::Value = serde_json::from_str(&output).expect("parse JSON output");

        assert_eq!(value["findings"][0]["rule_id"], "SEC009");
        assert_eq!(value["findings"][0]["severity"], "low");
        assert_eq!(value["findings"][0]["category"], "security");
        assert_eq!(value["findings"][1]["rule_id"], "SUPPLY003");
        assert_eq!(value["findings"][1]["severity"], "medium");
        assert_eq!(value["findings"][1]["category"], "reproducibility");
        assert!(error
            .to_string()
            .contains("fail_on matched an unsuppressed finding severity"));
    }

    #[test]
    fn run_scan_fail_on_low_ignores_suppressed_security_finding() {
        let workspace = CliTestWorkspace::new("security-fail-on-suppressed");
        workspace.write_file("SKILL.md", security_package_install_skill());
        workspace.write_file(
            "scripts/install.sh",
            "# SPDX-License-Identifier: Apache-2.0\n\nnpm install left-pad\n",
        );
        workspace.write_file(
            "agent-audit.yaml",
            r#"
fail_on:
  - low
ignore:
  - rule: SEC009
    path: scripts/install.sh
    reason: Package install command is reviewed in this fixture.
"#,
        );

        let output = run_scan_output(configured_scan_command(
            &workspace,
            ReportFormat::Json,
            "agent-audit.yaml",
        ))
        .expect("suppressed security finding should not trigger fail_on");
        let value: serde_json::Value = serde_json::from_str(&output).expect("parse JSON output");

        assert_eq!(value["summary"]["finding_count"], 2);
        assert_eq!(value["summary"]["suppressed_finding_count"], 1);
        assert_eq!(value["findings"][0]["rule_id"], "SUPPLY003");
        assert_eq!(value["findings"][1]["rule_id"], "SUPPLY004");
        assert_eq!(
            value["suppressed_findings"][0]["finding"]["rule_id"],
            "SEC009"
        );
        assert_eq!(
            value["suppressed_findings"][0]["finding"]["category"],
            "security"
        );
    }

    #[test]
    fn run_scan_validates_explicit_config_before_scanning() {
        let workspace = CliTestWorkspace::new("valid-config");
        workspace.write_file(
            "SKILL.md",
            r#"---
name: valid-config
description: Valid explicit config fixture.
---

# Valid Config
"#,
        );
        workspace.write_file(
            "agent-audit.yaml",
            r#"
profiles:
  - codex
fail_on:
  - high
ignore:
  - rule: SKILL010
    path: SKILL.md
    reason: Accepted fixture.
"#,
        );

        let output = run_scan_output(configured_scan_command(
            &workspace,
            ReportFormat::Summary,
            "agent-audit.yaml",
        ))
        .expect("valid config should load before scan");

        assert!(output.contains("Packages: 1\n"));
        assert!(output.ends_with('\n'));
    }

    #[test]
    fn run_scan_cli_profiles_override_config_profiles() {
        let workspace = CliTestWorkspace::new("cli-profiles-override-config");
        workspace.write_file("SKILL.md", valid_skill("cli-profiles-override-config"));
        workspace.write_file(
            "agent-audit.yaml",
            r#"
profiles:
  - generic
  - codex
"#,
        );

        let output = run_scan_output(configured_profile_scan_command(
            &workspace,
            ReportFormat::Json,
            &["claude-code", "agent-skills-spec"],
        ))
        .expect("CLI profiles should override config profiles");
        let value: serde_json::Value = serde_json::from_str(&output).expect("parse JSON output");

        assert_eq!(
            value["compatibility"]["profiles"],
            serde_json::json!(["claude-code", "agent-skills-spec"])
        );
        assert_eq!(
            profile_names(&value["compatibility"]["matrix"][0]["profiles"]),
            vec!["claude-code", "agent-skills-spec"]
        );
    }

    #[test]
    fn run_scan_profile_aliases_emit_canonical_json_profiles() {
        let workspace = CliTestWorkspace::new("cli-profile-aliases-json");
        workspace.write_file("SKILL.md", valid_skill("cli-profile-aliases-json"));
        let command = parsed_scan_command([
            "agent-audit",
            "scan",
            workspace
                .root
                .to_str()
                .expect("workspace path should be UTF-8"),
            "--format",
            "json",
            "--profile",
            "spec,claude,copilot",
        ]);

        let output = run_scan_output(command).expect("profile aliases should render JSON scan");
        let value: serde_json::Value = serde_json::from_str(&output).expect("parse JSON output");

        assert_eq!(
            value["compatibility"]["profiles"],
            serde_json::json!(["agent-skills-spec", "claude-code", "github-copilot"])
        );
        assert_eq!(
            profile_names(&value["compatibility"]["matrix"][0]["profiles"]),
            vec!["agent-skills-spec", "claude-code", "github-copilot"]
        );
    }

    #[test]
    fn run_scan_config_profile_aliases_emit_canonical_json_profiles() {
        let workspace = CliTestWorkspace::new("config-profile-aliases-json");
        workspace.write_file("SKILL.md", valid_skill("config-profile-aliases-json"));
        workspace.write_file(
            "agent-audit.yaml",
            r#"
profiles:
  - spec
  - claude
  - copilot
"#,
        );

        let output = run_scan_output(configured_scan_command(
            &workspace,
            ReportFormat::Json,
            "agent-audit.yaml",
        ))
        .expect("config profile aliases should render JSON scan");
        let value: serde_json::Value = serde_json::from_str(&output).expect("parse JSON output");

        assert_eq!(
            value["compatibility"]["profiles"],
            serde_json::json!(["agent-skills-spec", "claude-code", "github-copilot"])
        );
        assert_eq!(
            profile_names(&value["compatibility"]["matrix"][0]["profiles"]),
            vec!["agent-skills-spec", "claude-code", "github-copilot"]
        );
    }

    #[test]
    fn run_scan_without_cli_profiles_leaves_config_profiles() {
        let workspace = CliTestWorkspace::new("cli-profiles-leave-config");
        workspace.write_file("SKILL.md", valid_skill("cli-profiles-leave-config"));
        workspace.write_file(
            "agent-audit.yaml",
            r#"
profiles:
  - generic
  - codex
"#,
        );

        let output = run_scan_output(configured_scan_command(
            &workspace,
            ReportFormat::Json,
            "agent-audit.yaml",
        ))
        .expect("omitted CLI profiles should leave config profiles");
        let value: serde_json::Value = serde_json::from_str(&output).expect("parse JSON output");

        assert_eq!(
            value["compatibility"]["profiles"],
            serde_json::json!(["generic", "codex"])
        );
        assert_eq!(
            profile_names(&value["compatibility"]["matrix"][0]["profiles"]),
            vec!["generic", "codex"]
        );
    }

    #[test]
    fn run_scan_all_cli_profile_selects_registry_order() {
        let workspace = CliTestWorkspace::new("cli-profiles-all");
        workspace.write_file("SKILL.md", valid_skill("cli-profiles-all"));
        workspace.write_file(
            "agent-audit.yaml",
            r#"
profiles:
  - generic
"#,
        );

        let output = run_scan_output(configured_profile_scan_command(
            &workspace,
            ReportFormat::Json,
            &["all"],
        ))
        .expect("all CLI profile should select registry order");
        let value: serde_json::Value = serde_json::from_str(&output).expect("parse JSON output");

        assert_eq!(
            value["compatibility"]["profiles"],
            serde_json::json!(HOST_PROFILES)
        );
        assert_eq!(
            profile_names(&value["compatibility"]["matrix"][0]["profiles"]),
            HOST_PROFILES.to_vec()
        );
    }

    #[test]
    fn run_scan_applies_explicit_config_suppressions() {
        let workspace = CliTestWorkspace::new("config-suppression");
        workspace.write_file(
            "SKILL.md",
            r#"---
description: CLI suppression fixture.
---

Read [missing](references/missing.md).
"#,
        );
        workspace.write_file(
            "agent-audit.yaml",
            r#"
ignore:
  - rule: SKILL001
    path: SKILL.md
    reason: Name omitted for CLI suppression regression.
"#,
        );

        let output = run_scan_output(configured_scan_command(
            &workspace,
            ReportFormat::Json,
            "agent-audit.yaml",
        ))
        .expect("explicit config should suppress matching finding");
        let value: serde_json::Value = serde_json::from_str(&output).expect("parse JSON output");

        assert_eq!(value["summary"]["finding_count"], 1);
        assert_eq!(value["summary"]["suppressed_finding_count"], 1);
        assert_eq!(value["findings"][0]["rule_id"], "SKILL010");
        assert_eq!(
            value["suppressed_findings"][0]["finding"]["rule_id"],
            "SKILL001"
        );
        assert_eq!(
            value["suppressed_findings"][0]["suppression"]["reason"],
            "Name omitted for CLI suppression regression."
        );
        assert_audit_path_metadata_present(&value["audit"]["config"]["path"]);
        assert!(value["audit"]["config"]["hash"]
            .as_str()
            .expect("config hash")
            .starts_with("fnv1a64:"));
    }

    #[test]
    fn run_scan_reports_missing_explicit_config_path() {
        let workspace = CliTestWorkspace::new("missing-config");
        workspace.write_file(
            "SKILL.md",
            r#"---
name: missing-config
description: Missing explicit config fixture.
---

# Missing Config
"#,
        );
        let config_path = workspace.root.join("missing.yaml");

        let error = run_scan_output(configured_scan_command_with_path(
            &workspace,
            config_path.clone(),
        ))
        .expect_err("missing config should fail before scan");
        let message = error.to_string();

        assert!(message.contains("failed to read config"));
        assert!(message.contains(&config_path.display().to_string()));
    }

    #[test]
    fn run_scan_reports_malformed_explicit_config_yaml() {
        let workspace = CliTestWorkspace::new("malformed-config");
        workspace.write_file(
            "SKILL.md",
            r#"---
name: malformed-config
description: Malformed explicit config fixture.
---

# Malformed Config
"#,
        );
        workspace.write_file("agent-audit.yaml", "profiles: [codex\n");
        let config_path = workspace.root.join("agent-audit.yaml");

        let error = run_scan_output(configured_scan_command_with_path(
            &workspace,
            config_path.clone(),
        ))
        .expect_err("malformed config should fail before scan");
        let message = error.to_string();

        assert!(message.contains("failed to parse config"));
        assert!(message.contains(&config_path.display().to_string()));
    }

    #[test]
    fn run_scan_reports_explicit_config_validation_error() {
        let workspace = CliTestWorkspace::new("invalid-config");
        workspace.write_file(
            "SKILL.md",
            r#"---
name: invalid-config
description: Invalid explicit config fixture.
---

# Invalid Config
"#,
        );
        workspace.write_file("agent-audit.yaml", "profiles:\n  - unknown-host\n");
        let config_path = workspace.root.join("agent-audit.yaml");

        let error = run_scan_output(configured_scan_command_with_path(
            &workspace,
            config_path.clone(),
        ))
        .expect_err("invalid config should fail before scan");
        let message = error.to_string();

        assert!(message.contains("invalid config"));
        assert!(message.contains(&config_path.display().to_string()));
        assert!(message.contains("unknown host profile `unknown-host`"));
    }

    #[test]
    fn run_scan_reports_invalid_config_fail_on_severity_with_lowercase_names() {
        let workspace = CliTestWorkspace::new("invalid-config-fail-on");
        workspace.write_file(
            "SKILL.md",
            r#"---
name: invalid-config-fail-on
description: Invalid config fail_on fixture.
---

# Invalid Config Fail On
"#,
        );
        workspace.write_file("agent-audit.yaml", "fail_on:\n  - LOW\n");
        let config_path = workspace.root.join("agent-audit.yaml");

        let error = run_scan_output(configured_scan_command_with_path(
            &workspace,
            config_path.clone(),
        ))
        .expect_err("invalid config fail_on severity should fail before scan");
        let message = error.to_string();

        assert!(message.contains("invalid config"));
        assert!(message.contains(&config_path.display().to_string()));
        assert!(message.contains("fail_on[0] uses unknown severity `LOW`"));
        assert!(message.contains("expected one of: info, low, medium, high, critical"));
    }

    #[test]
    fn run_scan_does_not_auto_discover_project_config() {
        let workspace = CliTestWorkspace::new("no-config-discovery");
        workspace.write_file(
            "SKILL.md",
            r#"---
name: no-config-discovery
description: No config discovery fixture.
---

# No Config Discovery
"#,
        );
        workspace.write_file(".agent-audit.yaml", "profiles: [codex\n");

        let output = run_scan_output(scan_command(&workspace, ReportFormat::Summary))
            .expect("implicit config discovery should not run");

        assert!(output.contains("Packages: 1\n"));
    }

    #[test]
    fn run_scan_default_does_not_emit_missing_supply_chain_metadata_findings() {
        let workspace = CliTestWorkspace::new("default-supply-chain-policy");
        workspace.write_file("SKILL.md", valid_skill("default-supply-chain-policy"));

        let output =
            run_scan_output(scan_command(&workspace, ReportFormat::Json)).expect("run JSON scan");
        let value: serde_json::Value = serde_json::from_str(&output).expect("parse JSON output");

        assert!(!has_finding(&value, "SUPPLY001"));
        assert!(!has_finding(&value, "SUPPLY002"));
        assert!(!has_finding(&value, "SUPPLY011"));
    }

    #[test]
    fn run_scan_supply_chain_flag_keeps_default_policy() {
        let workspace = CliTestWorkspace::new("supply-chain-default-policy");
        workspace.write_file("SKILL.md", valid_skill("supply-chain-default-policy"));

        let output = run_scan_output(ScanCommand {
            supply_chain: true,
            ..scan_command(&workspace, ReportFormat::Json)
        })
        .expect("supply-chain view flag should not enable strict policy");
        let value: serde_json::Value = serde_json::from_str(&output).expect("parse JSON output");

        assert!(value.get("supply_chain").is_some());
        assert!(!has_finding(&value, "SUPPLY011"));
    }

    #[test]
    fn run_scan_strict_supply_chain_requires_trust_manifest_and_license_evidence() {
        let workspace = CliTestWorkspace::new("strict-supply-chain-policy");
        workspace.write_file("SKILL.md", valid_skill("strict-supply-chain-policy"));

        let output = run_scan_output(ScanCommand {
            strict_supply_chain: true,
            ..scan_command(&workspace, ReportFormat::Json)
        })
        .expect("strict supply-chain scan should render findings without fail_on");
        let value: serde_json::Value = serde_json::from_str(&output).expect("parse JSON output");

        assert!(has_finding(&value, "SUPPLY001"));
        assert!(has_finding(&value, "SUPPLY002"));
        assert!(has_finding(&value, "SUPPLY011"));
    }

    #[test]
    fn run_scan_config_strict_supply_chain_policy_requires_metadata() {
        let workspace = CliTestWorkspace::new("config-strict-supply-chain-policy");
        workspace.write_file("SKILL.md", valid_skill("config-strict-supply-chain-policy"));
        workspace.write_file(
            "agent-audit.yaml",
            r#"
supply_chain:
  policy: strict
"#,
        );

        let output = run_scan_output(configured_scan_command(
            &workspace,
            ReportFormat::Json,
            "agent-audit.yaml",
        ))
        .expect("config strict supply-chain policy should render findings");
        let value: serde_json::Value = serde_json::from_str(&output).expect("parse JSON output");

        assert!(has_finding(&value, "SUPPLY002"));
        assert!(has_finding(&value, "SUPPLY011"));
    }

    #[test]
    fn run_scan_cli_strict_supply_chain_overrides_default_config_policy() {
        let workspace = CliTestWorkspace::new("cli-strict-supply-chain-policy");
        workspace.write_file("SKILL.md", valid_skill("cli-strict-supply-chain-policy"));
        workspace.write_file(
            "agent-audit.yaml",
            r#"
supply_chain:
  policy: default
"#,
        );

        let output = run_scan_output(ScanCommand {
            strict_supply_chain: true,
            ..configured_scan_command(&workspace, ReportFormat::Json, "agent-audit.yaml")
        })
        .expect("CLI strict supply-chain policy should override config default");
        let value: serde_json::Value = serde_json::from_str(&output).expect("parse JSON output");

        assert!(has_finding(&value, "SUPPLY011"));
    }

    #[test]
    fn run_scan_fail_on_low_matches_strict_supply_chain_findings_after_json_output() {
        let workspace = CliTestWorkspace::new("strict-supply-chain-fail-on");
        workspace.write_file("SKILL.md", valid_skill("strict-supply-chain-fail-on"));

        let (output, result) = run_scan_attempt(ScanCommand {
            fail_on: vec![Severity::Low],
            strict_supply_chain: true,
            ..scan_command(&workspace, ReportFormat::Json)
        });
        let error = result.expect_err("low fail_on should match strict supply-chain findings");
        let value: serde_json::Value =
            serde_json::from_str(&output).expect("JSON output should be written before fail_on");

        assert!(has_finding(&value, "SUPPLY001"));
        assert!(error
            .to_string()
            .contains("fail_on matched an unsuppressed finding severity"));
    }

    fn missing_name_skill() -> &'static str {
        r#"---
description: Missing name fail_on fixture.
---

This manifest intentionally starts with a paragraph so the scanner cannot derive a heading fallback name.
"#
    }

    fn scan_command(workspace: &CliTestWorkspace, format: ReportFormat) -> ScanCommand {
        scan_path_command(workspace.root.clone(), format)
    }

    fn scan_path_command(path: PathBuf, format: ReportFormat) -> ScanCommand {
        ScanCommand {
            path,
            format,
            mode: ReportMode::Default,
            config: None,
            fail_on: Vec::new(),
            output: None,
            open: false,
            profiles: Vec::new(),
            supply_chain: false,
            strict_supply_chain: false,
            corpus_name: None,
            corpus_entry_id: None,
            methodology_version: None,
            inclusion_tags: Vec::new(),
            repo_classification: None,
            scan_batch_id: None,
        }
    }

    fn parsed_scan_command<const N: usize>(args: [&str; N]) -> ScanCommand {
        match Cli::parse_from(args).command {
            Command::Scan(command) => command,
        }
    }

    fn configured_scan_command(
        workspace: &CliTestWorkspace,
        format: ReportFormat,
        config: &str,
    ) -> ScanCommand {
        ScanCommand {
            config: Some(workspace.root.join(config)),
            ..scan_command(workspace, format)
        }
    }

    fn configured_profile_scan_command(
        workspace: &CliTestWorkspace,
        format: ReportFormat,
        profiles: &[&str],
    ) -> ScanCommand {
        ScanCommand {
            profiles: profiles
                .iter()
                .map(|profile| (*profile).to_owned())
                .collect(),
            ..configured_scan_command(workspace, format, "agent-audit.yaml")
        }
    }

    fn configured_scan_command_with_path(
        workspace: &CliTestWorkspace,
        config: PathBuf,
    ) -> ScanCommand {
        ScanCommand {
            config: Some(config),
            ..scan_command(workspace, ReportFormat::Summary)
        }
    }

    fn configured_path_scan_command(
        path: PathBuf,
        format: ReportFormat,
        config: &str,
    ) -> ScanCommand {
        ScanCommand {
            config: Some(path.join(config)),
            ..scan_path_command(path, format)
        }
    }

    fn failing_scan_command(
        workspace: &CliTestWorkspace,
        format: ReportFormat,
        fail_on: Vec<Severity>,
    ) -> ScanCommand {
        ScanCommand {
            fail_on,
            ..scan_command(workspace, format)
        }
    }

    fn valid_skill(name: &str) -> String {
        format!(
            r#"---
name: {name}
description: Valid profile fixture.
---

# {name}
"#
        )
    }

    fn compatibility_unknown_frontmatter_skill() -> &'static str {
        r#"---
name: compatibility-fail-on
description: Compatibility fail-on fixture.
x-owner: platform-team
---

# Compatibility Fail On
"#
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

    fn test_finding(rule_id: &str, severity: Severity) -> SkillFinding {
        SkillFinding {
            rule_id: rule_id.to_owned(),
            fingerprint: String::new(),
            severity,
            confidence: agent_audit_core::FindingConfidence::Medium,
            category: FindingCategory::Security,
            title: "Privileged command".to_owned(),
            message: "The skill fixture uses privileged command examples.".to_owned(),
            location: FindingLocation {
                path: "SKILL.md".to_owned(),
                line: Some(7),
            },
            rationale: "Privileged commands increase review risk.".to_owned(),
            remediation: "Avoid privileged commands or document the required privilege boundary."
                .to_owned(),
            suppression: format!("Suppress `{rule_id}` only with a documented reason."),
        }
    }

    fn phase2_fail_on_fixture(name: &str) -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("..")
            .join("fixtures")
            .join("spec")
            .join("phase2")
            .join("fail-on")
            .join(name)
    }

    fn profile_names(value: &serde_json::Value) -> Vec<&str> {
        value
            .as_array()
            .expect("profile result array")
            .iter()
            .map(|profile| profile["profile"].as_str().expect("profile name"))
            .collect()
    }

    fn has_finding(value: &serde_json::Value, rule_id: &str) -> bool {
        value["findings"]
            .as_array()
            .expect("findings array")
            .iter()
            .any(|finding| finding["rule_id"] == rule_id)
    }

    fn assert_audit_path_metadata_present(value: &serde_json::Value) {
        let path = value.as_str().expect("audit path metadata string");
        assert!(!path.is_empty());
    }

    fn assert_platform_metadata_shape(value: &serde_json::Value) {
        let platform = value.as_object().expect("platform metadata object");
        for field in ["os", "arch", "family"] {
            assert!(
                platform
                    .get(field)
                    .and_then(serde_json::Value::as_str)
                    .is_some_and(|value| !value.is_empty()),
                "platform metadata should include non-empty {field}"
            );
        }
    }

    struct CliTestWorkspace {
        root: PathBuf,
    }

    impl CliTestWorkspace {
        fn new(name: &str) -> Self {
            let id = NEXT_WORKSPACE_ID.fetch_add(1, Ordering::Relaxed);
            let root = Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("..")
                .join("..")
                .join("target")
                .join("agent-audit-cli-tests")
                .join(format!("{name}-{}-{id}", std::process::id()));

            if root.exists() {
                fs::remove_dir_all(&root).expect("remove stale test workspace");
            }
            fs::create_dir_all(&root).expect("create test workspace");

            Self { root }
        }

        fn write_file(&self, relative_path: &str, content: impl AsRef<str>) {
            let path = self.root.join(relative_path);
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent).expect("create test file parent directory");
            }
            fs::write(path, content.as_ref()).expect("write test file");
        }
    }

    impl Drop for CliTestWorkspace {
        fn drop(&mut self) {
            if self.root.exists() {
                fs::remove_dir_all(&self.root).expect("remove test workspace");
            }
        }
    }
}
