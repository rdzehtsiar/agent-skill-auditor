// SPDX-License-Identifier: Apache-2.0

use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::Command as ProcessCommand;

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

    let config = command
        .config
        .as_deref()
        .map(load_explicit_config)
        .transpose()?;
    let _supply_chain_requested = command.supply_chain;
    let fail_on = effective_fail_on(&command.fail_on, config.as_ref()).to_vec();
    let config = effective_config(config, &command.profiles, command.strict_supply_chain);

    let report = scan_path(
        &command.path,
        &ScanOptions {
            config,
            ..ScanOptions::default()
        },
    )?;
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

fn load_explicit_config(config_path: &Path) -> Result<AuditConfig> {
    let content = fs::read_to_string(config_path)
        .with_context(|| format!("failed to read config {}", config_path.display()))?;

    parse_audit_config(&content).map_err(|error| config_error_with_path(config_path, error))
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
        assert!(message.contains("supported: summary, json, sarif, html"));
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
        assert!(output.contains("html-output"));
        assert!(output.ends_with('\n'));
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
        assert!(message.contains(&workspace.root.display().to_string()));
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
            packages: Vec::new(),
            summary: ScanSummary {
                package_count: 0,
                finding_count: 0,
                suppressed_finding_count: 1,
                invalid_manifest_count: 0,
                broken_reference_count: 0,
            },
            findings: Vec::new(),
            finding_groups: Vec::new(),
            suppressed_findings: vec![SuppressedFinding {
                finding: test_finding("SEC005", Severity::High),
                suppression: SuppressionMatch {
                    matched_rule: "SEC005".to_owned(),
                    matched_path: "SKILL.md".to_owned(),
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
            configured_scan_command(&workspace, ReportFormat::Summary, "agent-audit.yaml");
        command.fail_on = vec![Severity::High];
        let output =
            run_scan_output(command).expect("CLI fail_on high should override config fail_on low");

        assert!(output.contains("SKILL001 [low/high/spec] x1 packages=1"));
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
