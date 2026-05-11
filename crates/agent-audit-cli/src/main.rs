// SPDX-License-Identifier: Apache-2.0

use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use agent_audit_core::{
    parse_audit_config, parse_severity, report_matches_fail_on, scan_path, AuditConfig, AuditError,
    ScanOptions, ScanReport, Severity,
};
use agent_audit_report::{
    render_report, ReportFormat, UnsupportedReportFormat, SUPPORTED_REPORT_FORMATS_HELP,
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
        value_parser = parse_report_format,
        default_value = "summary",
        value_name = "FORMAT",
        help = SUPPORTED_REPORT_FORMATS_HELP
    )]
    format: ReportFormat,
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
    let config = command
        .config
        .as_deref()
        .map(load_explicit_config)
        .transpose()?;
    let fail_on = effective_fail_on(&command.fail_on, config.as_ref()).to_vec();

    let report = scan_path(
        &command.path,
        &ScanOptions {
            config,
            ..ScanOptions::default()
        },
    )?;
    write_report_and_apply_fail_on(&report, command.format, &fail_on, writer)
}

fn write_report_and_apply_fail_on(
    report: &ScanReport,
    format: ReportFormat,
    fail_on: &[Severity],
    writer: &mut impl Write,
) -> Result<()> {
    let rendered = render_report(report, format)?;

    writer.write_all(rendered.as_bytes())?;
    writer.flush()?;

    if report_matches_fail_on(report, fail_on) {
        return Err(anyhow!(
            "scan failed because fail_on matched an unsuppressed finding severity"
        ));
    }

    Ok(())
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

fn parse_fail_on_severity(value: &str) -> Result<Severity, String> {
    parse_severity(value).ok_or_else(|| {
        format!("unknown severity `{value}`; expected one of: info, low, medium, high, critical")
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use agent_audit_core::model::{CompatibilityMatrix, ScanSummary};
    use agent_audit_core::{
        FindingCategory, FindingLocation, SkillFinding, SuppressedFinding, SuppressionMatch,
    };
    use clap::CommandFactory;
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
    fn parses_default_scan_command() {
        let cli = Cli::parse_from(["agent-audit", "scan"]);

        match cli.command {
            Command::Scan(command) => {
                assert_eq!(command.path, PathBuf::from("."));
                assert_eq!(command.format, ReportFormat::Summary);
                assert_eq!(command.config, None);
                assert_eq!(command.fail_on, Vec::<Severity>::new());
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
            }
        }
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
        let cli = Cli::parse_from([
            "agent-audit",
            "scan",
            "fixtures/spec/basic",
            "--format",
            "json",
        ]);

        match cli.command {
            Command::Scan(command) => {
                assert_eq!(command.path, PathBuf::from("fixtures/spec/basic"));
                assert_eq!(command.format, ReportFormat::Json);
                assert_eq!(command.config, None);
                assert_eq!(command.fail_on, Vec::<Severity>::new());
            }
        }
    }

    #[test]
    fn parses_sarif_scan_format() {
        let cli = Cli::parse_from([
            "agent-audit",
            "scan",
            "fixtures/spec/basic",
            "--format",
            "sarif",
        ]);

        match cli.command {
            Command::Scan(command) => {
                assert_eq!(command.path, PathBuf::from("fixtures/spec/basic"));
                assert_eq!(command.format, ReportFormat::Sarif);
                assert_eq!(command.config, None);
                assert_eq!(command.fail_on, Vec::<Severity>::new());
            }
        }
    }

    #[test]
    fn parses_html_scan_format() {
        let cli = Cli::parse_from([
            "agent-audit",
            "scan",
            "fixtures/spec/basic",
            "--format",
            "html",
        ]);

        match cli.command {
            Command::Scan(command) => {
                assert_eq!(command.path, PathBuf::from("fixtures/spec/basic"));
                assert_eq!(command.format, ReportFormat::Html);
                assert_eq!(command.config, None);
                assert_eq!(command.fail_on, Vec::<Severity>::new());
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

        let output = run_scan_output(ScanCommand {
            path: workspace.root.clone(),
            format: ReportFormat::Summary,
            config: None,
            fail_on: Vec::new(),
        })
        .expect("run summary scan");

        assert!(output.starts_with("Agent Skill Auditor scan summary\n"));
        assert!(output.contains("Packages: 1\n"));
        assert!(output.contains("Findings: "));
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

        let output = run_scan_output(ScanCommand {
            path: workspace.root.clone(),
            format: ReportFormat::Json,
            config: None,
            fail_on: Vec::new(),
        })
        .expect("run JSON scan");

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

        let output = run_scan_output(ScanCommand {
            path: workspace.root.clone(),
            format: ReportFormat::Sarif,
            config: None,
            fail_on: Vec::new(),
        })
        .expect("run SARIF scan");

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

        let output = run_scan_output(ScanCommand {
            path: workspace.root.clone(),
            format: ReportFormat::Html,
            config: None,
            fail_on: Vec::new(),
        })
        .expect("run HTML scan");

        assert!(output.starts_with("<!doctype html>\n"));
        assert!(output.contains("<h1>Agent Skill Auditor Report</h1>"));
        assert!(output.contains("html-output"));
        assert!(output.ends_with('\n'));
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

        let output = run_scan_output(ScanCommand {
            path: workspace.root.clone(),
            format: ReportFormat::Summary,
            config: None,
            fail_on: Vec::new(),
        })
        .expect("malformed frontmatter should render report");

        assert!(output.starts_with("Agent Skill Auditor scan summary\n"));
        assert!(output.contains("Packages: 1\n"));
        assert!(output.contains("Invalid manifests: 1\n"));
        assert!(output.contains("SKILL041 [low/spec] SKILL.md:"));
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

        let output = run_scan_output(ScanCommand {
            path: workspace.root.clone(),
            format: ReportFormat::Summary,
            config: None,
            fail_on: Vec::new(),
        })
        .expect("run summary scan");

        assert!(output.contains("Finding details:\n"));
        assert!(output.contains("[low/spec]"));
        assert!(output.contains("SKILL.md:"));
        assert!(output.contains("The skill manifest does not declare a name."));
        assert!(output.ends_with('\n'));
    }

    #[test]
    fn run_scan_default_does_not_fail_on_low_findings() {
        let workspace = CliTestWorkspace::new("default-non-failing");
        workspace.write_file("SKILL.md", missing_name_skill());

        let output = run_scan_output(ScanCommand {
            path: workspace.root.clone(),
            format: ReportFormat::Summary,
            config: None,
            fail_on: Vec::new(),
        })
        .expect("default scan should render low findings without failing");

        assert!(output.contains("SKILL001 [low/spec] SKILL.md:"));
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

        let (output, result) = run_scan_attempt(ScanCommand {
            path: workspace.root.clone(),
            format: ReportFormat::Summary,
            config: Some(workspace.root.join("agent-audit.yaml")),
            fail_on: Vec::new(),
        });
        let error = result.expect_err("low fail_on should fail after rendering");

        assert!(output.starts_with("Agent Skill Auditor scan summary\n"));
        assert!(output.contains("SKILL001 [low/spec] SKILL.md:"));
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

        let (output, result) = run_scan_attempt(ScanCommand {
            path: workspace.root.clone(),
            format: ReportFormat::Summary,
            config: Some(workspace.root.join("agent-audit.yaml")),
            fail_on: Vec::new(),
        });
        let error = result.expect_err("multiple config fail_on values should match low finding");

        assert!(output.contains("SKILL001 [low/spec] SKILL.md:"));
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

        let output = run_scan_output(ScanCommand {
            path: workspace.root.clone(),
            format: ReportFormat::Summary,
            config: Some(workspace.root.join("agent-audit.yaml")),
            fail_on: Vec::new(),
        })
        .expect("high fail_on should not match low finding");

        assert!(output.contains("SKILL001 [low/spec] SKILL.md:"));
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

        let output = run_scan_output(ScanCommand {
            path: workspace.root.clone(),
            format: ReportFormat::Summary,
            config: Some(workspace.root.join("agent-audit.yaml")),
            fail_on: Vec::new(),
        })
        .expect("multiple config fail_on values should not match low finding");

        assert!(output.contains("SKILL001 [low/spec] SKILL.md:"));
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

        let output = run_scan_output(ScanCommand {
            path: workspace.root.clone(),
            format: ReportFormat::Json,
            config: Some(workspace.root.join("agent-audit.yaml")),
            fail_on: Vec::new(),
        })
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
            suppressed_findings: vec![SuppressedFinding {
                finding: test_finding("SEC005", Severity::High),
                suppression: SuppressionMatch {
                    matched_rule: "SEC005".to_owned(),
                    matched_path: "SKILL.md".to_owned(),
                    reason: "Accepted privileged setup fixture.".to_owned(),
                },
            }],
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

        let (output, result) = run_scan_attempt(ScanCommand {
            path: workspace.root.clone(),
            format: ReportFormat::Summary,
            config: None,
            fail_on: vec![Severity::Low],
        });

        result.expect_err("CLI fail_on low should fail without config");
        assert!(output.contains("SKILL001 [low/spec] SKILL.md:"));
    }

    #[test]
    fn run_scan_multiple_cli_fail_on_values_match_low_findings() {
        let workspace = CliTestWorkspace::new("cli-multiple-fail-low");
        workspace.write_file("SKILL.md", missing_name_skill());

        let (output, result) = run_scan_attempt(ScanCommand {
            path: workspace.root.clone(),
            format: ReportFormat::Summary,
            config: None,
            fail_on: vec![Severity::Medium, Severity::Low],
        });
        let error = result.expect_err("multiple CLI fail_on values should match low finding");

        assert!(output.contains("SKILL001 [low/spec] SKILL.md:"));
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

        let output = run_scan_output(ScanCommand {
            path: workspace.root.clone(),
            format: ReportFormat::Summary,
            config: Some(workspace.root.join("agent-audit.yaml")),
            fail_on: vec![Severity::High],
        })
        .expect("CLI fail_on high should override config fail_on low");

        assert!(output.contains("SKILL001 [low/spec] SKILL.md:"));
    }

    #[test]
    fn run_scan_phase2_fail_on_low_fixture_fails_after_output() {
        let fixture = phase2_fail_on_fixture("low-unsuppressed");

        let (output, result) = run_scan_attempt(ScanCommand {
            path: fixture.clone(),
            format: ReportFormat::Summary,
            config: Some(fixture.join("agent-audit.yaml")),
            fail_on: Vec::new(),
        });
        let error = result.expect_err("low fail_on fixture should fail");

        assert!(output.contains("SKILL001 [low/spec] SKILL.md:"));
        assert!(error
            .to_string()
            .contains("fail_on matched an unsuppressed finding severity"));
    }

    #[test]
    fn run_scan_phase2_suppressed_low_fixture_does_not_fail() {
        let fixture = phase2_fail_on_fixture("suppressed-low");

        let output = run_scan_output(ScanCommand {
            path: fixture.clone(),
            format: ReportFormat::Json,
            config: Some(fixture.join("agent-audit.yaml")),
            fail_on: Vec::new(),
        })
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

        let output = run_scan_output(ScanCommand {
            path: fixture.clone(),
            format: ReportFormat::Summary,
            config: Some(fixture.join("agent-audit.yaml")),
            fail_on: Vec::new(),
        })
        .expect("high threshold should not fail low findings");

        assert!(output.contains("SKILL001 [low/spec] SKILL.md:"));
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

        let output = run_scan_output(ScanCommand {
            path: workspace.root.clone(),
            format: ReportFormat::Summary,
            config: Some(workspace.root.join("agent-audit.yaml")),
            fail_on: Vec::new(),
        })
        .expect("valid config should load before scan");

        assert!(output.contains("Packages: 1\n"));
        assert!(output.ends_with('\n'));
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

        let output = run_scan_output(ScanCommand {
            path: workspace.root.clone(),
            format: ReportFormat::Json,
            config: Some(workspace.root.join("agent-audit.yaml")),
            fail_on: Vec::new(),
        })
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

        let error = run_scan_output(ScanCommand {
            path: workspace.root.clone(),
            format: ReportFormat::Summary,
            config: Some(config_path.clone()),
            fail_on: Vec::new(),
        })
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

        let error = run_scan_output(ScanCommand {
            path: workspace.root.clone(),
            format: ReportFormat::Summary,
            config: Some(config_path.clone()),
            fail_on: Vec::new(),
        })
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

        let error = run_scan_output(ScanCommand {
            path: workspace.root.clone(),
            format: ReportFormat::Summary,
            config: Some(config_path.clone()),
            fail_on: Vec::new(),
        })
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

        let error = run_scan_output(ScanCommand {
            path: workspace.root.clone(),
            format: ReportFormat::Summary,
            config: Some(config_path.clone()),
            fail_on: Vec::new(),
        })
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

        let output = run_scan_output(ScanCommand {
            path: workspace.root.clone(),
            format: ReportFormat::Summary,
            config: None,
            fail_on: Vec::new(),
        })
        .expect("implicit config discovery should not run");

        assert!(output.contains("Packages: 1\n"));
    }

    fn missing_name_skill() -> &'static str {
        r#"---
description: Missing name fail_on fixture.
---

This manifest intentionally starts with a paragraph so the scanner cannot derive a heading fallback name.
"#
    }

    fn test_finding(rule_id: &str, severity: Severity) -> SkillFinding {
        SkillFinding {
            rule_id: rule_id.to_owned(),
            severity,
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

        fn write_file(&self, relative_path: &str, content: &str) {
            let path = self.root.join(relative_path);
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent).expect("create test file parent directory");
            }
            fs::write(path, content).expect("write test file");
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
