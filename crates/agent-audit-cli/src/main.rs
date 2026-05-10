// SPDX-License-Identifier: Apache-2.0

use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use agent_audit_core::{parse_audit_config, scan_path, AuditError, ScanOptions};
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
    if let Some(config_path) = &command.config {
        load_explicit_config(config_path)?;
    }

    let report = scan_path(&command.path, &ScanOptions::default())?;
    let rendered = render_report(&report, command.format)?;

    writer.write_all(rendered.as_bytes())?;

    Ok(())
}

fn load_explicit_config(config_path: &Path) -> Result<()> {
    let content = fs::read_to_string(config_path)
        .with_context(|| format!("failed to read config {}", config_path.display()))?;

    parse_audit_config(&content).map_err(|error| config_error_with_path(config_path, error))?;

    Ok(())
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

#[cfg(test)]
mod tests {
    use super::*;
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
    fn parses_default_scan_command() {
        let cli = Cli::parse_from(["agent-audit", "scan"]);

        match cli.command {
            Command::Scan(command) => {
                assert_eq!(command.path, PathBuf::from("."));
                assert_eq!(command.format, ReportFormat::Summary);
                assert_eq!(command.config, None);
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
            }
        }
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
        let mut output = Vec::new();

        run_scan_with_writer(command, &mut output)?;

        Ok(String::from_utf8(output).expect("scan output should be UTF-8"))
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
        })
        .expect("run summary scan");

        assert!(output.contains("Finding details:\n"));
        assert!(output.contains("[low/spec]"));
        assert!(output.contains("SKILL.md:"));
        assert!(output.contains("The skill manifest does not declare a name."));
        assert!(output.ends_with('\n'));
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
        })
        .expect("valid config should load before scan");

        assert!(output.contains("Packages: 1\n"));
        assert!(output.ends_with('\n'));
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
        })
        .expect_err("invalid config should fail before scan");
        let message = error.to_string();

        assert!(message.contains("invalid config"));
        assert!(message.contains(&config_path.display().to_string()));
        assert!(message.contains("unknown host profile `unknown-host`"));
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
        })
        .expect("implicit config discovery should not run");

        assert!(output.contains("Packages: 1\n"));
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
