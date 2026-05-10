// SPDX-License-Identifier: Apache-2.0

use std::path::PathBuf;

use agent_audit_core::{scan_path, ScanOptions};
use agent_audit_report::{render_html, render_sarif};
use anyhow::Result;
use clap::{Parser, ValueEnum};

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
    #[arg(long, value_enum, default_value_t = OutputFormat::Summary)]
    format: OutputFormat,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum OutputFormat {
    Summary,
    Json,
    Sarif,
    Html,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Command::Scan(command) => run_scan(command),
    }
}

fn run_scan(command: ScanCommand) -> Result<()> {
    let report = scan_path(&command.path, &ScanOptions::default())?;

    match command.format {
        OutputFormat::Summary => {
            println!("Agent Skill Auditor scan summary");
            println!("Packages: {}", report.summary.package_count);
            println!("Findings: {}", report.summary.finding_count);
            println!(
                "Invalid manifests: {}",
                report.summary.invalid_manifest_count
            );
            println!(
                "Broken references: {}",
                report.summary.broken_reference_count
            );

            for finding in &report.findings {
                println!(
                    "{} {:?} {}: {}",
                    finding.rule_id, finding.severity, finding.location.path, finding.message
                );
            }
        }
        OutputFormat::Json => {
            println!("{}", serde_json::to_string_pretty(&report)?);
        }
        OutputFormat::Sarif => {
            println!("{}", render_sarif(&report)?);
        }
        OutputFormat::Html => {
            println!("{}", render_html(&report));
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::Path;
    use std::sync::atomic::{AtomicUsize, Ordering};

    static NEXT_WORKSPACE_ID: AtomicUsize = AtomicUsize::new(0);

    #[test]
    fn parses_default_scan_command() {
        let cli = Cli::parse_from(["agent-audit", "scan"]);

        match cli.command {
            Command::Scan(command) => {
                assert_eq!(command.path, PathBuf::from("."));
                assert!(matches!(command.format, OutputFormat::Summary));
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
                assert!(matches!(command.format, OutputFormat::Json));
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
                assert!(matches!(command.format, OutputFormat::Sarif));
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
                assert!(matches!(command.format, OutputFormat::Html));
            }
        }
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

        let result = run_scan(ScanCommand {
            path: workspace.root.clone(),
            format: OutputFormat::Summary,
        });

        assert!(result.is_ok());
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

        let result = run_scan(ScanCommand {
            path: workspace.root.clone(),
            format: OutputFormat::Json,
        });

        assert!(result.is_ok());
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

        let result = run_scan(ScanCommand {
            path: workspace.root.clone(),
            format: OutputFormat::Sarif,
        });

        assert!(result.is_ok());
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

        let result = run_scan(ScanCommand {
            path: workspace.root.clone(),
            format: OutputFormat::Html,
        });

        assert!(result.is_ok());
    }

    #[test]
    fn run_scan_returns_manifest_parse_errors() {
        let workspace = CliTestWorkspace::new("parse-error");
        workspace.write_file(
            "SKILL.md",
            r#"---
name: [unterminated
---

# Malformed
"#,
        );

        let result = run_scan(ScanCommand {
            path: workspace.root.clone(),
            format: OutputFormat::Summary,
        });

        assert!(result.is_err());
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
