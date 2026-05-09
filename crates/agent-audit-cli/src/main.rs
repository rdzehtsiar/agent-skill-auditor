// SPDX-License-Identifier: Apache-2.0

use std::path::PathBuf;

use agent_audit_core::{scan_path, ScanOptions};
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
    }

    Ok(())
}
