// SPDX-License-Identifier: Apache-2.0

use std::path::Path;

use agent_audit_security::{AnalyzerConfidence, SecuritySignal, SecuritySignalKind};

use crate::error::{AuditError, AuditResult};
use crate::model::{
    EvidenceConfidence, LockfileEvidence, PackageManagerEvidence, PackageManagerKind,
    RemoteDependency, RemoteDependencyKind, SkillArtifactKind, SkillFileKind, SkillGraph,
    SupplyChainInventory, SupplyChainSourceKind,
};
use crate::path_utils::{collect_skill_package_files, display_path, filename};

pub fn inventory_package_files(
    scan_root: &Path,
    skill_root: &Path,
) -> AuditResult<SupplyChainInventory> {
    let mut inventory = SupplyChainInventory::default();
    for path in package_inventory_files(skill_root)? {
        inventory_package_file(scan_root, &path, &mut inventory)?;
    }

    inventory.sort_deterministically();
    Ok(inventory)
}

fn package_inventory_files(skill_root: &Path) -> AuditResult<Vec<std::path::PathBuf>> {
    let mut files = Vec::new();
    collect_skill_package_files(skill_root, skill_root, &mut files, &|path| {
        is_package_inventory_file(&filename(path))
    })?;
    files.sort();
    Ok(files)
}

fn inventory_package_file(
    scan_root: &Path,
    path: &Path,
    inventory: &mut SupplyChainInventory,
) -> AuditResult<()> {
    let filename = filename(path);
    let display = display_path(scan_root, path);

    inventory_lockfile(&filename, &display, inventory);
    inventory_manifest(path, &filename, &display, inventory)?;
    inventory_lockfile_urls(path, &filename, &display, inventory)?;

    Ok(())
}

fn inventory_lockfile(filename: &str, display: &str, inventory: &mut SupplyChainInventory) {
    let Some(manager) = lockfile_manager(filename) else {
        return;
    };

    inventory.lockfiles.push(LockfileEvidence {
        path: display.to_owned(),
        line: Some(1),
        source: SupplyChainSourceKind::Lockfile,
        manager,
        normalized: filename.to_owned(),
        raw: Some(filename.to_owned()),
        confidence: EvidenceConfidence::High,
    });
}

fn inventory_manifest(
    path: &Path,
    filename: &str,
    display: &str,
    inventory: &mut SupplyChainInventory,
) -> AuditResult<()> {
    let Some(manager) = manifest_manager(filename) else {
        return Ok(());
    };

    inventory.package_managers.push(package_manager_evidence(
        display,
        Some(1),
        SupplyChainSourceKind::PackageManifest,
        manager,
        Some(display.to_owned()),
        manager_label(manager),
        Some(filename.to_owned()),
    ));
    inventory
        .remote_dependencies
        .extend(package_manifest_dependencies(
            path, display, filename, manager,
        )?);

    Ok(())
}

fn inventory_lockfile_urls(
    path: &Path,
    filename: &str,
    display: &str,
    inventory: &mut SupplyChainInventory,
) -> AuditResult<()> {
    if !is_lockfile_with_urls(filename) {
        return Ok(());
    }

    let content = std::fs::read_to_string(path).map_err(|source| AuditError::Read {
        path: path.to_path_buf(),
        source,
    })?;
    let mut lockfile_url_inventory = crate::url_inventory::inventory_script_urls(display, &content);
    mark_lockfile_url_sources(display, &mut lockfile_url_inventory);
    inventory
        .external_urls
        .append(&mut lockfile_url_inventory.external_urls);
    inventory
        .remote_dependencies
        .append(&mut lockfile_url_inventory.remote_dependencies);

    Ok(())
}

fn mark_lockfile_url_sources(display: &str, inventory: &mut SupplyChainInventory) {
    for url in &mut inventory.external_urls {
        if url.path == display {
            url.source = SupplyChainSourceKind::Lockfile;
        }
    }
    for dependency in &mut inventory.remote_dependencies {
        if dependency.path == display {
            dependency.source = SupplyChainSourceKind::Lockfile;
        }
    }
}

pub fn inventory_package_installs_from_signals(signals: &[SecuritySignal]) -> SupplyChainInventory {
    let mut inventory = SupplyChainInventory::default();

    for signal in signals.iter().filter(|signal| {
        signal.kind == SecuritySignalKind::PackageInstallation
            && matches!(
                signal.confidence,
                AnalyzerConfidence::Medium | AnalyzerConfidence::High
            )
    }) {
        let Some(command) = InstallCommand::from_signal(signal) else {
            continue;
        };
        inventory.package_managers.push(package_manager_evidence(
            &signal.location.path,
            signal.location.line,
            SupplyChainSourceKind::Script,
            command.manager,
            None,
            manager_label(command.manager),
            Some(command.raw.clone()),
        ));
        inventory
            .remote_dependencies
            .extend(command.remote_dependencies(&signal.location.path, signal.location.line));
    }

    dedup_package_inventory(&mut inventory);
    inventory
}

pub fn inventory_package_installs_from_scripts(
    scan_root: &Path,
    skill_root: &Path,
    graph: &SkillGraph,
) -> AuditResult<SupplyChainInventory> {
    let mut inventory = SupplyChainInventory::default();

    for file in graph.files.iter().filter(|file| {
        file.kind == SkillFileKind::File && file.artifact == SkillArtifactKind::Scripts
    }) {
        let path = skill_root.join(&file.path);
        let display = display_path(scan_root, &path);
        let content = std::fs::read_to_string(&path).map_err(|source| AuditError::Read {
            path: path.clone(),
            source,
        })?;
        for (index, line) in content.lines().enumerate() {
            let Some(command) = InstallCommand::from_line(line) else {
                continue;
            };
            let line = Some(index + 1);
            inventory.package_managers.push(package_manager_evidence(
                &display,
                line,
                SupplyChainSourceKind::Script,
                command.manager,
                None,
                manager_label(command.manager),
                Some(command.raw.clone()),
            ));
            inventory
                .remote_dependencies
                .extend(command.remote_dependencies(&display, line));
        }
    }

    dedup_package_inventory(&mut inventory);
    Ok(inventory)
}

fn package_manifest_dependencies(
    path: &Path,
    display: &str,
    filename: &str,
    manager: PackageManagerKind,
) -> AuditResult<Vec<RemoteDependency>> {
    let content = std::fs::read_to_string(path).map_err(|source| AuditError::Read {
        path: path.to_path_buf(),
        source,
    })?;

    let dependencies = match filename {
        "package.json" => package_json_dependencies(display, &content),
        "requirements.txt" => requirements_dependencies(display, &content),
        "Cargo.toml" => cargo_toml_dependencies(display, &content),
        "go.mod" => go_mod_dependencies(display, &content),
        "composer.json" => composer_json_dependencies(display, &content),
        _ => Vec::new(),
    };

    Ok(dependencies
        .into_iter()
        .map(|dependency| dependency.into_remote_dependency(display, manager))
        .collect())
}

fn package_json_dependencies(path: &str, content: &str) -> Vec<ParsedDependency> {
    let Ok(serde_yaml::Value::Mapping(root)) = serde_yaml::from_str::<serde_yaml::Value>(content)
    else {
        return Vec::new();
    };
    let sections = [
        "dependencies",
        "devDependencies",
        "peerDependencies",
        "optionalDependencies",
    ];
    let mut dependencies = Vec::new();

    for section in sections {
        let Some(serde_yaml::Value::Mapping(mapping)) =
            root.get(serde_yaml::Value::String(section.to_owned()))
        else {
            continue;
        };
        for (name, version) in mapping {
            let Some(name) = name.as_str() else {
                continue;
            };
            let Some(version) = version.as_str() else {
                continue;
            };
            dependencies.push(manifest_dependency(path, content, name, version));
        }
    }

    dependencies.sort();
    dependencies
}

fn composer_json_dependencies(path: &str, content: &str) -> Vec<ParsedDependency> {
    let Ok(serde_yaml::Value::Mapping(root)) = serde_yaml::from_str::<serde_yaml::Value>(content)
    else {
        return Vec::new();
    };
    let mut dependencies = Vec::new();

    for section in ["require", "require-dev"] {
        let Some(serde_yaml::Value::Mapping(mapping)) =
            root.get(serde_yaml::Value::String(section.to_owned()))
        else {
            continue;
        };
        for (name, version) in mapping {
            let Some(name) = name.as_str() else {
                continue;
            };
            let Some(version) = version.as_str() else {
                continue;
            };
            if name == "php" || name.starts_with("ext-") {
                continue;
            }
            dependencies.push(manifest_dependency(path, content, name, version));
        }
    }

    dependencies.sort();
    dependencies
}

fn requirements_dependencies(_path: &str, content: &str) -> Vec<ParsedDependency> {
    content
        .lines()
        .enumerate()
        .filter_map(|(index, line)| {
            parse_requirement_line(line).map(|mut dependency| {
                dependency.line = Some(index + 1);
                dependency
            })
        })
        .collect()
}

fn parse_requirement_line(line: &str) -> Option<ParsedDependency> {
    let raw = line.split('#').next()?.trim();
    if raw.is_empty() || raw.starts_with('-') {
        return None;
    }

    let operator = ["===", "==", ">=", "<=", "~=", "!=", ">", "<"]
        .iter()
        .find(|operator| raw.contains(**operator));
    let (name, version, pinned) = match operator {
        Some(operator) => {
            let (name, version) = raw.split_once(*operator)?;
            let version = version.trim();
            let reported_version = if matches!(*operator, "==" | "===") {
                version.to_owned()
            } else {
                format!("{operator}{version}")
            };
            (
                normalize_python_name(name),
                Some(reported_version),
                matches!(*operator, "==" | "===") && version_is_pinned(version),
            )
        }
        None => (normalize_python_name(raw), None, false),
    };
    if name.is_empty() {
        return None;
    }

    Some(ParsedDependency {
        name,
        version,
        raw: raw.to_owned(),
        line: None,
        pinned,
    })
}

fn manifest_dependency(path: &str, content: &str, name: &str, version: &str) -> ParsedDependency {
    ParsedDependency {
        name: name.to_owned(),
        version: Some(version.to_owned()),
        raw: format!("{name} {version}"),
        line: dependency_line(path, content, name),
        pinned: version_is_pinned(version),
    }
}

fn cargo_toml_dependencies(_path: &str, content: &str) -> Vec<ParsedDependency> {
    let mut dependencies = Vec::new();
    let mut in_dependencies = false;

    for (index, line) in content.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.starts_with('[') && trimmed.ends_with(']') {
            in_dependencies = matches!(
                trimmed,
                "[dependencies]" | "[dev-dependencies]" | "[build-dependencies]"
            );
            continue;
        }
        if !in_dependencies || trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let Some((name, value)) = trimmed.split_once('=') else {
            continue;
        };
        let name = name.trim().trim_matches(['"', '\'']);
        let version = toml_dependency_version(value.trim());
        let pinned = version.as_deref().is_some_and(version_is_pinned);
        dependencies.push(ParsedDependency {
            name: name.to_owned(),
            version,
            raw: trimmed.trim_end_matches(',').to_owned(),
            line: Some(index + 1),
            pinned,
        });
    }

    dependencies.sort();
    dependencies
}

fn toml_dependency_version(value: &str) -> Option<String> {
    let value = value.trim().trim_end_matches(',');
    if let Some(version) = quoted_value(value) {
        return Some(version);
    }

    let version_key = "version";
    let version_index = value.find(version_key)?;
    let after_key = &value[version_index + version_key.len()..];
    let after_equals = after_key.split_once('=')?.1.trim();
    quoted_value(after_equals)
}

fn go_mod_dependencies(_path: &str, content: &str) -> Vec<ParsedDependency> {
    let mut dependencies = Vec::new();
    let mut in_require_block = false;

    for (index, line) in content.lines().enumerate() {
        let trimmed = line.split("//").next().unwrap_or_default().trim();
        if trimmed == "require (" {
            in_require_block = true;
            continue;
        }
        if in_require_block && trimmed == ")" {
            in_require_block = false;
            continue;
        }
        if trimmed.is_empty() {
            continue;
        }

        let fields = trimmed.split_whitespace().collect::<Vec<_>>();
        let dependency = if in_require_block && fields.len() >= 2 {
            Some((fields[0], fields[1]))
        } else if fields.len() >= 3 && fields[0] == "require" {
            Some((fields[1], fields[2]))
        } else {
            None
        };
        let Some((name, version)) = dependency else {
            continue;
        };
        dependencies.push(ParsedDependency {
            name: name.to_owned(),
            version: Some(version.to_owned()),
            raw: format!("{name} {version}"),
            line: Some(index + 1),
            pinned: go_version_is_pinned(version),
        });
    }

    dependencies.sort();
    dependencies
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct ParsedDependency {
    name: String,
    version: Option<String>,
    raw: String,
    line: Option<usize>,
    pinned: bool,
}

impl ParsedDependency {
    fn into_remote_dependency(self, path: &str, manager: PackageManagerKind) -> RemoteDependency {
        RemoteDependency {
            path: path.to_owned(),
            line: self.line,
            source: SupplyChainSourceKind::PackageManifest,
            kind: RemoteDependencyKind::Package,
            package_manager: Some(manager),
            normalized: normalized_package(
                manager_label(manager),
                &self.name,
                self.version.as_deref(),
            ),
            name: Some(self.name),
            version: self.version,
            raw: Some(self.raw),
            confidence: EvidenceConfidence::High,
            pinned: Some(self.pinned),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct InstallCommand {
    manager: PackageManagerKind,
    raw: String,
    packages: Vec<CommandPackage>,
}

impl InstallCommand {
    fn from_signal(signal: &SecuritySignal) -> Option<Self> {
        let target = signal
            .sink
            .as_ref()
            .and_then(|sink| sink.target.as_deref())
            .unwrap_or_default();
        Self::from_text(&signal.evidence).or_else(|| Self::from_text(target))
    }

    fn from_line(line: &str) -> Option<Self> {
        Self::from_text(line)
    }

    fn from_text(text: &str) -> Option<Self> {
        let tokens = shellish_tokens(text);
        let (index, manager, command_len) = install_command_start(&tokens)?;
        let packages = command_packages(manager, &tokens[index + command_len..]);
        Some(Self {
            manager,
            raw: text.trim().to_owned(),
            packages,
        })
    }

    fn remote_dependencies(&self, path: &str, line: Option<usize>) -> Vec<RemoteDependency> {
        let mut dependencies = self
            .packages
            .iter()
            .map(|package| RemoteDependency {
                path: path.to_owned(),
                line,
                source: SupplyChainSourceKind::Script,
                kind: RemoteDependencyKind::Package,
                package_manager: Some(self.manager),
                name: Some(package.name.clone()),
                version: package.version.clone(),
                normalized: normalized_package(
                    manager_label(self.manager),
                    &package.name,
                    package.version.as_deref(),
                ),
                raw: Some(package.raw.clone()),
                confidence: EvidenceConfidence::High,
                pinned: Some(package.pinned),
            })
            .collect::<Vec<_>>();
        dependencies.sort();
        dependencies
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CommandPackage {
    name: String,
    version: Option<String>,
    raw: String,
    pinned: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct InstallCommandStart {
    manager: PackageManagerKind,
    command_len: usize,
}

fn install_command_start(tokens: &[String]) -> Option<(usize, PackageManagerKind, usize)> {
    tokens.iter().enumerate().find_map(|(index, token)| {
        install_command_at(&shell_command_name(token), &tokens[index + 1..])
            .map(|start| (index, start.manager, start.command_len))
    })
}

fn install_command_at(token: &str, rest: &[String]) -> Option<InstallCommandStart> {
    javascript_install_command(token, rest)
        .or_else(|| pip_install_command(token, rest))
        .or_else(|| python_pip_install_command(token, rest))
        .or_else(|| simple_install_command(token, rest))
}

fn javascript_install_command(token: &str, rest: &[String]) -> Option<InstallCommandStart> {
    let manager = javascript_install_manager(token)?;
    install_subcommand(rest).map(|command_len| InstallCommandStart {
        manager,
        command_len,
    })
}

fn javascript_install_manager(token: &str) -> Option<PackageManagerKind> {
    match token {
        "npm" => Some(PackageManagerKind::Npm),
        "pnpm" => Some(PackageManagerKind::Pnpm),
        "yarn" => Some(PackageManagerKind::Yarn),
        _ => None,
    }
}

fn install_subcommand(rest: &[String]) -> Option<usize> {
    rest.first()
        .is_some_and(|next| matches!(next.as_str(), "install" | "i" | "add" | "ci"))
        .then_some(2)
}

fn pip_install_command(token: &str, rest: &[String]) -> Option<InstallCommandStart> {
    matches!(token, "pip" | "pip3")
        .then(|| install_literal_command(rest, PackageManagerKind::Pip))
        .flatten()
}

fn python_pip_install_command(token: &str, rest: &[String]) -> Option<InstallCommandStart> {
    if !matches!(token, "python" | "python3") || !is_python_pip_install(rest) {
        return None;
    }

    Some(InstallCommandStart {
        manager: PackageManagerKind::Pip,
        command_len: 4,
    })
}

fn is_python_pip_install(rest: &[String]) -> bool {
    rest.len() >= 3
        && rest[0] == "-m"
        && shell_command_name(&rest[1]) == "pip"
        && rest[2] == "install"
}

fn simple_install_command(token: &str, rest: &[String]) -> Option<InstallCommandStart> {
    let manager = match token {
        "cargo" => PackageManagerKind::Cargo,
        "gem" => PackageManagerKind::Gem,
        "go" => PackageManagerKind::Go,
        _ => return None,
    };
    install_literal_command(rest, manager)
}

fn install_literal_command(
    rest: &[String],
    manager: PackageManagerKind,
) -> Option<InstallCommandStart> {
    rest.first()
        .is_some_and(|next| next == "install")
        .then_some(InstallCommandStart {
            manager,
            command_len: 2,
        })
}

fn command_packages(manager: PackageManagerKind, tokens: &[String]) -> Vec<CommandPackage> {
    match manager {
        PackageManagerKind::Npm | PackageManagerKind::Yarn | PackageManagerKind::Pnpm => {
            javascript_command_packages(tokens)
        }
        PackageManagerKind::Pip => pip_command_packages(tokens),
        PackageManagerKind::Cargo => cargo_command_packages(tokens),
        PackageManagerKind::Gem => gem_command_packages(tokens),
        PackageManagerKind::Go => go_command_packages(tokens),
        _ => Vec::new(),
    }
}

fn javascript_command_packages(tokens: &[String]) -> Vec<CommandPackage> {
    tokens
        .iter()
        .filter(|token| !token.starts_with('-') && !matches!(token.as_str(), "install" | "add"))
        .filter_map(|token| javascript_package_spec(token))
        .collect()
}

fn javascript_package_spec(token: &str) -> Option<CommandPackage> {
    let token = strip_quotes(token);
    if token.is_empty() || token == "." || token.starts_with('.') {
        return None;
    }
    let (name, version) = javascript_name_version(token);
    Some(CommandPackage {
        name,
        version: version.clone(),
        raw: token.to_owned(),
        pinned: version.as_deref().is_some_and(version_is_pinned),
    })
}

fn javascript_name_version(token: &str) -> (String, Option<String>) {
    if let Some(scoped_name) = token.strip_prefix('@') {
        let Some(scope_end) = scoped_name.find('/') else {
            return (token.to_owned(), None);
        };
        let package_start = scope_end + 2;
        let rest = &token[package_start..];
        if let Some(version_at) = rest.rfind('@') {
            let version_index = package_start + version_at;
            return (
                token[..version_index].to_owned(),
                Some(token[version_index + 1..].to_owned()),
            );
        }
        return (token.to_owned(), None);
    }

    token
        .rsplit_once('@')
        .filter(|(name, version)| !name.is_empty() && !version.is_empty())
        .map_or_else(
            || (token.to_owned(), None),
            |(name, version)| (name.to_owned(), Some(version.to_owned())),
        )
}

fn pip_command_packages(tokens: &[String]) -> Vec<CommandPackage> {
    tokens
        .iter()
        .filter(|token| !token.starts_with('-'))
        .filter_map(|token| {
            let dependency = parse_requirement_line(token)?;
            Some(CommandPackage {
                name: dependency.name,
                version: dependency.version,
                raw: dependency.raw,
                pinned: dependency.pinned,
            })
        })
        .collect()
}

fn cargo_command_packages(tokens: &[String]) -> Vec<CommandPackage> {
    let mut packages = Vec::new();
    let mut version = None;
    for (index, token) in tokens.iter().enumerate() {
        if token == "--version" {
            version = tokens.get(index + 1).cloned();
        }
    }
    for token in tokens {
        if token.starts_with('-') || token == version.as_deref().unwrap_or_default() {
            continue;
        }
        packages.push(CommandPackage {
            name: strip_quotes(token).to_owned(),
            version: version.clone(),
            raw: match version.as_deref() {
                Some(version) => format!("{} --version {version}", strip_quotes(token)),
                None => strip_quotes(token).to_owned(),
            },
            pinned: version.as_deref().is_some_and(version_is_pinned),
        });
        break;
    }
    packages
}

fn gem_command_packages(tokens: &[String]) -> Vec<CommandPackage> {
    let mut packages = Vec::new();
    let mut version = None;
    for window in tokens.windows(2) {
        if matches!(window[0].as_str(), "-v" | "--version") {
            version = Some(window[1].clone());
        }
    }
    for token in tokens {
        if token.starts_with('-') || token == version.as_deref().unwrap_or_default() {
            continue;
        }
        packages.push(CommandPackage {
            name: strip_quotes(token).to_owned(),
            version: version.clone(),
            raw: match version.as_deref() {
                Some(version) => format!("{} -v {version}", strip_quotes(token)),
                None => strip_quotes(token).to_owned(),
            },
            pinned: version.as_deref().is_some_and(version_is_pinned),
        });
        break;
    }
    packages
}

fn go_command_packages(tokens: &[String]) -> Vec<CommandPackage> {
    tokens
        .iter()
        .filter(|token| !token.starts_with('-'))
        .map(|token| {
            let token = strip_quotes(token);
            let (name, version) = token.rsplit_once('@').map_or_else(
                || (token.to_owned(), None),
                |(name, version)| (name.to_owned(), Some(version.to_owned())),
            );
            CommandPackage {
                name,
                version: version.clone(),
                raw: token.to_owned(),
                pinned: version.as_deref().is_some_and(go_version_is_pinned),
            }
        })
        .collect()
}

fn package_manager_evidence(
    path: &str,
    line: Option<usize>,
    source: SupplyChainSourceKind,
    manager: PackageManagerKind,
    manifest_path: Option<String>,
    normalized: &str,
    raw: Option<String>,
) -> PackageManagerEvidence {
    PackageManagerEvidence {
        path: path.to_owned(),
        line,
        source,
        manager,
        manifest_path,
        normalized: normalized.to_owned(),
        raw,
        confidence: EvidenceConfidence::High,
    }
}

fn dedup_package_inventory(inventory: &mut SupplyChainInventory) {
    inventory.package_managers.sort();
    inventory.package_managers.dedup();
    inventory.remote_dependencies.sort();
    inventory.remote_dependencies.dedup();
    inventory.lockfiles.sort();
    inventory.lockfiles.dedup();
}

fn is_package_inventory_file(filename: &str) -> bool {
    lockfile_manager(filename).is_some()
        || manifest_manager(filename).is_some()
        || is_lockfile_with_urls(filename)
}

fn lockfile_manager(filename: &str) -> Option<PackageManagerKind> {
    match filename.to_ascii_lowercase().as_str() {
        "package-lock.json" | "npm-shrinkwrap.json" => Some(PackageManagerKind::Npm),
        "yarn.lock" => Some(PackageManagerKind::Yarn),
        "pnpm-lock.yaml" => Some(PackageManagerKind::Pnpm),
        "cargo.lock" => Some(PackageManagerKind::Cargo),
        "poetry.lock" => Some(PackageManagerKind::Poetry),
        "pipfile.lock" => Some(PackageManagerKind::Pip),
        "uv.lock" => Some(PackageManagerKind::Uv),
        "requirements.txt" => Some(PackageManagerKind::Pip),
        "gemfile.lock" => Some(PackageManagerKind::Gem),
        "go.sum" => Some(PackageManagerKind::Go),
        "composer.lock" => Some(PackageManagerKind::Composer),
        _ => None,
    }
}

fn manifest_manager(filename: &str) -> Option<PackageManagerKind> {
    match filename {
        "package.json" => Some(PackageManagerKind::Npm),
        "requirements.txt" => Some(PackageManagerKind::Pip),
        "Cargo.toml" => Some(PackageManagerKind::Cargo),
        "pyproject.toml" => Some(PackageManagerKind::Poetry),
        "Pipfile" => Some(PackageManagerKind::Pip),
        "Gemfile" => Some(PackageManagerKind::Gem),
        "go.mod" => Some(PackageManagerKind::Go),
        "composer.json" => Some(PackageManagerKind::Composer),
        _ => None,
    }
}

fn is_lockfile_with_urls(filename: &str) -> bool {
    matches!(filename, "package-lock.json" | "npm-shrinkwrap.json")
}

fn manager_label(manager: PackageManagerKind) -> &'static str {
    match manager {
        PackageManagerKind::Npm => "npm",
        PackageManagerKind::Yarn => "yarn",
        PackageManagerKind::Pnpm => "pnpm",
        PackageManagerKind::Pip => "pip",
        PackageManagerKind::Poetry => "poetry",
        PackageManagerKind::Uv => "uv",
        PackageManagerKind::Cargo => "cargo",
        PackageManagerKind::Go => "go",
        PackageManagerKind::Gem => "gem",
        PackageManagerKind::Composer => "composer",
        PackageManagerKind::Unknown => "unknown",
    }
}

fn normalized_package(manager: &str, name: &str, version: Option<&str>) -> String {
    match version {
        Some(version) if !version.is_empty() => format!("{manager}:{name}@{version}"),
        _ => format!("{manager}:{name}"),
    }
}

fn version_is_pinned(version: &str) -> bool {
    let version = version.trim().trim_matches(['"', '\'']);
    if version.is_empty() {
        return false;
    }
    let lower = version.to_ascii_lowercase();
    if lower == "latest"
        || lower == "*"
        || lower.starts_with(['^', '~', '>', '<', '='])
        || lower.contains('*')
        || lower.contains("x")
        || lower.contains("git")
        || lower.contains("branch")
    {
        return false;
    }

    exact_version(version)
}

fn go_version_is_pinned(version: &str) -> bool {
    let lower = version.trim().to_ascii_lowercase();
    lower.starts_with('v') && version_is_pinned(&lower[1..])
}

fn exact_version(version: &str) -> bool {
    let mut saw_digit = false;
    let mut saw_dot = false;
    for character in version.chars() {
        if character.is_ascii_digit() {
            saw_digit = true;
        } else if character == '.' {
            saw_dot = true;
        } else if matches!(character, '-' | '+') {
            break;
        } else {
            return false;
        }
    }
    saw_digit && saw_dot
}

fn shellish_tokens(text: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut current = String::new();
    let mut quote = None;

    for character in text.chars() {
        if quote.is_some_and(|quote| quote == character) {
            quote = None;
            continue;
        }
        if quote.is_none() && matches!(character, '"' | '\'') {
            quote = Some(character);
            continue;
        }
        if quote.is_none() && (character.is_whitespace() || matches!(character, ';' | '&' | '|')) {
            if !current.is_empty() {
                tokens.push(std::mem::take(&mut current));
            }
            continue;
        }
        current.push(character);
    }
    if !current.is_empty() {
        tokens.push(current);
    }

    tokens
}

fn shell_command_name(token: &str) -> String {
    token
        .rsplit('/')
        .next()
        .unwrap_or(token)
        .rsplit('\\')
        .next()
        .unwrap_or(token)
        .to_ascii_lowercase()
}

fn strip_quotes(value: &str) -> &str {
    value.trim().trim_matches(['"', '\''])
}

fn quoted_value(value: &str) -> Option<String> {
    let value = value.trim();
    let quote = value.chars().next()?;
    if !matches!(quote, '"' | '\'') {
        return None;
    }
    let rest = &value[quote.len_utf8()..];
    let end = rest.find(quote)?;
    Some(rest[..end].to_owned())
}

fn normalize_python_name(value: &str) -> String {
    value
        .split(['[', ' ', '\t'])
        .next()
        .unwrap_or_default()
        .trim()
        .to_owned()
}

fn dependency_line(_path: &str, content: &str, name: &str) -> Option<usize> {
    content
        .lines()
        .enumerate()
        .find(|(_, line)| line.contains(name))
        .map(|(index, _)| index + 1)
}

#[cfg(test)]
mod tests {
    use super::{install_command_start, shellish_tokens};

    use crate::model::PackageManagerKind;
    use crate::scan::{scan_path, ScanOptions};
    use crate::test_support::TestWorkspace;

    #[test]
    fn detects_common_lockfiles_per_skill_directory() {
        let workspace = TestWorkspace::new("package-inventory-lockfiles");
        workspace.write_file("SKILL.md", "# Root\n\nUseful skill.\n");
        for filename in [
            "package-lock.json",
            "npm-shrinkwrap.json",
            "yarn.lock",
            "pnpm-lock.yaml",
            "Cargo.lock",
            "Poetry.lock",
            "Pipfile.lock",
            "uv.lock",
            "requirements.txt",
            "Gemfile.lock",
            "go.sum",
            "composer.lock",
        ] {
            workspace.write_file(filename, "{}\n");
        }
        workspace.write_file("lowercase-poetry/poetry.lock", "{}\n");

        let report = scan_path(workspace.root(), &ScanOptions::default()).expect("scan path");

        assert_eq!(
            report
                .supply_chain
                .lockfiles
                .iter()
                .map(|lockfile| lockfile.path.as_str())
                .collect::<Vec<_>>(),
            vec![
                "Cargo.lock",
                "Gemfile.lock",
                "Pipfile.lock",
                "Poetry.lock",
                "composer.lock",
                "go.sum",
                "lowercase-poetry/poetry.lock",
                "npm-shrinkwrap.json",
                "package-lock.json",
                "pnpm-lock.yaml",
                "requirements.txt",
                "uv.lock",
                "yarn.lock",
            ]
        );
    }

    #[test]
    fn inventories_manifest_and_install_package_versions() {
        let workspace = TestWorkspace::new("package-inventory-versions");
        workspace.write_file("SKILL.md", "# Packages\n\nUseful skill.\n");
        workspace.write_file(
            "package.json",
            r#"{"dependencies":{"exact":"1.2.3","range":"^1.2.3","floating":"latest"}}"#,
        );
        workspace.write_file("requirements.txt", "requests==2.32.0\nclick>=8\npytest\n");
        workspace.write_file(
            "Cargo.toml",
            "[dependencies]\nripgrep = \"14.1.0\"\nregex = \"^1.10\"\n",
        );
        workspace.write_file(
            "scripts/install.sh",
            "#!/usr/bin/env sh\ncargo install fd-find --version 10.1.0\ngo install golang.org/x/tools/cmd/stringer@latest\n",
        );

        let report = scan_path(workspace.root(), &ScanOptions::default()).expect("scan path");

        assert_eq!(
            report
                .supply_chain
                .remote_dependencies
                .iter()
                .map(|dependency| (
                    dependency.normalized.as_str(),
                    dependency.pinned,
                    dependency.line
                ))
                .collect::<Vec<_>>(),
            vec![
                ("cargo:ripgrep@14.1.0", Some(true), Some(2)),
                ("cargo:regex@^1.10", Some(false), Some(3)),
                ("npm:exact@1.2.3", Some(true), Some(1)),
                ("npm:floating@latest", Some(false), Some(1)),
                ("npm:range@^1.2.3", Some(false), Some(1)),
                ("pip:requests@2.32.0", Some(true), Some(1)),
                ("pip:click@>=8", Some(false), Some(2)),
                ("pip:pytest", Some(false), Some(3)),
                ("cargo:fd-find@10.1.0", Some(true), Some(2)),
                (
                    "go:golang.org/x/tools/cmd/stringer@latest",
                    Some(false),
                    Some(3)
                ),
            ]
        );
    }

    #[test]
    fn detects_install_command_start_variants() {
        let cases = [
            (
                "sudo npm install left-pad",
                Some((1, PackageManagerKind::Npm, 2)),
            ),
            ("pnpm add zod", Some((0, PackageManagerKind::Pnpm, 2))),
            ("yarn ci", Some((0, PackageManagerKind::Yarn, 2))),
            (
                "pip3 install requests",
                Some((0, PackageManagerKind::Pip, 2)),
            ),
            (
                "python -m pip install requests",
                Some((0, PackageManagerKind::Pip, 4)),
            ),
            (
                "/usr/bin/cargo install ripgrep",
                Some((0, PackageManagerKind::Cargo, 2)),
            ),
            ("gem install rails", Some((0, PackageManagerKind::Gem, 2))),
            (
                "go install golang.org/x/tools/cmd/stringer@latest",
                Some((0, PackageManagerKind::Go, 2)),
            ),
            ("npm run install", None),
        ];

        for (line, expected) in cases {
            assert_eq!(
                install_command_start(&shellish_tokens(line)),
                expected,
                "{line}"
            );
        }
    }

    #[test]
    fn lockfile_inventory_skips_nested_skill_directories() {
        let workspace = TestWorkspace::new("package-inventory-nested-skills");
        workspace.write_file("SKILL.md", "# Parent\n\nUseful parent.\n");
        workspace.write_file("package-lock.json", "{}\n");
        workspace.write_file("child/SKILL.md", "# Child\n\nUseful child.\n");
        workspace.write_file("child/pnpm-lock.yaml", "{}\n");

        let report = scan_path(workspace.root(), &ScanOptions::default()).expect("scan path");

        assert_eq!(
            report
                .supply_chain
                .lockfiles
                .iter()
                .map(|lockfile| lockfile.path.as_str())
                .collect::<Vec<_>>(),
            vec!["child/pnpm-lock.yaml", "package-lock.json"]
        );
    }
}
