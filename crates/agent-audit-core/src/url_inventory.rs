// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeMap;

use crate::model::{
    EvidenceConfidence, ExternalUrl, ExternalUrlKind, MarkdownCodeBlock, PackageManagerKind,
    RemoteDependency, RemoteDependencyKind, SkillManifest, SupplyChainInventory,
    SupplyChainSourceKind,
};

pub fn inventory_manifest_urls(
    manifest_path: &str,
    manifest: &SkillManifest,
    frontmatter_key_lines: &BTreeMap<String, usize>,
) -> SupplyChainInventory {
    let mut inventory = SupplyChainInventory::default();

    collect_frontmatter_urls(
        manifest_path,
        &manifest.frontmatter,
        frontmatter_key_lines,
        &mut inventory,
    );
    collect_markdown_link_urls(manifest_path, manifest, &mut inventory);
    collect_inline_code_urls(manifest_path, manifest, &mut inventory);
    collect_code_block_urls(manifest_path, &manifest.code_blocks, &mut inventory);
    dedup_url_inventory(&mut inventory);

    inventory
}

pub fn inventory_script_urls(path: &str, content: &str) -> SupplyChainInventory {
    let mut inventory = SupplyChainInventory::default();

    for (index, line) in content.lines().enumerate() {
        for raw_url in extract_urls(line) {
            push_url(
                &mut inventory,
                UrlEvidenceInput {
                    path,
                    line: Some(index + 1),
                    source: SupplyChainSourceKind::Script,
                    raw_url,
                },
            );
        }
    }
    dedup_url_inventory(&mut inventory);

    inventory
}

fn collect_frontmatter_urls(
    manifest_path: &str,
    frontmatter: &BTreeMap<String, serde_yaml::Value>,
    frontmatter_key_lines: &BTreeMap<String, usize>,
    inventory: &mut SupplyChainInventory,
) {
    for (key, value) in frontmatter {
        collect_yaml_scalar_urls(
            manifest_path,
            value,
            frontmatter_key_lines.get(key.as_str()).copied(),
            inventory,
        );
    }
}

fn collect_yaml_scalar_urls(
    manifest_path: &str,
    value: &serde_yaml::Value,
    line: Option<usize>,
    inventory: &mut SupplyChainInventory,
) {
    match value {
        serde_yaml::Value::String(text) => {
            for raw_url in extract_urls(text) {
                push_url(
                    inventory,
                    UrlEvidenceInput {
                        path: manifest_path,
                        line,
                        source: SupplyChainSourceKind::Frontmatter,
                        raw_url,
                    },
                );
            }
        }
        serde_yaml::Value::Sequence(values) => {
            for value in values {
                collect_yaml_scalar_urls(manifest_path, value, line, inventory);
            }
        }
        serde_yaml::Value::Mapping(mapping) => {
            let mut entries = mapping.iter().collect::<Vec<_>>();
            entries.sort_by(|(left_key, _), (right_key, _)| {
                yaml_key_sort_value(left_key).cmp(&yaml_key_sort_value(right_key))
            });
            for (_key, value) in entries {
                collect_yaml_scalar_urls(manifest_path, value, line, inventory);
            }
        }
        _ => {}
    }
}

fn yaml_key_sort_value(value: &serde_yaml::Value) -> String {
    match value {
        serde_yaml::Value::String(value) => value.clone(),
        _ => serde_yaml::to_string(value).unwrap_or_default(),
    }
}

fn collect_markdown_link_urls(
    manifest_path: &str,
    manifest: &SkillManifest,
    inventory: &mut SupplyChainInventory,
) {
    for reference in &manifest.links {
        for raw_url in extract_urls(&reference.target) {
            push_url(
                inventory,
                UrlEvidenceInput {
                    path: manifest_path,
                    line: reference.line,
                    source: SupplyChainSourceKind::MarkdownLink,
                    raw_url,
                },
            );
        }
    }
}

fn collect_inline_code_urls(
    manifest_path: &str,
    manifest: &SkillManifest,
    inventory: &mut SupplyChainInventory,
) {
    if !manifest.inline_code_locations.is_empty()
        && manifest.inline_code_locations.len() == manifest.inline_code.len()
    {
        for code in &manifest.inline_code_locations {
            for raw_url in extract_urls(&code.content) {
                push_url(
                    inventory,
                    UrlEvidenceInput {
                        path: manifest_path,
                        line: code.line,
                        source: SupplyChainSourceKind::InlineCode,
                        raw_url,
                    },
                );
            }
        }
        return;
    }

    for code in &manifest.inline_code {
        for raw_url in extract_urls(code) {
            push_url(
                inventory,
                UrlEvidenceInput {
                    path: manifest_path,
                    line: None,
                    source: SupplyChainSourceKind::InlineCode,
                    raw_url,
                },
            );
        }
    }
}

fn collect_code_block_urls(
    manifest_path: &str,
    blocks: &[MarkdownCodeBlock],
    inventory: &mut SupplyChainInventory,
) {
    for block in blocks {
        for raw_url in extract_urls(&block.content) {
            push_url(
                inventory,
                UrlEvidenceInput {
                    path: manifest_path,
                    line: block.line,
                    source: SupplyChainSourceKind::CodeBlock,
                    raw_url,
                },
            );
        }
    }
}

struct UrlEvidenceInput<'a> {
    path: &'a str,
    line: Option<usize>,
    source: SupplyChainSourceKind,
    raw_url: String,
}

fn push_url(inventory: &mut SupplyChainInventory, input: UrlEvidenceInput<'_>) {
    let normalized = normalize_url(&input.raw_url);
    if normalized.is_empty() {
        return;
    }

    let classification = classify_url(&normalized, input.source);
    inventory.external_urls.push(ExternalUrl {
        path: input.path.to_owned(),
        line: input.line,
        source: input.source,
        kind: classification.kind,
        normalized: normalized.clone(),
        raw: Some(input.raw_url),
        confidence: EvidenceConfidence::High,
        pinned: classification.pinned,
    });

    if let Some(dependency) = remote_dependency_for_url(
        input.path,
        input.line,
        input.source,
        &normalized,
        &classification,
    ) {
        inventory.remote_dependencies.push(dependency);
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct UrlClassification {
    kind: ExternalUrlKind,
    pinned: Option<bool>,
    github: Option<GithubUrl>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct GithubUrl {
    owner: String,
    repo: String,
    ref_name: String,
    artifact_path: String,
    release_asset: bool,
}

fn classify_url(url: &str, source: SupplyChainSourceKind) -> UrlClassification {
    if let Some(github) = github_release_asset(url) {
        return UrlClassification {
            kind: ExternalUrlKind::GithubReleaseAsset,
            pinned: Some(false),
            github: Some(github),
        };
    }
    if let Some(github) = github_raw_or_blob(url) {
        return UrlClassification {
            kind: ExternalUrlKind::GithubRaw,
            pinned: Some(is_full_commit_sha(&github.ref_name)),
            github: Some(github),
        };
    }

    let host = url_host(url).unwrap_or_default();
    let path = url_path(url);
    let kind = if is_localhost_host(&host) {
        ExternalUrlKind::Localhost
    } else if is_internal_host(&host) {
        ExternalUrlKind::Internal
    } else if is_package_registry_url(&host, path) {
        ExternalUrlKind::PackageRegistry
    } else if is_downloaded_artifact_path(path) {
        ExternalUrlKind::DownloadedArtifact
    } else if is_remote_script_path(path) {
        ExternalUrlKind::RemoteScript
    } else if source == SupplyChainSourceKind::MarkdownLink || looks_like_documentation(&host, path)
    {
        ExternalUrlKind::Documentation
    } else if !host.is_empty() {
        ExternalUrlKind::HttpEndpoint
    } else {
        ExternalUrlKind::Unknown
    };

    UrlClassification {
        kind,
        pinned: pinned_for_kind(kind, path),
        github: None,
    }
}

fn pinned_for_kind(kind: ExternalUrlKind, path: &str) -> Option<bool> {
    match kind {
        ExternalUrlKind::DownloadedArtifact | ExternalUrlKind::RemoteScript => Some(false),
        ExternalUrlKind::PackageRegistry => Some(package_registry_path_has_version(path)),
        _ => None,
    }
}

fn remote_dependency_for_url(
    path: &str,
    line: Option<usize>,
    source: SupplyChainSourceKind,
    url: &str,
    classification: &UrlClassification,
) -> Option<RemoteDependency> {
    match classification.kind {
        ExternalUrlKind::GithubRaw => github_raw_dependency(path, line, source, classification),
        ExternalUrlKind::GithubReleaseAsset => {
            github_release_dependency(path, line, source, classification)
        }
        ExternalUrlKind::DownloadedArtifact => download_dependency(path, line, source, url),
        ExternalUrlKind::RemoteScript => script_dependency(path, line, source, url),
        ExternalUrlKind::PackageRegistry => package_registry_dependency(path, line, source, url),
        _ => None,
    }
}

fn github_raw_dependency(
    path: &str,
    line: Option<usize>,
    source: SupplyChainSourceKind,
    classification: &UrlClassification,
) -> Option<RemoteDependency> {
    let github = classification.github.as_ref()?;
    if !is_remote_script_path(&github.artifact_path)
        && !is_downloaded_artifact_path(&github.artifact_path)
    {
        return None;
    }

    Some(RemoteDependency {
        path: path.to_owned(),
        line,
        source,
        kind: if is_remote_script_path(&github.artifact_path) {
            RemoteDependencyKind::Script
        } else {
            RemoteDependencyKind::Artifact
        },
        package_manager: None,
        name: Some(github.artifact_path.clone()),
        version: Some(github.ref_name.clone()),
        normalized: format!(
            "github-raw:{}/{}@{}",
            github.owner, github.repo, github.artifact_path
        ),
        raw: Some(format!(
            "raw.githubusercontent.com/{}/{}",
            github.owner, github.repo
        )),
        confidence: EvidenceConfidence::High,
        pinned: classification.pinned,
    })
}

fn github_release_dependency(
    path: &str,
    line: Option<usize>,
    source: SupplyChainSourceKind,
    classification: &UrlClassification,
) -> Option<RemoteDependency> {
    let github = classification.github.as_ref()?;
    Some(RemoteDependency {
        path: path.to_owned(),
        line,
        source,
        kind: RemoteDependencyKind::Artifact,
        package_manager: None,
        name: Some(github.artifact_path.clone()),
        version: Some(github.ref_name.clone()),
        normalized: format!(
            "github-release:{}/{}@{}:{}",
            github.owner, github.repo, github.ref_name, github.artifact_path
        ),
        raw: Some(github.artifact_path.clone()),
        confidence: EvidenceConfidence::High,
        pinned: Some(false),
    })
}

fn download_dependency(
    path: &str,
    line: Option<usize>,
    source: SupplyChainSourceKind,
    url: &str,
) -> Option<RemoteDependency> {
    let name = file_name(url_path(url))?;
    Some(RemoteDependency {
        path: path.to_owned(),
        line,
        source,
        kind: RemoteDependencyKind::Artifact,
        package_manager: None,
        name: Some(name.clone()),
        version: None,
        normalized: format!("download:{name}"),
        raw: Some(name),
        confidence: EvidenceConfidence::High,
        pinned: Some(false),
    })
}

fn script_dependency(
    path: &str,
    line: Option<usize>,
    source: SupplyChainSourceKind,
    url: &str,
) -> Option<RemoteDependency> {
    let name = file_name(url_path(url))?;
    Some(RemoteDependency {
        path: path.to_owned(),
        line,
        source,
        kind: RemoteDependencyKind::Script,
        package_manager: None,
        name: Some(name.clone()),
        version: None,
        normalized: format!("script:{name}"),
        raw: Some(name),
        confidence: EvidenceConfidence::High,
        pinned: Some(false),
    })
}

fn package_registry_dependency(
    path: &str,
    line: Option<usize>,
    source: SupplyChainSourceKind,
    url: &str,
) -> Option<RemoteDependency> {
    let host = url_host(url)?;
    let url_path = url_path(url);
    let package = parse_package_registry_dependency(&host, url_path)?;
    Some(RemoteDependency {
        path: path.to_owned(),
        line,
        source,
        kind: RemoteDependencyKind::Package,
        package_manager: Some(package.manager),
        name: Some(package.name.clone()),
        version: package.version.clone(),
        normalized: match package.version.as_deref() {
            Some(version) => format!("{}:{}@{}", package.ecosystem, package.name, version),
            None => format!("{}:{}", package.ecosystem, package.name),
        },
        raw: match package.version.as_deref() {
            Some(version) => Some(format!("{} {}", package.name, version)),
            None => Some(package.name),
        },
        confidence: EvidenceConfidence::High,
        pinned: Some(package.version.is_some()),
    })
}

struct PackageRegistryDependency {
    ecosystem: &'static str,
    manager: PackageManagerKind,
    name: String,
    version: Option<String>,
}

fn parse_package_registry_dependency(host: &str, path: &str) -> Option<PackageRegistryDependency> {
    let segments = path_segments(path);
    if host == "registry.npmjs.org" {
        return parse_npm_registry_tarball(&segments);
    }
    if host == "www.npmjs.com" || host == "npmjs.com" {
        let name = package_name_after_marker(&segments, "package")?;
        return Some(PackageRegistryDependency {
            ecosystem: "npm",
            manager: PackageManagerKind::Npm,
            name,
            version: None,
        });
    }
    if host == "pypi.org" {
        let name = package_name_after_marker(&segments, "project")?;
        return Some(PackageRegistryDependency {
            ecosystem: "pip",
            manager: PackageManagerKind::Pip,
            name,
            version: None,
        });
    }
    if host == "crates.io" {
        let name = package_name_after_marker(&segments, "crates")?;
        return Some(PackageRegistryDependency {
            ecosystem: "cargo",
            manager: PackageManagerKind::Cargo,
            name,
            version: None,
        });
    }
    None
}

fn parse_npm_registry_tarball(segments: &[String]) -> Option<PackageRegistryDependency> {
    if segments.len() < 3 || segments.get(1).map(String::as_str) != Some("-") {
        return None;
    }

    let name = segments[0].clone();
    let tarball = segments[2].strip_suffix(".tgz").unwrap_or(&segments[2]);
    let version = tarball
        .strip_prefix(&format!("{name}-"))
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned);

    Some(PackageRegistryDependency {
        ecosystem: "npm",
        manager: PackageManagerKind::Npm,
        name,
        version,
    })
}

fn package_name_after_marker(segments: &[String], marker: &str) -> Option<String> {
    let marker_index = segments.iter().position(|segment| segment == marker)?;
    segments.get(marker_index + 1).cloned()
}

fn extract_urls(text: &str) -> Vec<String> {
    let mut urls = Vec::new();
    let mut search_start = 0;

    while search_start < text.len() {
        let Some(relative_start) = find_next_url_start(&text[search_start..]) else {
            break;
        };
        let start = search_start + relative_start;
        let end = text[start..]
            .char_indices()
            .find_map(|(index, character)| is_url_terminator(character).then_some(start + index))
            .unwrap_or(text.len());
        let candidate = trim_url_token(&text[start..end]);
        if !candidate.is_empty() {
            urls.push(candidate.to_owned());
        }
        search_start = end.saturating_add(1);
    }

    urls.sort();
    urls.dedup();
    urls
}

fn find_next_url_start(text: &str) -> Option<usize> {
    match (text.find("https://"), text.find("http://")) {
        (Some(https), Some(http)) => Some(https.min(http)),
        (Some(https), None) => Some(https),
        (None, Some(http)) => Some(http),
        (None, None) => None,
    }
}

fn is_url_terminator(character: char) -> bool {
    character.is_whitespace() || matches!(character, '"' | '\'' | '`' | '<' | '>' | '\\')
}

fn trim_url_token(value: &str) -> &str {
    value
        .trim_matches(|character| matches!(character, '(' | '[' | '{'))
        .trim_end_matches([')', ']', '}', ',', '.', ';', ':'])
}

fn normalize_url(url: &str) -> String {
    let trimmed = trim_url_token(url.trim());
    let Some((scheme, rest)) = trimmed.split_once("://") else {
        return String::new();
    };
    if !scheme.eq_ignore_ascii_case("http") && !scheme.eq_ignore_ascii_case("https") {
        return String::new();
    }

    let (authority, suffix) = match rest.find(['/', '?', '#']) {
        Some(index) => (&rest[..index], &rest[index..]),
        None => (rest, ""),
    };
    if authority.is_empty() {
        return String::new();
    }

    format!(
        "{}://{}{}",
        scheme.to_ascii_lowercase(),
        authority.to_ascii_lowercase(),
        suffix
    )
}

fn url_host(url: &str) -> Option<String> {
    let rest = url.split_once("://")?.1;
    let authority = rest
        .split(['/', '?', '#'])
        .next()
        .unwrap_or_default()
        .trim_matches(['[', ']']);
    let host = authority
        .rsplit_once('@')
        .map_or(authority, |(_, host)| host)
        .split_once(':')
        .map_or(authority, |(host, _)| host);
    (!host.is_empty()).then(|| host.to_ascii_lowercase())
}

fn url_path(url: &str) -> &str {
    let Some(rest) = url.split_once("://").map(|(_, rest)| rest) else {
        return "";
    };
    let Some(path_start) = rest.find('/') else {
        return "";
    };
    let path_and_more = &rest[path_start..];
    path_and_more
        .split(['?', '#'])
        .next()
        .unwrap_or(path_and_more)
}

fn path_segments(path: &str) -> Vec<String> {
    path.trim_start_matches('/')
        .split('/')
        .filter(|segment| !segment.is_empty())
        .map(percent_decode_minimal)
        .collect()
}

fn percent_decode_minimal(value: &str) -> String {
    value
        .replace("%40", "@")
        .replace("%2f", "/")
        .replace("%2F", "/")
}

fn github_raw_or_blob(url: &str) -> Option<GithubUrl> {
    let host = url_host(url)?;
    let segments = path_segments(url_path(url));
    if host == "raw.githubusercontent.com" && segments.len() >= 4 {
        return Some(GithubUrl {
            owner: segments[0].clone(),
            repo: segments[1].clone(),
            ref_name: segments[2].clone(),
            artifact_path: segments[3..].join("/"),
            release_asset: false,
        });
    }
    if host == "github.com" && segments.len() >= 5 {
        let marker = segments.get(2).map(String::as_str)?;
        if marker == "blob" || marker == "raw" {
            return Some(GithubUrl {
                owner: segments[0].clone(),
                repo: segments[1].clone(),
                ref_name: segments[3].clone(),
                artifact_path: segments[4..].join("/"),
                release_asset: false,
            });
        }
    }
    None
}

fn github_release_asset(url: &str) -> Option<GithubUrl> {
    let host = url_host(url)?;
    let segments = path_segments(url_path(url));
    if host == "github.com"
        && segments.len() >= 6
        && segments.get(2).map(String::as_str) == Some("releases")
        && segments.get(3).map(String::as_str) == Some("download")
    {
        return Some(GithubUrl {
            owner: segments[0].clone(),
            repo: segments[1].clone(),
            ref_name: segments[4].clone(),
            artifact_path: segments[5..].join("/"),
            release_asset: true,
        });
    }
    None
}

fn is_full_commit_sha(value: &str) -> bool {
    value.len() == 40 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn is_localhost_host(host: &str) -> bool {
    host == "localhost" || host == "::1" || host.starts_with("127.") || host == "0.0.0.0"
}

fn is_internal_host(host: &str) -> bool {
    host.ends_with(".internal")
        || host.ends_with(".local")
        || host.starts_with("10.")
        || host.starts_with("192.168.")
        || private_172_host(host)
}

fn private_172_host(host: &str) -> bool {
    let Some(rest) = host.strip_prefix("172.") else {
        return false;
    };
    let Some(octet) = rest
        .split('.')
        .next()
        .and_then(|octet| octet.parse::<u8>().ok())
    else {
        return false;
    };
    (16..=31).contains(&octet)
}

fn is_package_registry_url(host: &str, path: &str) -> bool {
    matches!(
        host,
        "registry.npmjs.org" | "www.npmjs.com" | "npmjs.com" | "pypi.org" | "crates.io"
    ) || path.contains("/packages/")
}

fn is_remote_script_path(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    [
        ".sh", ".bash", ".zsh", ".fish", ".ps1", ".py", ".js", ".mjs", ".cjs", ".ts",
    ]
    .iter()
    .any(|extension| lower.ends_with(extension))
}

fn is_downloaded_artifact_path(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    [
        ".exe", ".msi", ".dmg", ".pkg", ".deb", ".rpm", ".zip", ".tar", ".tar.gz", ".tgz", ".jar",
        ".war", ".wasm", ".dll", ".so", ".dylib",
    ]
    .iter()
    .any(|extension| lower.ends_with(extension))
}

fn looks_like_documentation(host: &str, path: &str) -> bool {
    host.starts_with("docs.")
        || path.contains("/docs/")
        || path.contains("/documentation/")
        || path.ends_with("/readme")
        || path.ends_with("/readme.md")
}

fn package_registry_path_has_version(path: &str) -> bool {
    path.contains(".tgz")
        || path_segments(path)
            .iter()
            .any(|segment| looks_like_version(segment))
}

fn looks_like_version(value: &str) -> bool {
    let mut parts = value.trim_start_matches('v').split('.');
    let Some(first) = parts.next() else {
        return false;
    };
    !first.is_empty()
        && first.chars().all(|character| character.is_ascii_digit())
        && parts.any(|part| {
            !part.is_empty() && part.chars().any(|character| character.is_ascii_digit())
        })
}

fn file_name(path: &str) -> Option<String> {
    path.rsplit('/')
        .next()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
}

pub(crate) fn dedup_url_inventory(inventory: &mut SupplyChainInventory) {
    dedup_external_urls(&mut inventory.external_urls);
    dedup_remote_dependencies(&mut inventory.remote_dependencies);
    inventory.sort_deterministically();
}

fn dedup_external_urls(urls: &mut Vec<ExternalUrl>) {
    urls.sort_by(|left, right| {
        left.normalized
            .cmp(&right.normalized)
            .then_with(|| external_url_evidence_cmp(left, right))
    });
    urls.dedup_by(|left, right| left.normalized == right.normalized);
}

fn dedup_remote_dependencies(dependencies: &mut Vec<RemoteDependency>) {
    dependencies.sort_by(|left, right| {
        left.normalized
            .cmp(&right.normalized)
            .then_with(|| remote_dependency_evidence_cmp(left, right))
    });
    dependencies.dedup_by(|left, right| left.normalized == right.normalized);
}

fn external_url_evidence_cmp(left: &ExternalUrl, right: &ExternalUrl) -> std::cmp::Ordering {
    evidence_source_kind_cmp(
        (&left.path, left.line, left.source, left.kind),
        (&right.path, right.line, right.source, right.kind),
    )
    .then_with(|| left.raw.cmp(&right.raw))
    .then_with(|| left.confidence.cmp(&right.confidence))
    .then_with(|| left.pinned.cmp(&right.pinned))
}

fn remote_dependency_evidence_cmp(
    left: &RemoteDependency,
    right: &RemoteDependency,
) -> std::cmp::Ordering {
    evidence_source_kind_cmp(
        (&left.path, left.line, left.source, left.kind),
        (&right.path, right.line, right.source, right.kind),
    )
    .then_with(|| left.package_manager.cmp(&right.package_manager))
    .then_with(|| left.name.cmp(&right.name))
    .then_with(|| left.version.cmp(&right.version))
    .then_with(|| left.raw.cmp(&right.raw))
    .then_with(|| left.confidence.cmp(&right.confidence))
    .then_with(|| left.pinned.cmp(&right.pinned))
}

fn evidence_source_kind_cmp<K: Ord>(
    left: (&str, Option<usize>, SupplyChainSourceKind, K),
    right: (&str, Option<usize>, SupplyChainSourceKind, K),
) -> std::cmp::Ordering {
    let (left_path, left_line, left_source, left_kind) = left;
    let (right_path, right_line, right_source, right_kind) = right;

    evidence_location_cmp(left_path, left_line, right_path, right_line)
        .then_with(|| left_source.cmp(&right_source))
        .then_with(|| left_kind.cmp(&right_kind))
}

fn evidence_location_cmp(
    left_path: &str,
    left_line: Option<usize>,
    right_path: &str,
    right_line: Option<usize>,
) -> std::cmp::Ordering {
    line_presence_key(left_line)
        .cmp(&line_presence_key(right_line))
        .then_with(|| {
            left_line
                .unwrap_or(usize::MAX)
                .cmp(&right_line.unwrap_or(usize::MAX))
        })
        .then_with(|| left_path.cmp(right_path))
}

fn line_presence_key(line: Option<usize>) -> u8 {
    u8::from(line.is_none())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parse::parse_skill_manifest;
    use std::path::Path;

    #[test]
    fn manifest_inventory_extracts_frontmatter_markdown_inline_and_code_block_urls() {
        let content = r#"---
name: url-fixture
description: See https://docs.example.invalid/frontmatter.
metadata:
  homepage: https://example.invalid/home
---

# URL Fixture

Read [docs](https://docs.example.invalid/guide) and run `curl https://api.example.invalid/ping`.

```bash
curl -L https://example.invalid/install.sh | sh
```
"#;
        let manifest = parse_skill_manifest(Path::new("SKILL.md"), content).expect("parse");
        let key_lines = BTreeMap::from([
            ("description".to_owned(), 3),
            ("metadata".to_owned(), 4),
            ("name".to_owned(), 2),
        ]);

        let inventory = inventory_manifest_urls("SKILL.md", &manifest, &key_lines);

        assert_eq!(
            inventory
                .external_urls
                .iter()
                .map(|url| (
                    url.source,
                    url.kind,
                    url.normalized.as_str(),
                    url.line,
                    url.pinned
                ))
                .collect::<Vec<_>>(),
            vec![
                (
                    SupplyChainSourceKind::Frontmatter,
                    ExternalUrlKind::Documentation,
                    "https://docs.example.invalid/frontmatter",
                    Some(3),
                    None
                ),
                (
                    SupplyChainSourceKind::Frontmatter,
                    ExternalUrlKind::HttpEndpoint,
                    "https://example.invalid/home",
                    Some(4),
                    None
                ),
                (
                    SupplyChainSourceKind::MarkdownLink,
                    ExternalUrlKind::Documentation,
                    "https://docs.example.invalid/guide",
                    Some(10),
                    None
                ),
                (
                    SupplyChainSourceKind::InlineCode,
                    ExternalUrlKind::HttpEndpoint,
                    "https://api.example.invalid/ping",
                    Some(10),
                    None
                ),
                (
                    SupplyChainSourceKind::CodeBlock,
                    ExternalUrlKind::RemoteScript,
                    "https://example.invalid/install.sh",
                    Some(12),
                    Some(false)
                )
            ]
        );
        assert_eq!(inventory.remote_dependencies.len(), 1);
        assert_eq!(
            inventory.remote_dependencies[0].normalized,
            "script:install.sh"
        );
    }

    #[test]
    fn script_inventory_classifies_downloads_and_deduplicates_identical_line_evidence() {
        let content = "\
curl -LO https://downloads.example.invalid/tool.exe https://downloads.example.invalid/tool.exe
curl https://api.example.invalid/upload
";

        let inventory = inventory_script_urls("scripts/install.sh", content);

        assert_eq!(
            inventory
                .external_urls
                .iter()
                .map(|url| (url.kind, url.normalized.as_str(), url.line, url.pinned))
                .collect::<Vec<_>>(),
            vec![
                (
                    ExternalUrlKind::DownloadedArtifact,
                    "https://downloads.example.invalid/tool.exe",
                    Some(1),
                    Some(false)
                ),
                (
                    ExternalUrlKind::HttpEndpoint,
                    "https://api.example.invalid/upload",
                    Some(2),
                    None
                )
            ]
        );
        assert_eq!(
            inventory
                .remote_dependencies
                .iter()
                .map(|dependency| (
                    dependency.kind,
                    dependency.name.as_deref(),
                    dependency.normalized.as_str()
                ))
                .collect::<Vec<_>>(),
            vec![(
                RemoteDependencyKind::Artifact,
                Some("tool.exe"),
                "download:tool.exe"
            )]
        );
    }

    #[test]
    fn inventory_deduplicates_normalized_urls_across_line_evidence() {
        let content = "\
curl https://DOWNLOADS.example.invalid/tool.exe
curl https://downloads.example.invalid/tool.exe
";

        let inventory = inventory_script_urls("scripts/install.sh", content);

        assert_eq!(inventory.external_urls.len(), 1);
        assert_eq!(
            (
                inventory.external_urls[0].normalized.as_str(),
                inventory.external_urls[0].line,
            ),
            ("https://downloads.example.invalid/tool.exe", Some(1))
        );
        assert_eq!(inventory.remote_dependencies.len(), 1);
        assert_eq!(
            (
                inventory.remote_dependencies[0].normalized.as_str(),
                inventory.remote_dependencies[0].line,
            ),
            ("download:tool.exe", Some(1))
        );
    }

    #[test]
    fn github_raw_and_blob_urls_distinguish_full_commit_shas_from_mutable_refs() {
        let pinned =
            "https://raw.githubusercontent.com/example/skill/0123456789abcdef0123456789abcdef01234567/scripts/install.sh";
        let unpinned = "https://github.com/example/skill/blob/main/scripts/install.sh";

        let pinned_inventory = inventory_script_urls("scripts/install.sh", pinned);
        let unpinned_inventory = inventory_script_urls("scripts/install.sh", unpinned);

        assert_eq!(
            pinned_inventory.external_urls[0].kind,
            ExternalUrlKind::GithubRaw
        );
        assert_eq!(pinned_inventory.external_urls[0].pinned, Some(true));
        assert_eq!(
            pinned_inventory.remote_dependencies[0].version.as_deref(),
            Some("0123456789abcdef0123456789abcdef01234567")
        );
        assert_eq!(
            unpinned_inventory.external_urls[0].kind,
            ExternalUrlKind::GithubRaw
        );
        assert_eq!(unpinned_inventory.external_urls[0].pinned, Some(false));
        assert_eq!(
            unpinned_inventory.remote_dependencies[0].version.as_deref(),
            Some("main")
        );
    }

    #[test]
    fn package_registry_urls_create_package_remote_dependencies() {
        let inventory = inventory_script_urls(
            "scripts/install.sh",
            "curl https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz",
        );

        assert_eq!(
            inventory.external_urls[0].kind,
            ExternalUrlKind::PackageRegistry
        );
        assert_eq!(inventory.external_urls[0].pinned, Some(true));
        assert_eq!(
            inventory.remote_dependencies[0].package_manager,
            Some(PackageManagerKind::Npm)
        );
        assert_eq!(
            inventory.remote_dependencies[0].normalized,
            "npm:left-pad@1.3.0"
        );
        assert_eq!(inventory.remote_dependencies[0].pinned, Some(true));
    }
}
