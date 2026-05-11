// SPDX-License-Identifier: Apache-2.0

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

pub const INITIAL_SECURITY_RULE_IDS: &[&str] = &[
    "SEC001", "SEC002", "SEC003", "SEC004", "SEC005", "SEC006", "SEC007", "SEC008", "SEC009",
    "SEC010", "SEC011", "SEC012",
];

#[derive(Debug, Clone, Default, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct SecurityScan {
    pub artifacts: Vec<SecurityArtifact>,
    pub signals: Vec<SecuritySignal>,
}

impl SecurityScan {
    pub fn is_empty(&self) -> bool {
        self.artifacts.is_empty() && self.signals.is_empty()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct SecurityArtifact {
    pub path: String,
    pub kind: SecurityArtifactKind,
    pub language: SecurityLanguage,
    pub size_bytes: u64,
    pub executable: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SecurityArtifactKind {
    Manifest,
    Script,
    Reference,
    Asset,
    Config,
    Other,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SecurityLanguage {
    Shell,
    Binary,
    #[serde(rename = "javascript")]
    JavaScript,
    Json,
    Ruby,
    Go,
    Rust,
    Python,
    #[serde(rename = "typescript")]
    TypeScript,
    Unknown,
    Yaml,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct SecurityArtifactClassification {
    pub path: String,
    pub language: SecurityLanguage,
    pub method: SecurityArtifactClassificationMethod,
    pub signals: Vec<SecurityArtifactClassificationSignal>,
    pub executable: bool,
    pub text_parsing_allowed: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SecurityArtifactClassificationMethod {
    BinaryContent,
    Shebang,
    Extension,
    ContentSniff,
    ExecutableContent,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SecurityArtifactClassificationSignal {
    BinaryContent,
    Shebang,
    Extension,
    ContentSniff,
    ExecutableBit,
}

pub fn classify_security_artifact(
    path: &str,
    content_prefix: &[u8],
    executable: bool,
) -> Option<SecurityArtifactClassification> {
    let normalized_path = normalize_scan_relative_path(path)?;
    Some(classify_normalized_security_artifact(
        normalized_path,
        content_prefix,
        executable,
    ))
}

fn classify_normalized_security_artifact(
    path: String,
    content_prefix: &[u8],
    executable: bool,
) -> SecurityArtifactClassification {
    let executable_signal =
        executable.then_some(SecurityArtifactClassificationSignal::ExecutableBit);

    // Classification precedence is intentionally conservative and deterministic:
    // binary content prevents every text classifier, known shebangs outrank file
    // extensions, extensions outrank content sniffing, and the executable bit can
    // only promote extensionless shell-like text when shell syntax is also present.
    if is_binary_content(content_prefix) {
        return SecurityArtifactClassification {
            path,
            language: SecurityLanguage::Binary,
            method: SecurityArtifactClassificationMethod::BinaryContent,
            signals: append_optional_signal(
                vec![SecurityArtifactClassificationSignal::BinaryContent],
                executable_signal,
            ),
            executable,
            text_parsing_allowed: false,
        };
    }

    if let Some(language) = shebang_language(content_prefix) {
        return SecurityArtifactClassification {
            path,
            language,
            method: SecurityArtifactClassificationMethod::Shebang,
            signals: append_optional_signal(
                vec![SecurityArtifactClassificationSignal::Shebang],
                executable_signal,
            ),
            executable,
            text_parsing_allowed: true,
        };
    }

    if let Some(language) = extension_language(&path) {
        return SecurityArtifactClassification {
            path,
            language,
            method: SecurityArtifactClassificationMethod::Extension,
            signals: append_optional_signal(
                vec![SecurityArtifactClassificationSignal::Extension],
                executable_signal,
            ),
            executable,
            text_parsing_allowed: true,
        };
    }

    if let Some(language) = sniff_content_language(content_prefix, executable) {
        let method = if language == SecurityLanguage::Shell && executable {
            SecurityArtifactClassificationMethod::ExecutableContent
        } else {
            SecurityArtifactClassificationMethod::ContentSniff
        };
        return SecurityArtifactClassification {
            path,
            language,
            method,
            signals: append_optional_signal(
                vec![SecurityArtifactClassificationSignal::ContentSniff],
                executable_signal,
            ),
            executable,
            text_parsing_allowed: true,
        };
    }

    SecurityArtifactClassification {
        path,
        language: SecurityLanguage::Unknown,
        method: SecurityArtifactClassificationMethod::Unknown,
        signals: executable_signal.into_iter().collect(),
        executable,
        text_parsing_allowed: true,
    }
}

fn append_optional_signal(
    mut signals: Vec<SecurityArtifactClassificationSignal>,
    signal: Option<SecurityArtifactClassificationSignal>,
) -> Vec<SecurityArtifactClassificationSignal> {
    if let Some(signal) = signal {
        signals.push(signal);
    }
    signals
}

fn is_binary_content(content: &[u8]) -> bool {
    if content.is_empty() {
        return false;
    }
    if content.contains(&0) || std::str::from_utf8(content).is_err() {
        return true;
    }

    let control_count = content
        .iter()
        .filter(|&&byte| byte.is_ascii_control() && !matches!(byte, b'\t' | b'\n' | b'\r' | 0x0c))
        .count();

    control_count >= 4 && control_count * 100 / content.len() > 30
}

fn shebang_language(content: &[u8]) -> Option<SecurityLanguage> {
    let text = std::str::from_utf8(content).ok()?;
    let shebang = text.strip_prefix("#!")?;
    let first_line = shebang.lines().next().unwrap_or_default();
    let mut tokens = first_line.split_ascii_whitespace();
    let first = tokens.next()?;
    if interpreter_basename(first).eq_ignore_ascii_case("env") {
        for token in tokens {
            if token == "-S" || token.starts_with('-') {
                continue;
            }
            return interpreter_language(token);
        }
        None
    } else {
        interpreter_language(first)
    }
}

fn interpreter_language(token: &str) -> Option<SecurityLanguage> {
    let name = interpreter_basename(token).to_ascii_lowercase();
    let name = name.strip_suffix(".exe").unwrap_or(&name);
    match name {
        "sh" | "bash" | "dash" | "zsh" | "ksh" | "fish" => Some(SecurityLanguage::Shell),
        "python" | "python2" | "python3" => Some(SecurityLanguage::Python),
        "node" | "nodejs" | "deno" | "bun" => Some(SecurityLanguage::JavaScript),
        "ts-node" | "tsx" => Some(SecurityLanguage::TypeScript),
        "ruby" | "rb" => Some(SecurityLanguage::Ruby),
        _ => None,
    }
}

fn interpreter_basename(token: &str) -> &str {
    token.rsplit(['/', '\\']).next().unwrap_or(token)
}

fn extension_language(path: &str) -> Option<SecurityLanguage> {
    let extension = path.rsplit_once('.')?.1.to_ascii_lowercase();
    match extension.as_str() {
        "sh" | "bash" | "zsh" | "ksh" | "dash" | "fish" => Some(SecurityLanguage::Shell),
        "py" | "pyw" => Some(SecurityLanguage::Python),
        "js" | "cjs" | "mjs" => Some(SecurityLanguage::JavaScript),
        "ts" | "cts" | "mts" => Some(SecurityLanguage::TypeScript),
        "rb" => Some(SecurityLanguage::Ruby),
        "go" => Some(SecurityLanguage::Go),
        "rs" => Some(SecurityLanguage::Rust),
        "yaml" | "yml" => Some(SecurityLanguage::Yaml),
        "json" => Some(SecurityLanguage::Json),
        _ => None,
    }
}

fn sniff_content_language(content: &[u8], executable: bool) -> Option<SecurityLanguage> {
    let text = std::str::from_utf8(content).ok()?;
    let trimmed = text.trim_start_matches('\u{feff}').trim_start();
    if trimmed.is_empty() {
        return None;
    }
    let lower = trimmed.to_ascii_lowercase();

    if has_json_document_start(trimmed) {
        return Some(SecurityLanguage::Json);
    }
    if trimmed.starts_with("---\n")
        || trimmed.starts_with("---\r\n")
        || has_yaml_directive_start(&lower)
        || has_yaml_mapping_block(trimmed)
    {
        return Some(SecurityLanguage::Yaml);
    }
    if has_go_hint(trimmed) {
        return Some(SecurityLanguage::Go);
    }
    if has_rust_hint(trimmed) {
        return Some(SecurityLanguage::Rust);
    }
    if has_typescript_hint(trimmed) {
        return Some(SecurityLanguage::TypeScript);
    }
    if has_javascript_hint(trimmed) {
        return Some(SecurityLanguage::JavaScript);
    }
    if has_python_hint(trimmed) {
        return Some(SecurityLanguage::Python);
    }
    if has_ruby_hint(trimmed) {
        return Some(SecurityLanguage::Ruby);
    }
    if executable && has_shell_hint(trimmed) {
        return Some(SecurityLanguage::Shell);
    }

    None
}

fn has_json_document_start(text: &str) -> bool {
    if !(text.starts_with('{') || text.starts_with('[')) {
        return false;
    }

    JsonSniffParser::new(text).parse_document()
}

struct JsonSniffParser<'a> {
    text: &'a str,
    index: usize,
}

impl<'a> JsonSniffParser<'a> {
    const MAX_DEPTH: usize = 64;

    fn new(text: &'a str) -> Self {
        Self { text, index: 0 }
    }

    fn parse_document(&mut self) -> bool {
        self.skip_json_whitespace();
        if !matches!(self.peek_byte(), Some(b'{' | b'[')) {
            return false;
        }
        self.parse_value(0) && {
            self.skip_json_whitespace();
            self.index == self.text.len()
        }
    }

    fn parse_value(&mut self, depth: usize) -> bool {
        if depth > Self::MAX_DEPTH {
            return false;
        }

        self.skip_json_whitespace();
        match self.peek_byte() {
            Some(b'{') => self.parse_object(depth + 1),
            Some(b'[') => self.parse_array(depth + 1),
            Some(b'"') => self.parse_string(),
            Some(b'-' | b'0'..=b'9') => self.parse_number(),
            Some(b't') => self.consume_keyword("true"),
            Some(b'f') => self.consume_keyword("false"),
            Some(b'n') => self.consume_keyword("null"),
            _ => false,
        }
    }

    fn parse_object(&mut self, depth: usize) -> bool {
        if !self.consume_byte(b'{') {
            return false;
        }
        self.skip_json_whitespace();
        if self.consume_byte(b'}') {
            return true;
        }

        loop {
            self.skip_json_whitespace();
            if !self.parse_string() {
                return false;
            }
            self.skip_json_whitespace();
            if !self.consume_byte(b':') {
                return false;
            }
            if !self.parse_value(depth) {
                return false;
            }
            self.skip_json_whitespace();
            if self.consume_byte(b'}') {
                return true;
            }
            if !self.consume_byte(b',') {
                return false;
            }
        }
    }

    fn parse_array(&mut self, depth: usize) -> bool {
        if !self.consume_byte(b'[') {
            return false;
        }
        self.skip_json_whitespace();
        if self.consume_byte(b']') {
            return true;
        }

        loop {
            if !self.parse_value(depth) {
                return false;
            }
            self.skip_json_whitespace();
            if self.consume_byte(b']') {
                return true;
            }
            if !self.consume_byte(b',') {
                return false;
            }
        }
    }

    fn parse_string(&mut self) -> bool {
        if !self.consume_byte(b'"') {
            return false;
        }

        while let Some(byte) = self.peek_byte() {
            match byte {
                b'"' => {
                    self.index += 1;
                    return true;
                }
                b'\\' => {
                    self.index += 1;
                    if !self.parse_escape() {
                        return false;
                    }
                }
                0x00..=0x1f => return false,
                _ => self.index += 1,
            }
        }

        false
    }

    fn parse_escape(&mut self) -> bool {
        match self.peek_byte() {
            Some(b'"' | b'\\' | b'/' | b'b' | b'f' | b'n' | b'r' | b't') => {
                self.index += 1;
                true
            }
            Some(b'u') => {
                self.index += 1;
                for _ in 0..4 {
                    if !matches!(self.peek_byte(), Some(byte) if byte.is_ascii_hexdigit()) {
                        return false;
                    }
                    self.index += 1;
                }
                true
            }
            _ => false,
        }
    }

    fn parse_number(&mut self) -> bool {
        let start = self.index;
        self.consume_byte(b'-');

        match self.peek_byte() {
            Some(b'0') => self.index += 1,
            Some(b'1'..=b'9') => {
                self.index += 1;
                while matches!(self.peek_byte(), Some(b'0'..=b'9')) {
                    self.index += 1;
                }
            }
            _ => return false,
        }

        if self.consume_byte(b'.') {
            if !matches!(self.peek_byte(), Some(b'0'..=b'9')) {
                return false;
            }
            while matches!(self.peek_byte(), Some(b'0'..=b'9')) {
                self.index += 1;
            }
        }

        if matches!(self.peek_byte(), Some(b'e' | b'E')) {
            self.index += 1;
            let _ = self.consume_byte(b'+') || self.consume_byte(b'-');
            if !matches!(self.peek_byte(), Some(b'0'..=b'9')) {
                return false;
            }
            while matches!(self.peek_byte(), Some(b'0'..=b'9')) {
                self.index += 1;
            }
        }

        self.index > start
    }

    fn consume_keyword(&mut self, keyword: &str) -> bool {
        if self.text[self.index..].starts_with(keyword) {
            self.index += keyword.len();
            true
        } else {
            false
        }
    }

    fn skip_json_whitespace(&mut self) {
        while matches!(self.peek_byte(), Some(b' ' | b'\n' | b'\r' | b'\t')) {
            self.index += 1;
        }
    }

    fn consume_byte(&mut self, expected: u8) -> bool {
        if self.peek_byte() == Some(expected) {
            self.index += 1;
            true
        } else {
            false
        }
    }

    fn peek_byte(&self) -> Option<u8> {
        self.text.as_bytes().get(self.index).copied()
    }
}

fn has_yaml_directive_start(lowercase_text: &str) -> bool {
    let directive = lowercase_text.lines().next().unwrap_or_default();
    let Some(rest) = directive.strip_prefix("%yaml") else {
        return false;
    };

    rest.is_empty() || rest.starts_with(char::is_whitespace)
}

fn has_yaml_mapping_block(text: &str) -> bool {
    let mut mapping_entries = 0;
    let mut pending_nested_value = false;

    for line in text
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .take(8)
    {
        if pending_nested_value && line.starts_with("- ") {
            return true;
        }

        let Some((key, value)) = line.split_once(':') else {
            return false;
        };
        if !is_yaml_mapping_key(key) || !(value.is_empty() || value.starts_with(' ')) {
            return false;
        }

        mapping_entries += 1;
        if mapping_entries >= 2 {
            return true;
        }
        pending_nested_value = value.trim().is_empty();
    }

    false
}

fn is_yaml_mapping_key(key: &str) -> bool {
    let mut chars = key.chars();
    matches!(chars.next(), Some(first) if first.is_ascii_lowercase())
        && chars.all(|character| {
            character.is_ascii_lowercase()
                || character.is_ascii_digit()
                || matches!(character, '_' | '-')
        })
}

fn has_go_hint(text: &str) -> bool {
    let Some(line) = first_meaningful_line(text) else {
        return false;
    };
    line.starts_with("package ") && text.contains("\nfunc ")
}

fn has_rust_hint(text: &str) -> bool {
    text.contains("fn main(")
        || text.contains("\nfn ")
        || text.starts_with("use std::")
        || text.contains("\nuse std::")
}

fn has_typescript_hint(text: &str) -> bool {
    text.starts_with("interface ")
        || text.starts_with("type ")
        || text.contains(": string")
        || text.contains(": number")
        || text.contains(": boolean")
}

fn has_javascript_hint(text: &str) -> bool {
    let first_line = first_meaningful_line(text).unwrap_or_default();
    text.starts_with("const ")
        || text.starts_with("let ")
        || text.starts_with("var ")
        || (first_line.starts_with("import ")
            && (first_line.contains(" from ")
                || first_line.contains('"')
                || first_line.contains('\'')
                || first_line.ends_with(';')))
        || text.contains("require(")
        || text.contains("module.exports")
}

fn has_python_hint(text: &str) -> bool {
    text.starts_with("import ")
        || text.starts_with("from ")
        || text.starts_with("def ")
        || text.starts_with("class ")
        || text.contains("if __name__ == \"__main__\":")
        || text.contains("if __name__ == '__main__':")
}

fn has_ruby_hint(text: &str) -> bool {
    text.starts_with("require ")
        || text.starts_with("puts ")
        || text.contains("\ndef ")
        || text.contains("\nclass ")
}

fn has_shell_hint(text: &str) -> bool {
    let Some(line) = first_meaningful_line(text) else {
        return false;
    };
    line.starts_with("set -")
        || line.starts_with("echo ")
        || line.starts_with("export ")
        || line.starts_with("cd ")
        || line.starts_with("if [ ")
        || line.starts_with("for ")
        || text.contains("\nthen\n")
        || text.contains("; do")
}

fn first_meaningful_line(text: &str) -> Option<&str> {
    text.lines()
        .map(str::trim)
        .find(|line| !line.is_empty() && !line.starts_with('#'))
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecurityArtifactSelection {
    pub artifacts: Vec<SelectedSecurityArtifact>,
}

impl SecurityArtifactSelection {
    pub fn is_empty(&self) -> bool {
        self.artifacts.is_empty()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct SelectedSecurityArtifact {
    pub path: String,
    pub reasons: Vec<SecurityArtifactSelectionReason>,
    pub executable: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SecurityArtifactSelectionReason {
    Manifest,
    Referenced,
    KnownArtifactDirectory,
    Executable,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecurityPackageSelectionInput {
    pub package_root: String,
    pub manifest_path: String,
    pub references: Vec<SecurityReferenceSelectionInput>,
    pub artifact_inventory: Vec<SecurityArtifactInventoryEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecurityReferenceSelectionInput {
    pub target: String,
    pub exists: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecurityArtifactInventoryEntry {
    pub path: String,
    pub kind: SecurityArtifactKind,
    pub file_kind: SecurityArtifactFileKind,
    pub size_bytes: u64,
    pub executable: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SecurityArtifactFileKind {
    File,
    Directory,
    Symlink,
    Other,
}

pub fn select_security_artifacts(
    packages: &[SecurityPackageSelectionInput],
) -> SecurityArtifactSelection {
    let mut selected = BTreeMap::new();

    for package in packages {
        select_package_security_artifacts(package, &mut selected);
    }

    SecurityArtifactSelection {
        artifacts: selected
            .into_iter()
            .map(|(path, artifact)| SelectedSecurityArtifact {
                path,
                reasons: artifact.reasons.into_iter().collect(),
                executable: artifact.executable,
            })
            .collect(),
    }
}

fn select_package_security_artifacts(
    package: &SecurityPackageSelectionInput,
    selected: &mut BTreeMap<String, SelectedArtifactAccumulator>,
) {
    let Some(package_root) = normalize_package_root(&package.package_root) else {
        return;
    };

    if let Some(manifest_path) = normalize_scan_relative_path(&package.manifest_path) {
        record_selection(
            selected,
            manifest_path,
            SecurityArtifactSelectionReason::Manifest,
            false,
        );
    }

    for reference in &package.references {
        if !reference.exists {
            continue;
        }
        let Some(reference_path) =
            normalize_package_relative_path(strip_query_and_fragment(&reference.target))
        else {
            continue;
        };
        record_selection(
            selected,
            join_package_path(&package_root, &reference_path),
            SecurityArtifactSelectionReason::Referenced,
            false,
        );
    }

    for entry in &package.artifact_inventory {
        if entry.file_kind == SecurityArtifactFileKind::Directory {
            continue;
        }

        let mut reasons = BTreeSet::new();
        if is_known_artifact_directory_kind(entry.kind) {
            reasons.insert(SecurityArtifactSelectionReason::KnownArtifactDirectory);
        }
        if entry.executable {
            reasons.insert(SecurityArtifactSelectionReason::Executable);
        }
        if reasons.is_empty() {
            continue;
        }

        let Some(entry_path) = normalize_package_relative_path(&entry.path) else {
            continue;
        };
        let output_path = join_package_path(&package_root, &entry_path);
        for reason in reasons {
            record_selection(selected, output_path.clone(), reason, entry.executable);
        }
    }
}

#[derive(Debug, Clone, Default)]
struct SelectedArtifactAccumulator {
    reasons: BTreeSet<SecurityArtifactSelectionReason>,
    executable: bool,
}

fn record_selection(
    selected: &mut BTreeMap<String, SelectedArtifactAccumulator>,
    path: String,
    reason: SecurityArtifactSelectionReason,
    executable: bool,
) {
    let artifact = selected.entry(path).or_default();
    artifact.reasons.insert(reason);
    artifact.executable |= executable;
}

fn is_known_artifact_directory_kind(kind: SecurityArtifactKind) -> bool {
    matches!(
        kind,
        SecurityArtifactKind::Script
            | SecurityArtifactKind::Reference
            | SecurityArtifactKind::Asset
    )
}

fn normalize_scan_relative_path(path: &str) -> Option<String> {
    normalize_local_relative_path(path, false)
}

fn normalize_package_root(path: &str) -> Option<String> {
    normalize_local_relative_path(path, true)
}

fn normalize_package_relative_path(path: &str) -> Option<String> {
    normalize_local_relative_path(path, false)
}

fn normalize_local_relative_path(path: &str, allow_empty: bool) -> Option<String> {
    let normalized = path.replace('\\', "/");
    if normalized.is_empty() || normalized == "." {
        return allow_empty.then(String::new);
    }
    if has_uri_scheme(&normalized) || normalized.starts_with('/') || has_windows_prefix(&normalized)
    {
        return None;
    }

    let mut components = Vec::new();
    for component in normalized.split('/') {
        match component {
            "" | "." => {}
            ".." => return None,
            value => components.push(value),
        }
    }

    if components.is_empty() {
        allow_empty.then(String::new)
    } else {
        Some(components.join("/"))
    }
}

fn join_package_path(package_root: &str, package_relative_path: &str) -> String {
    if package_root.is_empty() {
        package_relative_path.to_owned()
    } else {
        format!("{package_root}/{package_relative_path}")
    }
}

fn strip_query_and_fragment(target: &str) -> &str {
    match (target.find('?'), target.find('#')) {
        (Some(query), Some(fragment)) => &target[..query.min(fragment)],
        (Some(index), None) | (None, Some(index)) => &target[..index],
        (None, None) => target,
    }
}

fn has_uri_scheme(target: &str) -> bool {
    let Some(colon_index) = target.find(':') else {
        return false;
    };
    if target[..colon_index].contains('/') {
        return false;
    }

    let mut chars = target[..colon_index].chars();
    matches!(chars.next(), Some(first) if first.is_ascii_alphabetic())
        && chars.all(|value| value.is_ascii_alphanumeric() || matches!(value, '+' | '-' | '.'))
}

fn has_windows_prefix(target: &str) -> bool {
    let bytes = target.as_bytes();
    matches!(
        bytes,
        [drive, b':', ..] if drive.is_ascii_alphabetic()
    ) || target.starts_with("//")
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct SecuritySignal {
    pub location: SecurityLocation,
    pub kind: SecuritySignalKind,
    pub source: Option<SecuritySource>,
    pub sink: Option<SecuritySink>,
    pub risk: SecurityRiskScore,
    pub confidence: AnalyzerConfidence,
    pub classification: ClassificationMethod,
    pub evidence: String,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct SecurityLocation {
    pub path: String,
    pub line: Option<usize>,
    pub column: Option<usize>,
    pub byte_offset: Option<usize>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SecuritySignalKind {
    CredentialUse,
    DataExfiltration,
    DestructiveCommand,
    DynamicCodeEvaluation,
    EnvironmentVariableRead,
    FileWrite,
    GitHistoryModification,
    HiddenInstruction,
    NetworkAccess,
    ObfuscatedCommand,
    PackageInstallation,
    PromptInjectionInstruction,
    RemoteCodeExecution,
    SecretRead,
    SubprocessExecution,
    PrivilegeEscalation,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct SecuritySource {
    pub kind: SecuritySourceKind,
    pub name: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SecuritySourceKind {
    CredentialStore,
    EnvironmentVariable,
    FileSystem,
    NetworkResponse,
    ProcessArgument,
    StandardInput,
    UserInput,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct SecuritySink {
    pub kind: SecuritySinkKind,
    pub target: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SecuritySinkKind {
    DynamicCodeEvaluation,
    EnvironmentWrite,
    FileDelete,
    FileWrite,
    GitHistoryRewrite,
    NetworkRequest,
    PackageInstall,
    PrivilegeEscalation,
    ProcessExecution,
    ShellExecution,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct SecurityRiskScore {
    pub value: u8,
}

impl SecurityRiskScore {
    pub const MIN: u8 = 0;
    pub const MAX: u8 = 100;

    pub const fn new(value: u8) -> Self {
        Self { value }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AnalyzerConfidence {
    Low,
    Medium,
    High,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ClassificationMethod {
    AstPattern,
    FrontmatterField,
    ManifestText,
    RegexFallback,
    StaticMetadata,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    #[test]
    fn initial_security_rule_ids_are_stable_and_unique() {
        assert_eq!(INITIAL_SECURITY_RULE_IDS.first(), Some(&"SEC001"));
        assert_eq!(INITIAL_SECURITY_RULE_IDS.last(), Some(&"SEC012"));
        assert_eq!(INITIAL_SECURITY_RULE_IDS.len(), 12);

        let mut sorted = INITIAL_SECURITY_RULE_IDS.to_vec();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), INITIAL_SECURITY_RULE_IDS.len());
    }

    #[test]
    fn security_artifacts_have_stable_equality_and_ordering() {
        let artifacts = vec![
            SecurityArtifact {
                path: "scripts/install.sh".to_owned(),
                kind: SecurityArtifactKind::Script,
                language: SecurityLanguage::Shell,
                size_bytes: 120,
                executable: true,
            },
            SecurityArtifact {
                path: "SKILL.md".to_owned(),
                kind: SecurityArtifactKind::Manifest,
                language: SecurityLanguage::Unknown,
                size_bytes: 80,
                executable: false,
            },
        ];
        let mut sorted = artifacts.clone();

        sorted.sort();

        assert_ne!(artifacts[0], artifacts[1]);
        assert_eq!(
            sorted
                .iter()
                .map(|artifact| artifact.path.as_str())
                .collect::<Vec<_>>(),
            vec!["SKILL.md", "scripts/install.sh",]
        );
    }

    #[test]
    fn security_signals_deduplicate_with_ord_consistent_equality() {
        let first = sudo_signal("scripts/install.sh", 9, 4);
        let duplicate = sudo_signal("scripts/install.sh", 9, 4);
        let later = sudo_signal("scripts/install.sh", 12, 4);
        let mut signals = BTreeSet::new();

        signals.insert(later.clone());
        signals.insert(first.clone());
        signals.insert(duplicate);

        assert_eq!(signals.len(), 2);
        assert_eq!(signals.into_iter().collect::<Vec<_>>(), vec![first, later]);
    }

    #[test]
    fn security_scan_serializes_with_stable_field_and_enum_names() {
        let scan = SecurityScan {
            artifacts: vec![SecurityArtifact {
                path: "scripts/install.sh".to_owned(),
                kind: SecurityArtifactKind::Script,
                language: SecurityLanguage::Shell,
                size_bytes: 120,
                executable: true,
            }],
            signals: vec![sudo_signal("scripts/install.sh", 9, 4)],
        };

        assert_eq!(
            serde_json::to_value(&scan).expect("serialize security scan"),
            serde_json::json!({
                "artifacts": [
                    {
                        "path": "scripts/install.sh",
                        "kind": "script",
                        "language": "shell",
                        "size_bytes": 120,
                        "executable": true
                    }
                ],
                "signals": [
                    {
                        "location": {
                            "path": "scripts/install.sh",
                            "line": 9,
                            "column": 4,
                            "byte_offset": null
                        },
                        "kind": "privilege-escalation",
                        "source": null,
                        "sink": {
                            "kind": "privilege-escalation",
                            "target": "sudo"
                        },
                        "risk": {
                            "value": 75
                        },
                        "confidence": "high",
                        "classification": "regex-fallback",
                        "evidence": "sudo apt-get update"
                    }
                ]
            })
        );
    }

    #[test]
    fn security_artifact_selection_orders_paths_stably() {
        let packages = vec![
            selection_package(
                "zeta",
                "zeta\\SKILL.md",
                vec![existing_reference("references\\guide.md")],
                vec![inventory_file(
                    "scripts\\run.sh",
                    SecurityArtifactKind::Script,
                    true,
                )],
            ),
            selection_package(
                "alpha",
                "alpha/SKILL.md",
                vec![existing_reference("references/setup.md#install")],
                vec![inventory_file(
                    "assets/icon.png",
                    SecurityArtifactKind::Asset,
                    false,
                )],
            ),
        ];

        let first = select_security_artifacts(&packages);
        let second = select_security_artifacts(&packages);

        assert_eq!(first, second);
        assert_eq!(
            selected_paths(&first),
            vec![
                "alpha/SKILL.md",
                "alpha/assets/icon.png",
                "alpha/references/setup.md",
                "zeta/SKILL.md",
                "zeta/references/guide.md",
                "zeta/scripts/run.sh",
            ]
        );
    }

    #[test]
    fn security_artifact_selection_deduplicates_paths_and_reasons() {
        let package = selection_package(
            "skill",
            "skill/SKILL.md",
            vec![
                existing_reference("references/guide.md"),
                existing_reference("references/guide.md?raw=1#setup"),
            ],
            vec![
                inventory_file("references/guide.md", SecurityArtifactKind::Reference, true),
                inventory_file("references/guide.md", SecurityArtifactKind::Reference, true),
            ],
        );

        let selection = select_security_artifacts(&[package]);
        let guide = selection
            .artifacts
            .iter()
            .find(|artifact| artifact.path == "skill/references/guide.md")
            .expect("guide selected");

        assert_eq!(selection.artifacts.len(), 2);
        assert_eq!(
            guide.reasons,
            vec![
                SecurityArtifactSelectionReason::Referenced,
                SecurityArtifactSelectionReason::KnownArtifactDirectory,
                SecurityArtifactSelectionReason::Executable,
            ]
        );
        assert!(guide.executable);
    }

    #[test]
    fn security_artifact_selection_excludes_missing_references() {
        let package = selection_package(
            "",
            "SKILL.md",
            vec![
                existing_reference("references/guide.md"),
                SecurityReferenceSelectionInput {
                    target: "references/missing.md".to_owned(),
                    exists: false,
                },
            ],
            Vec::new(),
        );

        let selection = select_security_artifacts(&[package]);

        assert_eq!(
            selected_paths(&selection),
            vec!["SKILL.md", "references/guide.md"]
        );
        assert!(!selected_paths(&selection).contains(&"references/missing.md"));
    }

    #[test]
    fn security_artifact_selection_excludes_unrelated_repository_files() {
        let package = selection_package(
            "skill",
            "skill/SKILL.md",
            vec![
                existing_reference("references/guide.md"),
                existing_reference("../outside.md"),
                existing_reference("https://example.test/remote.md"),
            ],
            vec![
                inventory_file("scripts/run.sh", SecurityArtifactKind::Script, false),
                inventory_file("../scripts/outside.sh", SecurityArtifactKind::Script, true),
                inventory_file("src/lib.rs", SecurityArtifactKind::Other, false),
                inventory_directory("scripts/nested", SecurityArtifactKind::Script),
            ],
        );

        let selection = select_security_artifacts(&[package]);

        assert_eq!(
            selected_paths(&selection),
            vec![
                "skill/SKILL.md",
                "skill/references/guide.md",
                "skill/scripts/run.sh",
            ]
        );
    }

    #[test]
    fn security_artifact_selection_can_select_explicit_executable_inventory() {
        let package = selection_package(
            "skill",
            "skill/SKILL.md",
            Vec::new(),
            vec![inventory_file(
                "tools/local-helper",
                SecurityArtifactKind::Other,
                true,
            )],
        );

        let selection = select_security_artifacts(&[package]);

        assert_eq!(
            selected_paths(&selection),
            vec!["skill/SKILL.md", "skill/tools/local-helper"]
        );
        assert_eq!(
            selection.artifacts[1].reasons,
            vec![SecurityArtifactSelectionReason::Executable]
        );
        assert!(selection.artifacts[1].executable);
    }

    #[test]
    fn enum_serialization_names_are_stable_for_public_output() {
        assert_eq!(
            serde_json::to_value([
                SecuritySignalKind::RemoteCodeExecution,
                SecuritySignalKind::GitHistoryModification,
                SecuritySignalKind::HiddenInstruction,
            ])
            .expect("serialize signal kinds"),
            serde_json::json!([
                "remote-code-execution",
                "git-history-modification",
                "hidden-instruction"
            ])
        );
        assert_eq!(
            serde_json::to_value([
                SecurityLanguage::JavaScript,
                SecurityLanguage::Shell,
                SecurityLanguage::TypeScript,
            ])
            .expect("serialize security languages"),
            serde_json::json!(["javascript", "shell", "typescript"])
        );
        assert_eq!(
            serde_json::to_value([
                ClassificationMethod::AstPattern,
                ClassificationMethod::RegexFallback,
                ClassificationMethod::StaticMetadata,
            ])
            .expect("serialize classification methods"),
            serde_json::json!(["ast-pattern", "regex-fallback", "static-metadata"])
        );
        assert_eq!(
            serde_json::to_value([
                SecurityArtifactSelectionReason::KnownArtifactDirectory,
                SecurityArtifactSelectionReason::Executable,
            ])
            .expect("serialize selection reasons"),
            serde_json::json!(["known-artifact-directory", "executable"])
        );
        assert_eq!(
            serde_json::to_value([
                SecurityArtifactClassificationMethod::BinaryContent,
                SecurityArtifactClassificationMethod::ContentSniff,
                SecurityArtifactClassificationMethod::ExecutableContent,
            ])
            .expect("serialize classification methods"),
            serde_json::json!(["binary-content", "content-sniff", "executable-content"])
        );
        assert_eq!(
            serde_json::to_value([
                SecurityArtifactClassificationSignal::BinaryContent,
                SecurityArtifactClassificationSignal::ExecutableBit,
            ])
            .expect("serialize classification signals"),
            serde_json::json!(["binary-content", "executable-bit"])
        );
    }

    #[test]
    fn empty_security_scan_is_explicit() {
        assert!(SecurityScan::default().is_empty());
        assert!(!SecurityScan {
            artifacts: Vec::new(),
            signals: vec![sudo_signal("scripts/install.sh", 9, 4)],
        }
        .is_empty());
    }

    #[test]
    fn classification_detects_binary_before_text_signals() {
        let classification = classify_security_artifact(
            "scripts\\payload.py",
            b"#!/usr/bin/env python\n\0\x01\x02\x03",
            true,
        )
        .expect("safe path");

        assert_eq!(classification.path, "scripts/payload.py");
        assert_eq!(classification.language, SecurityLanguage::Binary);
        assert_eq!(
            classification.method,
            SecurityArtifactClassificationMethod::BinaryContent
        );
        assert_eq!(
            classification.signals,
            vec![
                SecurityArtifactClassificationSignal::BinaryContent,
                SecurityArtifactClassificationSignal::ExecutableBit,
            ]
        );
        assert!(!classification.text_parsing_allowed);
    }

    #[test]
    fn classification_uses_shebang_without_extension() {
        let classification =
            classify_security_artifact("scripts/bootstrap", b"#!/usr/bin/env ruby\n", false)
                .expect("safe path");

        assert_eq!(classification.language, SecurityLanguage::Ruby);
        assert_eq!(
            classification.method,
            SecurityArtifactClassificationMethod::Shebang
        );
        assert_eq!(
            classification.signals,
            vec![SecurityArtifactClassificationSignal::Shebang]
        );
        assert!(classification.text_parsing_allowed);
    }

    #[test]
    fn classification_lets_shebang_outrank_conflicting_extension() {
        let classification =
            classify_security_artifact("scripts/install.sh", b"#!/usr/bin/env python3\n", true)
                .expect("safe path");

        assert_eq!(classification.language, SecurityLanguage::Python);
        assert_eq!(
            classification.method,
            SecurityArtifactClassificationMethod::Shebang
        );
    }

    #[test]
    fn classification_uses_extension_before_conflicting_content_sniff() {
        let classification =
            classify_security_artifact("scripts/build.js", b"def build():\n    pass\n", false)
                .expect("safe path");

        assert_eq!(classification.language, SecurityLanguage::JavaScript);
        assert_eq!(
            classification.method,
            SecurityArtifactClassificationMethod::Extension
        );
        assert_eq!(
            classification.signals,
            vec![SecurityArtifactClassificationSignal::Extension]
        );
    }

    #[test]
    fn classification_maps_supported_extensions_deterministically() {
        let cases = [
            ("scripts/run.sh", SecurityLanguage::Shell),
            ("scripts/run.py", SecurityLanguage::Python),
            ("scripts/run.mjs", SecurityLanguage::JavaScript),
            ("scripts/run.ts", SecurityLanguage::TypeScript),
            ("scripts/run.rb", SecurityLanguage::Ruby),
            ("scripts/run.go", SecurityLanguage::Go),
            ("scripts/run.rs", SecurityLanguage::Rust),
            ("references/config.yaml", SecurityLanguage::Yaml),
            ("references/config.json", SecurityLanguage::Json),
        ];

        for (path, language) in cases {
            let first =
                classify_security_artifact(path, b"plain text\n", false).expect("safe path");
            let second =
                classify_security_artifact(path, b"plain text\n", false).expect("safe path");

            assert_eq!(first, second);
            assert_eq!(first.language, language);
            assert_eq!(
                first.method,
                SecurityArtifactClassificationMethod::Extension
            );
            assert!(first.text_parsing_allowed);
        }
    }

    #[test]
    fn classification_sniffs_obvious_text_formats() {
        let json_object =
            classify_security_artifact("references/schema", b"{\"name\":\"skill\"}", false)
                .expect("safe path");
        let json_array = classify_security_artifact("references/list", b"[\"notes\"]", false)
            .expect("safe path");
        let yaml = classify_security_artifact("references/config", b"---\nname: skill\n", false)
            .expect("safe path");

        assert_eq!(json_object.language, SecurityLanguage::Json);
        assert_eq!(
            json_object.method,
            SecurityArtifactClassificationMethod::ContentSniff
        );
        assert_eq!(json_array.language, SecurityLanguage::Json);
        assert_eq!(
            json_array.method,
            SecurityArtifactClassificationMethod::ContentSniff
        );
        assert_eq!(yaml.language, SecurityLanguage::Yaml);
        assert_eq!(
            yaml.method,
            SecurityArtifactClassificationMethod::ContentSniff
        );
    }

    #[test]
    fn classification_does_not_sniff_invalid_json_like_text() {
        for content in [b"{not json}".as_slice(), b"[notes]".as_slice()] {
            let classification =
                classify_security_artifact("references/notes", content, false).expect("safe path");

            assert_eq!(classification.language, SecurityLanguage::Unknown);
            assert_eq!(
                classification.method,
                SecurityArtifactClassificationMethod::Unknown
            );
        }
    }

    #[test]
    fn classification_does_not_sniff_single_prose_label_as_yaml() {
        let classification =
            classify_security_artifact("references/notes", b"TODO: review install script\n", false)
                .expect("safe path");

        assert_eq!(classification.language, SecurityLanguage::Unknown);
        assert_eq!(
            classification.method,
            SecurityArtifactClassificationMethod::Unknown
        );
    }

    #[test]
    fn classification_sniffs_obvious_script_languages() {
        let cases = [
            (
                b"package main\n\nfunc main() {}\n".as_slice(),
                SecurityLanguage::Go,
            ),
            (b"fn main() {}\n".as_slice(), SecurityLanguage::Rust),
            (
                b"interface Options { name: string }\n".as_slice(),
                SecurityLanguage::TypeScript,
            ),
            (
                b"const name = require('node:fs');\n".as_slice(),
                SecurityLanguage::JavaScript,
            ),
            (b"import os\n".as_slice(), SecurityLanguage::Python),
        ];

        for (content, language) in cases {
            let classification =
                classify_security_artifact("scripts/helper", content, false).expect("safe path");
            assert_eq!(classification.language, language);
            assert_eq!(
                classification.method,
                SecurityArtifactClassificationMethod::ContentSniff
            );
        }
    }

    #[test]
    fn classification_uses_executable_bit_only_with_shell_like_content() {
        let shell = classify_security_artifact("scripts/install", b"set -eu\necho ready\n", true)
            .expect("safe path");
        let executable_text =
            classify_security_artifact("scripts/readme", b"plain operational notes\n", true)
                .expect("safe path");

        assert_eq!(shell.language, SecurityLanguage::Shell);
        assert_eq!(
            shell.method,
            SecurityArtifactClassificationMethod::ExecutableContent
        );
        assert_eq!(
            shell.signals,
            vec![
                SecurityArtifactClassificationSignal::ContentSniff,
                SecurityArtifactClassificationSignal::ExecutableBit,
            ]
        );
        assert_eq!(executable_text.language, SecurityLanguage::Unknown);
        assert_eq!(
            executable_text.method,
            SecurityArtifactClassificationMethod::Unknown
        );
        assert_eq!(
            executable_text.signals,
            vec![SecurityArtifactClassificationSignal::ExecutableBit]
        );
    }

    #[test]
    fn classification_rejects_unsafe_public_paths() {
        assert!(classify_security_artifact("../scripts/run.sh", b"echo nope\n", true).is_none());
        assert!(classify_security_artifact("https://example.test/run.sh", b"", false).is_none());
        assert!(classify_security_artifact("C:\\tmp\\run.sh", b"", false).is_none());
    }

    fn sudo_signal(path: &str, line: usize, column: usize) -> SecuritySignal {
        SecuritySignal {
            location: SecurityLocation {
                path: path.to_owned(),
                line: Some(line),
                column: Some(column),
                byte_offset: None,
            },
            kind: SecuritySignalKind::PrivilegeEscalation,
            source: None,
            sink: Some(SecuritySink {
                kind: SecuritySinkKind::PrivilegeEscalation,
                target: Some("sudo".to_owned()),
            }),
            risk: SecurityRiskScore::new(75),
            confidence: AnalyzerConfidence::High,
            classification: ClassificationMethod::RegexFallback,
            evidence: "sudo apt-get update".to_owned(),
        }
    }

    fn selection_package(
        package_root: &str,
        manifest_path: &str,
        references: Vec<SecurityReferenceSelectionInput>,
        artifact_inventory: Vec<SecurityArtifactInventoryEntry>,
    ) -> SecurityPackageSelectionInput {
        SecurityPackageSelectionInput {
            package_root: package_root.to_owned(),
            manifest_path: manifest_path.to_owned(),
            references,
            artifact_inventory,
        }
    }

    fn existing_reference(target: &str) -> SecurityReferenceSelectionInput {
        SecurityReferenceSelectionInput {
            target: target.to_owned(),
            exists: true,
        }
    }

    fn inventory_file(
        path: &str,
        kind: SecurityArtifactKind,
        executable: bool,
    ) -> SecurityArtifactInventoryEntry {
        SecurityArtifactInventoryEntry {
            path: path.to_owned(),
            kind,
            file_kind: SecurityArtifactFileKind::File,
            size_bytes: 10,
            executable,
        }
    }

    fn inventory_directory(
        path: &str,
        kind: SecurityArtifactKind,
    ) -> SecurityArtifactInventoryEntry {
        SecurityArtifactInventoryEntry {
            path: path.to_owned(),
            kind,
            file_kind: SecurityArtifactFileKind::Directory,
            size_bytes: 0,
            executable: false,
        }
    }

    fn selected_paths(selection: &SecurityArtifactSelection) -> Vec<&str> {
        selection
            .artifacts
            .iter()
            .map(|artifact| artifact.path.as_str())
            .collect()
    }
}
