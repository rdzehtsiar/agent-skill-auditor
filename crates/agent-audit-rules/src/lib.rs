// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeMap;
use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum RuleId {
    Skill001,
    Skill002,
    Skill010,
    Skill020,
    Skill030,
    Skill040,
    Skill041,
    Skill050,
}

impl RuleId {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Skill001 => "SKILL001",
            Self::Skill002 => "SKILL002",
            Self::Skill010 => "SKILL010",
            Self::Skill020 => "SKILL020",
            Self::Skill030 => "SKILL030",
            Self::Skill040 => "SKILL040",
            Self::Skill041 => "SKILL041",
            Self::Skill050 => "SKILL050",
        }
    }

    pub const fn parse(rule_id: &str) -> Option<Self> {
        match rule_id.as_bytes() {
            b"SKILL001" => Some(Self::Skill001),
            b"SKILL002" => Some(Self::Skill002),
            b"SKILL010" => Some(Self::Skill010),
            b"SKILL020" => Some(Self::Skill020),
            b"SKILL030" => Some(Self::Skill030),
            b"SKILL040" => Some(Self::Skill040),
            b"SKILL041" => Some(Self::Skill041),
            b"SKILL050" => Some(Self::Skill050),
            _ => None,
        }
    }
}

impl fmt::Display for RuleId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum RuleSeverity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl RuleSeverity {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Info => "info",
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
            Self::Critical => "critical",
        }
    }
}

impl fmt::Display for RuleSeverity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum RuleCategory {
    Spec,
    Compatibility,
    Security,
    Quality,
    Portability,
    Reproducibility,
}

impl RuleCategory {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Spec => "spec",
            Self::Compatibility => "compatibility",
            Self::Security => "security",
            Self::Quality => "quality",
            Self::Portability => "portability",
            Self::Reproducibility => "reproducibility",
        }
    }
}

impl fmt::Display for RuleCategory {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum RuleStatus {
    Active,
    Reserved,
}

impl RuleStatus {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Reserved => "reserved",
        }
    }

    pub const fn emits_findings(self) -> bool {
        matches!(self, Self::Active)
    }
}

impl fmt::Display for RuleStatus {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum HostProfile {
    AgentSkillsSpec,
    ClaudeCode,
    Codex,
    GithubCopilot,
    VscodeCopilot,
    Generic,
}

impl HostProfile {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AgentSkillsSpec => "agent-skills-spec",
            Self::ClaudeCode => "claude-code",
            Self::Codex => "codex",
            Self::GithubCopilot => "github-copilot",
            Self::VscodeCopilot => "vscode-copilot",
            Self::Generic => "generic",
        }
    }
}

impl fmt::Display for HostProfile {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum RuleInputNodeType {
    SkillManifest,
    Frontmatter,
    RelativeReference,
    SkillPackage,
}

impl RuleInputNodeType {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SkillManifest => "skill-manifest",
            Self::Frontmatter => "frontmatter",
            Self::RelativeReference => "relative-reference",
            Self::SkillPackage => "skill-package",
        }
    }
}

impl fmt::Display for RuleInputNodeType {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RuleExample {
    pub summary: &'static str,
    pub non_compliant: &'static str,
    pub compliant: &'static str,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RuleMetadata {
    pub id: RuleId,
    pub status: RuleStatus,
    pub title: &'static str,
    pub severity: RuleSeverity,
    pub category: RuleCategory,
    pub applicable_profiles: &'static [HostProfile],
    pub input_node_types: &'static [RuleInputNodeType],
    pub rationale: &'static str,
    pub remediation: &'static str,
    pub suppression_guidance: &'static str,
    pub examples: &'static [RuleExample],
}

#[derive(Debug, Clone, Copy)]
pub struct RuleRegistry {
    rules: &'static [RuleMetadata],
}

impl RuleRegistry {
    const fn new(rules: &'static [RuleMetadata]) -> Self {
        Self { rules }
    }

    pub const fn rules(&self) -> &'static [RuleMetadata] {
        self.rules
    }

    pub fn metadata(&self, rule_id: &str) -> Option<&'static RuleMetadata> {
        self.rules
            .binary_search_by(|metadata| metadata.id.as_str().cmp(rule_id))
            .ok()
            .map(|index| &self.rules[index])
    }
}

pub const STRUCTURAL_RULE_IDS: &[&str] = &[
    "SKILL001", "SKILL002", "SKILL010", "SKILL020", "SKILL030", "SKILL040", "SKILL041",
];

pub const ACTIVE_RULE_IDS: &[&str] = &[
    "SKILL001", "SKILL002", "SKILL010", "SKILL020", "SKILL030", "SKILL040", "SKILL041", "SKILL050",
];

pub const RESERVED_RULE_IDS: &[&str] = &[];

pub const ALL_HOST_PROFILES: &[HostProfile] = &[
    HostProfile::AgentSkillsSpec,
    HostProfile::ClaudeCode,
    HostProfile::Codex,
    HostProfile::GithubCopilot,
    HostProfile::VscodeCopilot,
    HostProfile::Generic,
];

const SKILL_MANIFEST_INPUT: &[RuleInputNodeType] = &[RuleInputNodeType::SkillManifest];
const FRONTMATTER_INPUT: &[RuleInputNodeType] = &[RuleInputNodeType::Frontmatter];
const RELATIVE_REFERENCE_INPUT: &[RuleInputNodeType] = &[RuleInputNodeType::RelativeReference];
const SKILL_PACKAGE_INPUT: &[RuleInputNodeType] = &[RuleInputNodeType::SkillPackage];

const SKILL001_EXAMPLES: &[RuleExample] = &[RuleExample {
    summary: "Declare a stable skill name.",
    non_compliant: "---\ndescription: Reviews pull requests.\n---\n",
    compliant: "---\nname: pr-reviewer\ndescription: Reviews pull requests.\n---\n",
}];

const SKILL002_EXAMPLES: &[RuleExample] = &[RuleExample {
    summary: "Declare a concise skill description.",
    non_compliant: "---\nname: pr-reviewer\n---\n",
    compliant: "---\nname: pr-reviewer\ndescription: Reviews pull requests.\n---\n",
}];

const SKILL010_EXAMPLES: &[RuleExample] = &[RuleExample {
    summary: "Keep relative references resolvable within the skill directory.",
    non_compliant: "See [guide](references/missing.md).",
    compliant: "See [guide](references/guide.md).",
}];

const SKILL020_EXAMPLES: &[RuleExample] = &[RuleExample {
    summary: "Move long content out of SKILL.md.",
    non_compliant: "A very large SKILL.md containing bulk reference material.",
    compliant: "A compact SKILL.md that links to detailed files under references/.",
}];

const SKILL030_EXAMPLES: &[RuleExample] = &[RuleExample {
    summary: "Use unique names across scanned skill packages.",
    non_compliant: "Two discovered manifests both declare name: reviewer.",
    compliant:
        "One manifest declares name: pr-reviewer and another declares name: release-reviewer.",
}];

const SKILL040_EXAMPLES: &[RuleExample] = &[RuleExample {
    summary: "Use only portable or selected-profile-supported frontmatter fields.",
    non_compliant: "---\nname: reviewer\ndescription: Reviews changes.\nowner: security\n---\n",
    compliant: "---\nname: reviewer\ndescription: Reviews changes.\n---\n",
}];

const SKILL041_EXAMPLES: &[RuleExample] = &[RuleExample {
    summary: "Keep YAML frontmatter parseable.",
    non_compliant: "---\nname: [unterminated\n---\n",
    compliant: "---\nname: reviewer\ndescription: Reviews changes.\n---\n",
}];

const SKILL050_EXAMPLES: &[RuleExample] = &[RuleExample {
    summary: "Use metadata fields supported by the selected host profile.",
    non_compliant:
        "---\nname: reviewer\ndescription: Reviews changes.\nallowed-tools:\n  - Bash\n---\n",
    compliant: "---\nname: reviewer\ndescription: Reviews changes.\ntools:\n  - shell\n---\n",
}];

pub const RULE_METADATA: &[RuleMetadata] = &[
    RuleMetadata {
        id: RuleId::Skill001,
        status: RuleStatus::Active,
        title: "Missing skill name",
        severity: RuleSeverity::Low,
        category: RuleCategory::Spec,
        applicable_profiles: ALL_HOST_PROFILES,
        input_node_types: SKILL_MANIFEST_INPUT,
        rationale: "Skills without stable names are hard to inventory and compare across hosts.",
        remediation: "Add a non-empty `name` field to frontmatter or a clear top-level heading.",
        suppression_guidance:
            "Suppress `SKILL001` only with a documented reason in the project audit config.",
        examples: SKILL001_EXAMPLES,
    },
    RuleMetadata {
        id: RuleId::Skill002,
        status: RuleStatus::Active,
        title: "Missing skill description",
        severity: RuleSeverity::Low,
        category: RuleCategory::Spec,
        applicable_profiles: ALL_HOST_PROFILES,
        input_node_types: SKILL_MANIFEST_INPUT,
        rationale: "Reviewers and host profiles need a concise behavior statement for the skill.",
        remediation: "Add a non-empty `description` field to frontmatter or an opening paragraph.",
        suppression_guidance:
            "Suppress `SKILL002` only with a documented reason in the project audit config.",
        examples: SKILL002_EXAMPLES,
    },
    RuleMetadata {
        id: RuleId::Skill010,
        status: RuleStatus::Active,
        title: "Broken relative reference",
        severity: RuleSeverity::Low,
        category: RuleCategory::Spec,
        applicable_profiles: ALL_HOST_PROFILES,
        input_node_types: RELATIVE_REFERENCE_INPUT,
        rationale:
            "Broken references can make a skill behave differently than documented or fail at runtime.",
        remediation: "Create the referenced file, update the link, or remove the stale reference.",
        suppression_guidance:
            "Suppress `SKILL010` only with a documented reason in the project audit config.",
        examples: SKILL010_EXAMPLES,
    },
    RuleMetadata {
        id: RuleId::Skill020,
        status: RuleStatus::Active,
        title: "Oversized skill manifest",
        severity: RuleSeverity::Low,
        category: RuleCategory::Spec,
        applicable_profiles: ALL_HOST_PROFILES,
        input_node_types: SKILL_MANIFEST_INPUT,
        rationale: "Very large manifests are harder to review and may be rejected or truncated by hosts.",
        remediation: "Move long reference material into `references/` and link to it from SKILL.md.",
        suppression_guidance:
            "Suppress `SKILL020` only with a documented reason in the project audit config.",
        examples: SKILL020_EXAMPLES,
    },
    RuleMetadata {
        id: RuleId::Skill030,
        status: RuleStatus::Active,
        title: "Duplicate skill name",
        severity: RuleSeverity::Low,
        category: RuleCategory::Compatibility,
        applicable_profiles: ALL_HOST_PROFILES,
        input_node_types: SKILL_PACKAGE_INPUT,
        rationale: "Duplicate names make inventory, policy, host routing, and review ambiguous.",
        remediation: "Rename packages so every scanned skill has a unique stable name.",
        suppression_guidance:
            "Suppress `SKILL030` only with a documented reason in the project audit config.",
        examples: SKILL030_EXAMPLES,
    },
    RuleMetadata {
        id: RuleId::Skill040,
        status: RuleStatus::Active,
        title: "Unknown frontmatter field",
        severity: RuleSeverity::Low,
        category: RuleCategory::Compatibility,
        applicable_profiles: ALL_HOST_PROFILES,
        input_node_types: FRONTMATTER_INPUT,
        rationale: "Unknown fields may be ignored, rejected, or interpreted differently by hosts, reducing portability and reviewability.",
        remediation: "Remove the field, move the information into the Markdown body, or wait for documented host profile support.",
        suppression_guidance:
            "Suppress `SKILL040` only with a documented reason in the project audit config.",
        examples: SKILL040_EXAMPLES,
    },
    RuleMetadata {
        id: RuleId::Skill041,
        status: RuleStatus::Active,
        title: "Malformed frontmatter",
        severity: RuleSeverity::Low,
        category: RuleCategory::Spec,
        applicable_profiles: ALL_HOST_PROFILES,
        input_node_types: FRONTMATTER_INPUT,
        rationale: "Malformed frontmatter prevents deterministic extraction of declared metadata and may cause hosts to reject or misread the skill.",
        remediation:
            "Fix the YAML frontmatter syntax, or remove the frontmatter block and rely on Markdown fallbacks.",
        suppression_guidance:
            "Suppress `SKILL041` only with a documented reason in the project audit config.",
        examples: SKILL041_EXAMPLES,
    },
    RuleMetadata {
        id: RuleId::Skill050,
        status: RuleStatus::Active,
        title: "Ignored host-specific metadata",
        severity: RuleSeverity::Low,
        category: RuleCategory::Compatibility,
        applicable_profiles: ALL_HOST_PROFILES,
        input_node_types: FRONTMATTER_INPUT,
        rationale: "Host-specific metadata fields that the selected profile is likely to ignore can create a false sense that tool or permission settings will be enforced.",
        remediation:
            "Use metadata supported by the selected profile, move advisory settings into the Markdown body, or remove fields that the profile marks as ignored.",
        suppression_guidance:
            "Suppress `SKILL050` only when a documented wrapper, host version, or project policy intentionally accepts the ignored metadata, and include that context in the reason.",
        examples: SKILL050_EXAMPLES,
    },
];

pub const RULE_REGISTRY: RuleRegistry = RuleRegistry::new(RULE_METADATA);

pub fn rule_metadata(rule_id: &str) -> Option<&'static RuleMetadata> {
    RULE_REGISTRY.metadata(rule_id)
}

pub fn active_rule_metadata(rule_id: &str) -> Option<&'static RuleMetadata> {
    RULE_REGISTRY
        .metadata(rule_id)
        .filter(|metadata| metadata.status.emits_findings())
}

pub fn rule_counts_as_invalid_manifest(rule_id: &str) -> bool {
    matches!(
        RuleId::parse(rule_id),
        Some(RuleId::Skill001 | RuleId::Skill002 | RuleId::Skill041)
    )
}

pub fn rule_counts_as_broken_reference(rule_id: &str) -> bool {
    matches!(RuleId::parse(rule_id), Some(RuleId::Skill010))
}

/// Portable frontmatter fields accepted by the initial structural scanner.
pub const ACCEPTED_FRONTMATTER_FIELDS: &[&str] = &["name", "description", "tools", "permissions"];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RulePackageFacts {
    pub manifest_path: String,
    pub manifest: RuleManifestFacts,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RuleManifestFacts {
    Parsed(RuleParsedManifestFacts),
    UnreadOversized,
    MalformedFrontmatter(RuleMalformedFrontmatterFact),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuleParsedManifestFacts {
    pub name: Option<String>,
    pub description: Option<String>,
    pub frontmatter_fields: Vec<RuleFrontmatterFieldFact>,
    pub references: Vec<RuleReferenceFact>,
    pub oversized: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuleFrontmatterFieldFact {
    pub name: String,
    pub line: Option<usize>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuleReferenceFact {
    pub target: String,
    pub line: Option<usize>,
    pub exists: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuleMalformedFrontmatterFact {
    pub line: Option<usize>,
    pub parse_message: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvaluatedRuleFinding {
    pub rule_id: RuleId,
    pub message: String,
    pub location: RuleFindingLocation,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuleFindingLocation {
    pub path: String,
    pub line: Option<usize>,
}

pub fn evaluate_structural_rules(packages: &[RulePackageFacts]) -> Vec<EvaluatedRuleFinding> {
    let mut findings = Vec::new();

    for package in packages {
        match &package.manifest {
            RuleManifestFacts::Parsed(manifest) => {
                evaluate_parsed_manifest(package, manifest, &mut findings);
            }
            RuleManifestFacts::UnreadOversized => {
                findings.push(oversized_manifest_finding(&package.manifest_path));
            }
            RuleManifestFacts::MalformedFrontmatter(failure) => {
                findings.push(malformed_frontmatter_finding(
                    &package.manifest_path,
                    failure.line,
                    &failure.parse_message,
                ));
            }
        }
    }

    findings.extend(duplicate_skill_name_findings(packages));
    sort_evaluated_findings(&mut findings);
    findings
}

fn evaluate_parsed_manifest(
    package: &RulePackageFacts,
    manifest: &RuleParsedManifestFacts,
    findings: &mut Vec<EvaluatedRuleFinding>,
) {
    if manifest.name.is_none() {
        findings.push(structural_finding(
            RuleId::Skill001,
            "The skill manifest does not declare a name.",
            &package.manifest_path,
            Some(1),
        ));
    }
    if manifest.description.is_none() {
        findings.push(structural_finding(
            RuleId::Skill002,
            "The skill manifest does not declare a description.",
            &package.manifest_path,
            Some(1),
        ));
    }
    if manifest.oversized {
        findings.push(oversized_manifest_finding(&package.manifest_path));
    }

    for field in manifest
        .frontmatter_fields
        .iter()
        .filter(|field| !ACCEPTED_FRONTMATTER_FIELDS.contains(&field.name.as_str()))
    {
        findings.push(unknown_frontmatter_field_finding(
            &field.name,
            &package.manifest_path,
            field.line.or(Some(1)),
        ));
    }

    for reference in manifest
        .references
        .iter()
        .filter(|reference| reference.exists == Some(false))
    {
        findings.push(structural_finding(
            RuleId::Skill010,
            &format!(
                "The manifest references `{}`, but the file was not found.",
                reference.target
            ),
            &package.manifest_path,
            reference.line,
        ));
    }
}

fn sort_evaluated_findings(findings: &mut [EvaluatedRuleFinding]) {
    findings.sort_by(|left, right| {
        left.location
            .path
            .cmp(&right.location.path)
            .then(left.location.line.cmp(&right.location.line))
            .then(left.rule_id.cmp(&right.rule_id))
            .then(left.message.cmp(&right.message))
    });
}

fn oversized_manifest_finding(path: &str) -> EvaluatedRuleFinding {
    structural_finding(
        RuleId::Skill020,
        "The SKILL.md file exceeds the recommended manifest size.",
        path,
        Some(1),
    )
}

fn malformed_frontmatter_finding(
    path: &str,
    line: Option<usize>,
    parse_message: &str,
) -> EvaluatedRuleFinding {
    structural_finding(
        RuleId::Skill041,
        &format!("The skill manifest frontmatter could not be parsed: {parse_message}."),
        path,
        line.or(Some(1)),
    )
}

fn structural_finding(
    rule_id: RuleId,
    message: &str,
    path: &str,
    line: Option<usize>,
) -> EvaluatedRuleFinding {
    EvaluatedRuleFinding {
        rule_id,
        message: message.to_owned(),
        location: RuleFindingLocation {
            path: path.to_owned(),
            line,
        },
    }
}

fn duplicate_skill_name_findings(packages: &[RulePackageFacts]) -> Vec<EvaluatedRuleFinding> {
    let mut manifest_paths_by_name = BTreeMap::<&str, Vec<&str>>::new();

    for package in packages {
        let RuleManifestFacts::Parsed(manifest) = &package.manifest else {
            continue;
        };
        if let Some(name) = manifest.name.as_deref() {
            manifest_paths_by_name
                .entry(name)
                .or_default()
                .push(package.manifest_path.as_str());
        }
    }

    let mut findings = Vec::new();
    for (name, manifest_paths) in manifest_paths_by_name
        .iter_mut()
        .filter(|(_, manifest_paths)| manifest_paths.len() > 1)
    {
        manifest_paths.sort_unstable();

        for manifest_path in manifest_paths.iter().copied() {
            let other_paths = manifest_paths
                .iter()
                .copied()
                .filter(|other_path| *other_path != manifest_path)
                .map(|other_path| format!("`{other_path}`"))
                .collect::<Vec<_>>()
                .join(", ");

            findings.push(structural_finding(
                RuleId::Skill030,
                &format!(
                    "The skill name `{name}` is also declared by other manifest path(s): {other_paths}."
                ),
                manifest_path,
                Some(1),
            ));
        }
    }

    findings
}

fn unknown_frontmatter_field_finding(
    field: &str,
    path: &str,
    line: Option<usize>,
) -> EvaluatedRuleFinding {
    structural_finding(
        RuleId::Skill040,
        &format!("The manifest declares unsupported frontmatter field `{field}`."),
        path,
        line,
    )
}

pub fn render_rule_documentation() -> String {
    render_rule_documentation_for(&RULE_REGISTRY)
}

pub fn render_rule_documentation_for(registry: &RuleRegistry) -> String {
    let mut markdown = String::new();

    markdown.push_str("# Rules\n\n");
    markdown.push_str(
        "This document is generated from `agent-audit-rules` metadata. Keep rule changes in source and regenerate this file when metadata changes.\n\n",
    );
    markdown.push_str("The initial rule set is intentionally conservative. Rules report deterministic, explainable findings for offline skill audits.\n\n");
    markdown.push_str("Rule status is explicit: `active` rules may emit findings and be suppressed, while `reserved` rules document future rule IDs and are not emitted or accepted in suppression config.\n\n");
    markdown.push_str("## Rule Index\n\n");
    markdown.push_str("| Rule | Status | Severity | Category | Title |\n");
    markdown.push_str("| --- | --- | --- | --- | --- |\n");

    for metadata in registry.rules() {
        markdown.push_str("| [");
        markdown.push_str(metadata.id.as_str());
        markdown.push_str("](#");
        markdown.push_str(&rule_anchor(metadata));
        markdown.push_str(") | `");
        markdown.push_str(metadata.status.as_str());
        markdown.push_str("` | `");
        markdown.push_str(metadata.severity.as_str());
        markdown.push_str("` | `");
        markdown.push_str(metadata.category.as_str());
        markdown.push_str("` | ");
        markdown.push_str(metadata.title);
        markdown.push_str(" |\n");
    }

    for metadata in registry.rules() {
        markdown.push('\n');
        markdown.push_str("## ");
        markdown.push_str(metadata.id.as_str());
        markdown.push_str(": ");
        markdown.push_str(metadata.title);
        markdown.push_str("\n\n");
        markdown.push_str("- Status: `");
        markdown.push_str(metadata.status.as_str());
        markdown.push_str("`");
        if !metadata.status.emits_findings() {
            markdown.push_str(" (reserved; not emitted)");
        }
        markdown.push('\n');
        markdown.push_str("- Severity: `");
        markdown.push_str(metadata.severity.as_str());
        markdown.push_str("`\n");
        markdown.push_str("- Category: `");
        markdown.push_str(metadata.category.as_str());
        markdown.push_str("`\n");
        markdown.push_str("- Applies to: ");
        push_backticked_list(
            &mut markdown,
            metadata
                .applicable_profiles
                .iter()
                .map(|profile| profile.as_str()),
        );
        markdown.push('\n');
        markdown.push_str("- Input nodes: ");
        push_backticked_list(
            &mut markdown,
            metadata.input_node_types.iter().map(|node| node.as_str()),
        );
        markdown.push_str("\n\n");
        markdown.push_str("### Why It Matters\n\n");
        markdown.push_str(metadata.rationale);
        markdown.push_str("\n\n");
        markdown.push_str("### How To Fix\n\n");
        markdown.push_str(metadata.remediation);
        markdown.push_str("\n\n");
        markdown.push_str("### Safe Suppression\n\n");
        markdown.push_str(metadata.suppression_guidance);
        markdown.push_str("\n\n");
        markdown.push_str("### Examples\n");

        for example in metadata.examples {
            markdown.push('\n');
            markdown.push_str(example.summary);
            markdown.push_str("\n\n");
            markdown.push_str("Non-compliant:\n\n");
            push_fenced_block(&mut markdown, example.non_compliant);
            markdown.push('\n');
            markdown.push_str("Compliant:\n\n");
            push_fenced_block(&mut markdown, example.compliant);
        }
    }

    markdown
}

fn rule_anchor(metadata: &RuleMetadata) -> String {
    let mut anchor = metadata.id.as_str().to_ascii_lowercase();
    anchor.push('-');

    for character in metadata.title.chars() {
        if character.is_ascii_alphanumeric() {
            anchor.push(character.to_ascii_lowercase());
        } else if !anchor.ends_with('-') {
            anchor.push('-');
        }
    }

    anchor.trim_end_matches('-').to_owned()
}

fn push_backticked_list<'a>(markdown: &mut String, values: impl Iterator<Item = &'a str>) {
    for (index, value) in values.enumerate() {
        if index > 0 {
            markdown.push_str(", ");
        }
        markdown.push('`');
        markdown.push_str(value);
        markdown.push('`');
    }
}

fn push_fenced_block(markdown: &mut String, content: &str) {
    markdown.push_str("```text\n");
    markdown.push_str(content);
    if !content.ends_with('\n') {
        markdown.push('\n');
    }
    markdown.push_str("```\n");
}

#[cfg(test)]
mod tests {
    use super::*;

    fn normalize_line_endings(value: &str) -> String {
        value.replace("\r\n", "\n")
    }

    #[test]
    fn structural_rule_ids_cover_current_implemented_rules() {
        assert_eq!(
            STRUCTURAL_RULE_IDS,
            &["SKILL001", "SKILL002", "SKILL010", "SKILL020", "SKILL030", "SKILL040", "SKILL041",]
        );
    }

    #[test]
    fn structural_rule_ids_are_active_metadata_in_deterministic_order() {
        let structural_metadata_ids = STRUCTURAL_RULE_IDS
            .iter()
            .map(|rule_id| {
                active_rule_metadata(rule_id)
                    .expect("structural rule must be active")
                    .id
                    .as_str()
            })
            .collect::<Vec<_>>();

        assert_eq!(structural_metadata_ids, STRUCTURAL_RULE_IDS);
        assert!(
            structural_metadata_ids
                .windows(2)
                .all(|ids| ids[0] < ids[1]),
            "structural rule ids must remain sorted"
        );
    }

    #[test]
    fn metadata_covers_active_rule_ids_in_deterministic_order() {
        let active_metadata_ids = RULE_REGISTRY
            .rules()
            .iter()
            .filter(|metadata| metadata.status == RuleStatus::Active)
            .map(|metadata| metadata.id.as_str())
            .collect::<Vec<_>>();

        assert_eq!(active_metadata_ids, ACTIVE_RULE_IDS);
        assert!(active_metadata_ids.windows(2).all(|ids| ids[0] < ids[1]));
    }

    #[test]
    fn registry_rules_are_unique_sorted_and_include_reserved_metadata() {
        let registry_ids = RULE_REGISTRY
            .rules()
            .iter()
            .map(|metadata| metadata.id.as_str())
            .collect::<Vec<_>>();

        assert_eq!(
            registry_ids,
            vec![
                RuleId::Skill001.as_str(),
                RuleId::Skill002.as_str(),
                RuleId::Skill010.as_str(),
                RuleId::Skill020.as_str(),
                RuleId::Skill030.as_str(),
                RuleId::Skill040.as_str(),
                RuleId::Skill041.as_str(),
                RuleId::Skill050.as_str(),
            ]
        );
        assert!(
            registry_ids.windows(2).all(|ids| ids[0] < ids[1]),
            "registry ids must remain sorted for deterministic output and binary lookup"
        );
        assert!(
            registry_ids.windows(2).all(|ids| ids[0] != ids[1]),
            "registry ids must be unique"
        );
    }

    #[test]
    fn active_and_reserved_rule_ids_are_explicit_and_deterministic() {
        let active_ids = RULE_REGISTRY
            .rules()
            .iter()
            .filter(|metadata| metadata.status == RuleStatus::Active)
            .map(|metadata| metadata.id.as_str())
            .collect::<Vec<_>>();
        let reserved_ids = RULE_REGISTRY
            .rules()
            .iter()
            .filter(|metadata| metadata.status == RuleStatus::Reserved)
            .map(|metadata| metadata.id.as_str())
            .collect::<Vec<_>>();

        assert_eq!(active_ids, ACTIVE_RULE_IDS);
        assert_eq!(reserved_ids, RESERVED_RULE_IDS);
        assert!(active_ids.windows(2).all(|ids| ids[0] < ids[1]));
        assert!(reserved_ids.windows(2).all(|ids| ids[0] < ids[1]));
    }

    #[test]
    fn registry_repeated_calls_are_stable() {
        let first_rules = RULE_REGISTRY.rules();
        let second_rules = RULE_REGISTRY.rules();

        assert_eq!(first_rules, second_rules);
        assert_eq!(first_rules.as_ptr(), second_rules.as_ptr());
        assert_eq!(
            RULE_REGISTRY.metadata("SKILL030"),
            RULE_REGISTRY.metadata("SKILL030")
        );
    }

    #[test]
    fn metadata_required_fields_are_present() {
        for metadata in RULE_REGISTRY.rules() {
            assert!(!metadata.id.as_str().is_empty(), "missing id");
            assert!(
                !metadata.title.is_empty(),
                "missing title for {}",
                metadata.id.as_str()
            );
            assert!(
                !metadata.applicable_profiles.is_empty(),
                "missing applicable profiles for {}",
                metadata.id.as_str()
            );
            assert!(
                !metadata.input_node_types.is_empty(),
                "missing input node types for {}",
                metadata.id.as_str()
            );
            assert!(
                !metadata.rationale.is_empty(),
                "missing rationale for {}",
                metadata.id.as_str()
            );
            assert!(
                !metadata.remediation.is_empty(),
                "missing remediation for {}",
                metadata.id.as_str()
            );
            assert!(
                !metadata.suppression_guidance.is_empty(),
                "missing suppression guidance for {}",
                metadata.id.as_str()
            );
            assert!(
                metadata.suppression_guidance.contains(metadata.id.as_str()),
                "suppression guidance must name {}",
                metadata.id.as_str()
            );
            assert!(
                !metadata.examples.is_empty(),
                "missing examples for {}",
                metadata.id.as_str()
            );

            for example in metadata.examples {
                assert!(
                    !example.summary.is_empty(),
                    "missing example summary for {}",
                    metadata.id.as_str()
                );
                assert!(
                    !example.non_compliant.is_empty(),
                    "missing non-compliant example for {}",
                    metadata.id.as_str()
                );
                assert!(
                    !example.compliant.is_empty(),
                    "missing compliant example for {}",
                    metadata.id.as_str()
                );
            }
        }
    }

    #[test]
    fn metadata_severity_and_category_match_current_scanner_behavior() {
        let expected = [
            ("SKILL001", RuleSeverity::Low, RuleCategory::Spec),
            ("SKILL002", RuleSeverity::Low, RuleCategory::Spec),
            ("SKILL010", RuleSeverity::Low, RuleCategory::Spec),
            ("SKILL020", RuleSeverity::Low, RuleCategory::Spec),
            ("SKILL030", RuleSeverity::Low, RuleCategory::Compatibility),
            ("SKILL040", RuleSeverity::Low, RuleCategory::Compatibility),
            ("SKILL041", RuleSeverity::Low, RuleCategory::Spec),
            ("SKILL050", RuleSeverity::Low, RuleCategory::Compatibility),
        ];

        for (rule_id, severity, category) in expected {
            let metadata = rule_metadata(rule_id).expect("metadata exists");
            assert_eq!(metadata.severity, severity, "{rule_id} severity");
            assert_eq!(metadata.category, category, "{rule_id} category");
        }
    }

    #[test]
    fn metadata_lookup_is_first_class_and_rejects_unknown_ids() {
        assert_eq!(
            rule_metadata("SKILL030").map(|metadata| metadata.title),
            Some("Duplicate skill name")
        );
        assert_eq!(
            RULE_REGISTRY
                .metadata("SKILL030")
                .map(|metadata| metadata.title),
            Some("Duplicate skill name")
        );
        assert!(rule_metadata("SEC001").is_none());
        assert!(RULE_REGISTRY.metadata("SEC001").is_none());
    }

    #[test]
    fn active_metadata_lookup_accepts_active_and_rejects_unknown_ids() {
        assert_eq!(
            active_rule_metadata("SKILL040").map(|metadata| metadata.title),
            Some("Unknown frontmatter field")
        );
        assert_eq!(
            rule_metadata("SKILL050").map(|metadata| metadata.status),
            Some(RuleStatus::Active)
        );
        assert_eq!(
            active_rule_metadata("SKILL050").map(|metadata| metadata.title),
            Some("Ignored host-specific metadata")
        );
        assert!(active_rule_metadata("SEC001").is_none());
    }

    #[test]
    fn summary_classification_helpers_are_rule_owned() {
        assert!(rule_counts_as_invalid_manifest("SKILL001"));
        assert!(rule_counts_as_invalid_manifest("SKILL002"));
        assert!(rule_counts_as_invalid_manifest("SKILL041"));
        assert!(!rule_counts_as_invalid_manifest("SKILL010"));
        assert!(!rule_counts_as_invalid_manifest("SEC001"));
        assert!(rule_counts_as_broken_reference("SKILL010"));
        assert!(!rule_counts_as_broken_reference("SKILL001"));
        assert!(!rule_counts_as_broken_reference("SEC001"));
    }

    #[test]
    fn skill001_reports_missing_name() {
        let packages = vec![parsed_manifest_package(
            "missing-name/SKILL.md",
            RuleParsedManifestFacts {
                name: None,
                description: Some("Reviews pull requests.".to_owned()),
                frontmatter_fields: Vec::new(),
                references: Vec::new(),
                oversized: false,
            },
        )];

        let findings = evaluate_structural_rules(&packages);

        assert_eq!(
            findings,
            vec![finding(
                RuleId::Skill001,
                "The skill manifest does not declare a name.",
                "missing-name/SKILL.md",
                Some(1)
            )]
        );
    }

    #[test]
    fn skill002_reports_missing_description() {
        let packages = vec![parsed_manifest_package(
            "missing-description/SKILL.md",
            RuleParsedManifestFacts {
                name: Some("reviewer".to_owned()),
                description: None,
                frontmatter_fields: Vec::new(),
                references: Vec::new(),
                oversized: false,
            },
        )];

        let findings = evaluate_structural_rules(&packages);

        assert_eq!(
            findings,
            vec![finding(
                RuleId::Skill002,
                "The skill manifest does not declare a description.",
                "missing-description/SKILL.md",
                Some(1)
            )]
        );
    }

    #[test]
    fn skill010_reports_broken_relative_reference() {
        let packages = vec![parsed_manifest_package(
            "broken-reference/SKILL.md",
            RuleParsedManifestFacts {
                name: Some("reviewer".to_owned()),
                description: Some("Reviews pull requests.".to_owned()),
                frontmatter_fields: Vec::new(),
                references: vec![RuleReferenceFact {
                    target: "references/missing.md".to_owned(),
                    line: Some(9),
                    exists: Some(false),
                }],
                oversized: false,
            },
        )];

        let findings = evaluate_structural_rules(&packages);

        assert_eq!(
            findings,
            vec![finding(
                RuleId::Skill010,
                "The manifest references `references/missing.md`, but the file was not found.",
                "broken-reference/SKILL.md",
                Some(9)
            )]
        );
    }

    #[test]
    fn skill020_reports_oversized_manifest() {
        let packages = vec![parsed_manifest_package(
            "oversized/SKILL.md",
            RuleParsedManifestFacts {
                name: Some("reviewer".to_owned()),
                description: Some("Reviews pull requests.".to_owned()),
                frontmatter_fields: Vec::new(),
                references: Vec::new(),
                oversized: true,
            },
        )];

        let findings = evaluate_structural_rules(&packages);

        assert_eq!(
            findings,
            vec![finding(
                RuleId::Skill020,
                "The SKILL.md file exceeds the recommended manifest size.",
                "oversized/SKILL.md",
                Some(1)
            )]
        );
    }

    #[test]
    fn skill030_reports_duplicate_skill_names() {
        let packages = vec![
            parsed_package("beta/SKILL.md", Some("duplicate")),
            parsed_package("alpha/SKILL.md", Some("duplicate")),
            parsed_package("unique/SKILL.md", Some("unique")),
        ];

        let findings = evaluate_structural_rules(&packages);

        assert_eq!(
            findings,
            vec![
                finding(
                    RuleId::Skill030,
                    "The skill name `duplicate` is also declared by other manifest path(s): `beta/SKILL.md`.",
                    "alpha/SKILL.md",
                    Some(1),
                ),
                finding(
                    RuleId::Skill030,
                    "The skill name `duplicate` is also declared by other manifest path(s): `alpha/SKILL.md`.",
                    "beta/SKILL.md",
                    Some(1),
                ),
            ]
        );
    }

    #[test]
    fn skill040_reports_unknown_frontmatter_field() {
        let packages = vec![parsed_manifest_package(
            "unknown-field/SKILL.md",
            RuleParsedManifestFacts {
                name: Some("reviewer".to_owned()),
                description: Some("Reviews pull requests.".to_owned()),
                frontmatter_fields: vec![RuleFrontmatterFieldFact {
                    name: "owner".to_owned(),
                    line: Some(4),
                }],
                references: Vec::new(),
                oversized: false,
            },
        )];

        let findings = evaluate_structural_rules(&packages);

        assert_eq!(
            findings,
            vec![finding(
                RuleId::Skill040,
                "The manifest declares unsupported frontmatter field `owner`.",
                "unknown-field/SKILL.md",
                Some(4)
            )]
        );
    }

    #[test]
    fn skill041_reports_malformed_frontmatter() {
        let packages = vec![RulePackageFacts {
            manifest_path: "malformed/SKILL.md".to_owned(),
            manifest: RuleManifestFacts::MalformedFrontmatter(RuleMalformedFrontmatterFact {
                line: Some(2),
                parse_message: "invalid YAML at line 2".to_owned(),
            }),
        }];

        let findings = evaluate_structural_rules(&packages);

        assert_eq!(
            findings,
            vec![finding(
                RuleId::Skill041,
                "The skill manifest frontmatter could not be parsed: invalid YAML at line 2.",
                "malformed/SKILL.md",
                Some(2)
            )]
        );
    }

    #[test]
    fn valid_package_facts_do_not_report_structural_findings() {
        let packages = vec![
            parsed_manifest_package(
                "alpha/SKILL.md",
                RuleParsedManifestFacts {
                    name: Some("alpha".to_owned()),
                    description: Some("Reviews pull requests.".to_owned()),
                    frontmatter_fields: vec![
                        RuleFrontmatterFieldFact {
                            name: "name".to_owned(),
                            line: Some(2),
                        },
                        RuleFrontmatterFieldFact {
                            name: "description".to_owned(),
                            line: Some(3),
                        },
                        RuleFrontmatterFieldFact {
                            name: "tools".to_owned(),
                            line: Some(4),
                        },
                        RuleFrontmatterFieldFact {
                            name: "permissions".to_owned(),
                            line: Some(5),
                        },
                    ],
                    references: vec![
                        RuleReferenceFact {
                            target: "references/guide.md".to_owned(),
                            line: Some(9),
                            exists: Some(true),
                        },
                        RuleReferenceFact {
                            target: "references/deferred.md".to_owned(),
                            line: Some(10),
                            exists: None,
                        },
                    ],
                    oversized: false,
                },
            ),
            parsed_package("beta/SKILL.md", Some("beta")),
        ];

        let findings = evaluate_structural_rules(&packages);

        assert!(findings.is_empty());
    }

    #[test]
    fn structural_findings_are_sorted_by_path_location_rule_id_and_message() {
        let packages = vec![
            parsed_manifest_package(
                "zeta/SKILL.md",
                RuleParsedManifestFacts {
                    name: None,
                    description: None,
                    frontmatter_fields: Vec::new(),
                    references: Vec::new(),
                    oversized: false,
                },
            ),
            parsed_manifest_package(
                "alpha/SKILL.md",
                RuleParsedManifestFacts {
                    name: Some("alpha".to_owned()),
                    description: Some("Reviews pull requests.".to_owned()),
                    frontmatter_fields: vec![
                        RuleFrontmatterFieldFact {
                            name: "zeta".to_owned(),
                            line: Some(4),
                        },
                        RuleFrontmatterFieldFact {
                            name: "alpha".to_owned(),
                            line: Some(4),
                        },
                    ],
                    references: vec![RuleReferenceFact {
                        target: "references/missing.md".to_owned(),
                        line: Some(2),
                        exists: Some(false),
                    }],
                    oversized: false,
                },
            ),
        ];

        let findings = evaluate_structural_rules(&packages);

        assert_eq!(
            finding_projection(&findings),
            vec![
                (RuleId::Skill010, "alpha/SKILL.md", Some(2)),
                (RuleId::Skill040, "alpha/SKILL.md", Some(4)),
                (RuleId::Skill040, "alpha/SKILL.md", Some(4)),
                (RuleId::Skill001, "zeta/SKILL.md", Some(1)),
                (RuleId::Skill002, "zeta/SKILL.md", Some(1)),
            ]
        );
        assert!(findings[1].message < findings[2].message);
    }

    #[test]
    fn evaluator_reports_parsed_manifest_structural_findings_without_filesystem() {
        let packages = vec![RulePackageFacts {
            manifest_path: "skill/SKILL.md".to_owned(),
            manifest: RuleManifestFacts::Parsed(RuleParsedManifestFacts {
                name: None,
                description: None,
                frontmatter_fields: vec![RuleFrontmatterFieldFact {
                    name: "owner".to_owned(),
                    line: Some(3),
                }],
                references: vec![RuleReferenceFact {
                    target: "references/missing.md".to_owned(),
                    line: Some(7),
                    exists: Some(false),
                }],
                oversized: true,
            }),
        }];

        let findings = evaluate_structural_rules(&packages);

        assert_eq!(
            finding_projection(&findings),
            vec![
                (RuleId::Skill001, "skill/SKILL.md", Some(1)),
                (RuleId::Skill002, "skill/SKILL.md", Some(1)),
                (RuleId::Skill020, "skill/SKILL.md", Some(1)),
                (RuleId::Skill040, "skill/SKILL.md", Some(3)),
                (RuleId::Skill010, "skill/SKILL.md", Some(7)),
            ]
        );
        assert!(findings[3].message.contains("`owner`"));
        assert!(findings[4].message.contains("references/missing.md"));
    }

    #[test]
    fn evaluator_reports_only_size_for_unread_oversized_manifest() {
        let packages = vec![RulePackageFacts {
            manifest_path: "SKILL.md".to_owned(),
            manifest: RuleManifestFacts::UnreadOversized,
        }];

        let findings = evaluate_structural_rules(&packages);

        assert_eq!(
            finding_projection(&findings),
            vec![(RuleId::Skill020, "SKILL.md", Some(1))]
        );
    }

    #[test]
    fn evaluator_reports_only_parse_failure_for_malformed_frontmatter() {
        let packages = vec![RulePackageFacts {
            manifest_path: "SKILL.md".to_owned(),
            manifest: RuleManifestFacts::MalformedFrontmatter(RuleMalformedFrontmatterFact {
                line: Some(3),
                parse_message: "invalid YAML at line 3".to_owned(),
            }),
        }];

        let findings = evaluate_structural_rules(&packages);

        assert_eq!(
            finding_projection(&findings),
            vec![(RuleId::Skill041, "SKILL.md", Some(3))]
        );
        assert_eq!(
            findings[0].message,
            "The skill manifest frontmatter could not be parsed: invalid YAML at line 3."
        );
    }

    #[test]
    fn rendered_rule_documentation_is_deterministic_and_complete() {
        let first_render = render_rule_documentation();
        let second_render = render_rule_documentation();

        assert_eq!(first_render, second_render);
        assert!(first_render.ends_with('\n'));
        assert!(first_render.contains("## Rule Index"));
        assert!(first_render.contains("| Rule | Status | Severity | Category | Title |"));
        assert!(first_render.contains("| [SKILL050](#skill050-ignored-host-specific-metadata) | `active` | `low` | `compatibility` | Ignored host-specific metadata |"));
        assert!(first_render.contains("- Status: `active`"));

        for metadata in RULE_REGISTRY.rules() {
            assert!(first_render.contains(metadata.id.as_str()));
            assert!(first_render.contains(metadata.title));
            assert!(first_render.contains(metadata.rationale));
            assert!(first_render.contains(metadata.remediation));
            assert!(first_render.contains(metadata.suppression_guidance));
        }
    }

    #[test]
    fn checked_in_rule_documentation_matches_generated_markdown() {
        let checked_in = normalize_line_endings(include_str!("../../../docs/rules/README.md"));
        let generated = render_rule_documentation();

        assert_eq!(
            checked_in, generated,
            "docs/rules/README.md has drifted from agent-audit-rules metadata"
        );
    }

    fn parsed_manifest_package(path: &str, manifest: RuleParsedManifestFacts) -> RulePackageFacts {
        RulePackageFacts {
            manifest_path: path.to_owned(),
            manifest: RuleManifestFacts::Parsed(manifest),
        }
    }

    fn parsed_package(path: &str, name: Option<&str>) -> RulePackageFacts {
        RulePackageFacts {
            manifest_path: path.to_owned(),
            manifest: RuleManifestFacts::Parsed(RuleParsedManifestFacts {
                name: name.map(str::to_owned),
                description: Some("Description.".to_owned()),
                frontmatter_fields: Vec::new(),
                references: Vec::new(),
                oversized: false,
            }),
        }
    }

    fn finding(
        rule_id: RuleId,
        message: &str,
        path: &str,
        line: Option<usize>,
    ) -> EvaluatedRuleFinding {
        EvaluatedRuleFinding {
            rule_id,
            message: message.to_owned(),
            location: RuleFindingLocation {
                path: path.to_owned(),
                line,
            },
        }
    }

    fn finding_projection(findings: &[EvaluatedRuleFinding]) -> Vec<(RuleId, &str, Option<usize>)> {
        findings
            .iter()
            .map(|finding| {
                (
                    finding.rule_id,
                    finding.location.path.as_str(),
                    finding.location.line,
                )
            })
            .collect()
    }
}
