// SPDX-License-Identifier: Apache-2.0

use serde::{Deserialize, Serialize};

pub const HOST_PROFILES: &[&str] = &[
    "agent-skills-spec",
    "claude-code",
    "codex",
    "github-copilot",
    "vscode-copilot",
    "generic",
];

macro_rules! host_profile {
    (
        $id:expr,
        $display_name:expr,
        $required_fields:expr,
        $accepted_optional_fields:expr,
        $known_ignored_fields:expr,
        $metadata_fields:expr,
        $metadata_namespaces:expr,
        $path_conventions:expr,
        $recommended_manifest_size_limit:expr,
        $tool_expectation:expr,
        $script_support:expr,
        $artifact_support:expr,
        $known_incompatibilities:expr,
        $warnings:expr,
        $documentation_notes:expr $(,)?
    ) => {
        host_profile(HostProfileDefinition {
            id: $id,
            display_name: $display_name,
            required_fields: $required_fields,
            accepted_optional_fields: $accepted_optional_fields,
            known_ignored_fields: $known_ignored_fields,
            metadata_fields: $metadata_fields,
            metadata_namespaces: $metadata_namespaces,
            path_conventions: $path_conventions,
            recommended_manifest_size_limit: $recommended_manifest_size_limit,
            tool_expectation: $tool_expectation,
            script_support: $script_support,
            artifact_support: $artifact_support,
            known_incompatibilities: $known_incompatibilities,
            warnings: $warnings,
            documentation_notes: $documentation_notes,
        })
    };
}

macro_rules! name_description_tools_profile {
    (
        id: $id:expr,
        display_name: $display_name:expr,
        name: $name_description:expr,
        description: $description_description:expr,
        tools: $tools_description:expr,
        ignored_allowed_tools: $ignored_allowed_tools_description:expr,
        metadata_fields: $metadata_fields:expr,
        metadata_namespaces: $metadata_namespaces:expr,
        path_conventions: $path_conventions:expr,
        manifest_size_limit: $recommended_manifest_size_limit:expr,
        capabilities: ($tool_expectation:expr, $script_support:expr, $artifact_support:expr $(,)?),
        known_incompatibilities: $known_incompatibilities:expr,
        warnings: $warnings:expr,
        documentation_notes: $documentation_notes:expr $(,)?
    ) => {
        host_profile!(
            $id,
            $display_name,
            &[manifest_field("name", $name_description)],
            &[
                manifest_field("description", $description_description),
                manifest_field("tools", $tools_description),
            ],
            &[manifest_field(
                "allowed-tools",
                $ignored_allowed_tools_description,
            )],
            $metadata_fields,
            $metadata_namespaces,
            $path_conventions,
            $recommended_manifest_size_limit,
            $tool_expectation,
            $script_support,
            $artifact_support,
            $known_incompatibilities,
            $warnings,
            $documentation_notes,
        )
    };
}

pub const HOST_PROFILE_DEFINITIONS: &[HostProfile] = &[
    host_profile!(
        "agent-skills-spec",
        "Agent Skills Specification",
        &[
            manifest_field(
                "name",
                "Stable skill name declared in SKILL.md frontmatter.",
            ),
            manifest_field(
                "description",
                "Short human-readable summary of the skill behavior.",
            ),
        ],
        &[],
        &[manifest_field(
            "license",
            "License metadata is useful to auditors but not part of the base skill contract.",
        )],
        &[metadata_field(
            "tools",
            None,
            "Optional declaration of tools the skill expects an agent to provide.",
        )],
        &["agent-skills"],
        &[
            path_convention(
                "SKILL.md",
                "Manifest and instructions live in the root of each skill directory.",
            ),
            path_convention(
                "scripts/",
                "Referenced scripts are colocated under the skill directory.",
            ),
            path_convention(
                "references/",
                "Large supporting documents are stored outside the manifest body.",
            ),
            path_convention(
                "assets/",
                "Images and other static assets are stored with the skill package.",
            ),
        ],
        manifest_size_limit(
            32 * 1024,
            "Keep SKILL.md concise enough for agents to load without truncation.",
        ),
        expectation(
            "Tools should be declared when the skill depends on agent capabilities.",
            &["Undeclared tools may still work on permissive hosts but reduce portability."],
        ),
        expectation(
            "Scripts may be packaged but should not be executed unless an agent explicitly allows them.",
            &["Static analysis should treat scripts as inert artifacts by default."],
        ),
        expectation(
            "scripts/, references/, and assets/ are expected package artifacts.",
            &["Referenced artifacts should use relative paths inside the skill directory."],
        ),
        &[notice(
            "SPEC001",
            "Host-specific metadata may be ignored by strict spec consumers.",
        )],
        &[notice(
            "SPEC-W001",
            "Oversized manifests can be truncated or skipped by context-limited agents.",
        )],
        &["Use this profile as the portable baseline for deterministic skill package checks."],
    ),
    host_profile!(
        "claude-code",
        "Claude Code",
        &[manifest_field("name", "Skill name used to identify the package.")],
        &[
            manifest_field(
                "description",
                "Description used by agents and reviewers to understand when to use the skill.",
            ),
            manifest_field(
                "allowed-tools",
                "Host-specific allowlist of tools the skill may request.",
            ),
        ],
        &[manifest_field(
            "tools",
            "Portable tool declarations may be ignored in favor of host-specific tool allowlists.",
        )],
        &[metadata_field(
            "allowed-tools",
            Some("claude"),
            "Claude-style tool permission declaration.",
        )],
        &["claude", "anthropic"],
        &[
            path_convention(
                ".claude/skills/**/SKILL.md",
                "Claude-specific skill discovery path.",
            ),
            path_convention(
                "SKILL.md",
                "Each skill package is rooted at a manifest file.",
            ),
            path_convention("scripts/", "Optional scripts referenced by the skill."),
            path_convention("references/", "Optional supporting reference material."),
        ],
        manifest_size_limit(
            32 * 1024,
            "Keep host instructions compact enough for reliable agent loading.",
        ),
        expectation(
            "Tool declarations should use the host allowlist format when present.",
            &["Portable declarations are useful documentation but may not control host permissions."],
        ),
        expectation(
            "Scripts are supported as packaged references, with execution controlled by the host.",
            &["Audits must not assume scripts execute automatically."],
        ),
        expectation(
            "References and scripts may be bundled with the skill.",
            &["Relative references should remain inside the skill directory."],
        ),
        &[notice("CLAUDE001", "Non-Claude metadata namespaces may be ignored.")],
        &[notice(
            "CLAUDE-W001",
            "Broad tool allowlists reduce reviewability and portability.",
        )],
        &["Model this profile around Claude Code skill packaging and permission metadata."],
    ),
    name_description_tools_profile!(
        id: "codex",
        display_name: "Codex",
        name: "Skill name used by Codex to present available skills.",
        description: "Description that explains when Codex should apply the skill.",
        tools: "Tool or capability hints documented by the package.",
        ignored_allowed_tools: "Claude-style allowlists may be documentation only for Codex.",
        metadata_fields: &[metadata_field(
            "tools",
            Some("codex"),
            "Codex-facing capability declarations when present.",
        )],
        metadata_namespaces: &["codex", "openai"],
        path_conventions: &[
            path_convention(
                ".agents/skills/**/SKILL.md",
                "Agent skill discovery path used by Codex-style packages.",
            ),
            path_convention("SKILL.md", "Root manifest for the skill package."),
            path_convention("scripts/", "Helper scripts shipped with the skill."),
            path_convention(
                "assets/",
                "Images and static files referenced by instructions.",
            ),
        ],
        manifest_size_limit: manifest_size_limit(
            32 * 1024,
            "Keep instructions short enough to fit predictable context budgets.",
        ),
        capabilities: (
            expectation(
                "Tool needs should be documented explicitly and treated as host-mediated capabilities.",
                &["Tool declarations do not imply automatic access."],
            ),
            expectation(
                "Scripts can be included as artifacts, but execution is host-mediated and should be reviewed.",
                &["Auditors should inspect scripts without running them."],
            ),
            expectation(
                "scripts/, references/, and assets/ are supported package conventions.",
                &["Artifact links should be relative and deterministic."],
            ),
        ),
        known_incompatibilities: &[notice(
            "CODEX001",
            "Claude-only permission metadata may not be enforced.",
        )],
        warnings: &[notice(
            "CODEX-W001",
            "Skills that require network access or script execution are less portable.",
        )],
        documentation_notes: &["Use this profile for Codex-compatible offline skill package review."],
    ),
    name_description_tools_profile!(
        id: "github-copilot",
        display_name: "GitHub Copilot",
        name: "Skill or instruction package name.",
        description: "Summary used by reviewers to understand intended behavior.",
        tools: "Documented tool expectations for environments that expose them.",
        ignored_allowed_tools: "Host may ignore explicit tool allowlists embedded in skill metadata.",
        metadata_fields: &[metadata_field(
            "github",
            Some("github"),
            "GitHub-specific metadata namespace for future compatibility checks.",
        )],
        metadata_namespaces: &["github", "copilot"],
        path_conventions: &[
            path_convention(
                ".github/skills/**/SKILL.md",
                "Repository-scoped GitHub skill discovery path.",
            ),
            path_convention("SKILL.md", "Portable skill manifest location."),
            path_convention(
                "references/",
                "Reference material packaged with the skill.",
            ),
        ],
        manifest_size_limit: manifest_size_limit(
            24 * 1024,
            "Prefer compact repository instructions for predictable host consumption.",
        ),
        capabilities: (
            expectation(
                "Tool expectations should be documented but may not map to explicit host permissions.",
                &["Repository context and available tools vary by host surface."],
            ),
            expectation(
                "Scripts should be treated as reviewable artifacts, not automatically supported actions.",
                &["CI and local developer environments may differ."],
            ),
            expectation(
                "Reference files are useful; executable artifacts require careful review.",
                &["Keep package references repository-relative."],
            ),
        ),
        known_incompatibilities: &[notice(
            "GHCOPILOT001",
            "Skill packages that depend on explicit host tool allowlists may not transfer directly.",
        )],
        warnings: &[notice(
            "GHCOPILOT-W001",
            "Repository-specific assumptions can reduce portability across Copilot surfaces.",
        )],
        documentation_notes: &["Use this profile for GitHub-hosted skill package compatibility notes."],
    ),
    name_description_tools_profile!(
        id: "vscode-copilot",
        display_name: "VS Code Copilot",
        name: "Skill or instruction package name.",
        description: "Summary of when the skill should apply.",
        tools: "Documented local tool expectations.",
        ignored_allowed_tools: "Host-specific allowlists from other agents may be ignored.",
        metadata_fields: &[metadata_field(
            "vscode",
            Some("vscode"),
            "VS Code specific metadata namespace for future compatibility checks.",
        )],
        metadata_namespaces: &["vscode", "copilot"],
        path_conventions: &[
            path_convention(
                ".github/skills/**/SKILL.md",
                "Repository skill path often shared with Copilot workflows.",
            ),
            path_convention("SKILL.md", "Portable skill manifest location."),
            path_convention("assets/", "Static assets referenced by the skill."),
        ],
        manifest_size_limit: manifest_size_limit(
            24 * 1024,
            "Keep local editor instructions compact and scannable.",
        ),
        capabilities: (
            expectation(
                "Local tool expectations should be described rather than assumed.",
                &["Available editor tools depend on extensions, workspace trust, and user configuration."],
            ),
            expectation(
                "Scripts are local artifacts and should require explicit user or host action.",
                &["Workspace trust and shell availability affect script behavior."],
            ),
            expectation(
                "References and assets can be useful when paths remain workspace-relative.",
                &["Absolute local paths reduce portability."],
            ),
        ),
        known_incompatibilities: &[notice(
            "VSCOPILOT001",
            "Workspace-specific assumptions may not hold outside VS Code.",
        )],
        warnings: &[notice(
            "VSCOPILOT-W001",
            "Local shell or extension dependencies should be documented explicitly.",
        )],
        documentation_notes: &["Use this profile for editor-oriented Copilot compatibility checks."],
    ),
    name_description_tools_profile!(
        id: "generic",
        display_name: "Generic Agent",
        name: "Portable skill name.",
        description: "Portable description of skill behavior.",
        tools: "Optional human-readable tool expectations.",
        ignored_allowed_tools: "Host-specific tool permission fields may be ignored by generic agents.",
        metadata_fields: &[metadata_field(
            "metadata",
            None,
            "Unrecognized metadata should be treated conservatively.",
        )],
        metadata_namespaces: &["generic"],
        path_conventions: &[
            path_convention(
                "**/SKILL.md",
                "Discover skill manifests regardless of host-specific parent directory.",
            ),
            path_convention(
                "references/",
                "Reference material remains optional and package-relative.",
            ),
            path_convention("assets/", "Static assets remain optional and package-relative."),
        ],
        manifest_size_limit: manifest_size_limit(
            16 * 1024,
            "Use a conservative manifest size for broad agent portability.",
        ),
        capabilities: (
            expectation(
                "Tool requirements should be documented as assumptions, not guarantees.",
                &["Generic agents may not expose matching tools or permission controls."],
            ),
            expectation(
                "Do not assume script execution support.",
                &["Generic compatibility requires behavior to be understandable without running code."],
            ),
            expectation(
                "Artifacts are optional and should degrade gracefully when ignored.",
                &["Core behavior should remain clear from SKILL.md."],
            ),
        ),
        known_incompatibilities: &[notice(
            "GENERIC001",
            "Host-specific metadata and path conventions may not be recognized.",
        )],
        warnings: &[notice(
            "GENERIC-W001",
            "Features requiring a specific agent host are not generically portable.",
        )],
        documentation_notes: &["Use this profile as the broadest compatibility target when no host is selected."],
    ),
];

struct HostProfileDefinition {
    id: &'static str,
    display_name: &'static str,
    required_fields: &'static [ManifestField],
    accepted_optional_fields: &'static [ManifestField],
    known_ignored_fields: &'static [ManifestField],
    metadata_fields: &'static [HostMetadataField],
    metadata_namespaces: &'static [&'static str],
    path_conventions: &'static [PathConvention],
    recommended_manifest_size_limit: ManifestSizeLimit,
    tool_expectation: CapabilityExpectation,
    script_support: CapabilityExpectation,
    artifact_support: CapabilityExpectation,
    known_incompatibilities: &'static [ProfileNotice],
    warnings: &'static [ProfileNotice],
    documentation_notes: &'static [&'static str],
}

const fn host_profile(definition: HostProfileDefinition) -> HostProfile {
    HostProfile {
        id: definition.id,
        display_name: definition.display_name,
        required_fields: definition.required_fields,
        accepted_optional_fields: definition.accepted_optional_fields,
        known_ignored_fields: definition.known_ignored_fields,
        metadata_fields: definition.metadata_fields,
        metadata_namespaces: definition.metadata_namespaces,
        path_conventions: definition.path_conventions,
        recommended_manifest_size_limit: definition.recommended_manifest_size_limit,
        tool_expectation: definition.tool_expectation,
        script_support: definition.script_support,
        artifact_support: definition.artifact_support,
        known_incompatibilities: definition.known_incompatibilities,
        warnings: definition.warnings,
        documentation_notes: definition.documentation_notes,
    }
}

const fn manifest_field(name: &'static str, description: &'static str) -> ManifestField {
    ManifestField { name, description }
}

const fn metadata_field(
    field: &'static str,
    namespace: Option<&'static str>,
    description: &'static str,
) -> HostMetadataField {
    HostMetadataField {
        field,
        namespace,
        description,
    }
}

const fn path_convention(pattern: &'static str, description: &'static str) -> PathConvention {
    PathConvention {
        pattern,
        description,
    }
}

const fn manifest_size_limit(bytes: usize, description: &'static str) -> ManifestSizeLimit {
    ManifestSizeLimit { bytes, description }
}

const fn expectation(
    summary: &'static str,
    notes: &'static [&'static str],
) -> CapabilityExpectation {
    CapabilityExpectation { summary, notes }
}

const fn notice(code: &'static str, summary: &'static str) -> ProfileNotice {
    ProfileNotice { code, summary }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HostProfile {
    pub id: &'static str,
    pub display_name: &'static str,
    pub required_fields: &'static [ManifestField],
    pub accepted_optional_fields: &'static [ManifestField],
    pub known_ignored_fields: &'static [ManifestField],
    pub metadata_fields: &'static [HostMetadataField],
    pub metadata_namespaces: &'static [&'static str],
    pub path_conventions: &'static [PathConvention],
    pub recommended_manifest_size_limit: ManifestSizeLimit,
    pub tool_expectation: CapabilityExpectation,
    pub script_support: CapabilityExpectation,
    pub artifact_support: CapabilityExpectation,
    pub known_incompatibilities: &'static [ProfileNotice],
    pub warnings: &'static [ProfileNotice],
    pub documentation_notes: &'static [&'static str],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ManifestField {
    pub name: &'static str,
    pub description: &'static str,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HostMetadataField {
    pub field: &'static str,
    pub namespace: Option<&'static str>,
    pub description: &'static str,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PathConvention {
    pub pattern: &'static str,
    pub description: &'static str,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ManifestSizeLimit {
    pub bytes: usize,
    pub description: &'static str,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CapabilityExpectation {
    pub summary: &'static str,
    pub notes: &'static [&'static str],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProfileNotice {
    pub code: &'static str,
    pub summary: &'static str,
}

pub const fn profiles() -> &'static [HostProfile] {
    HOST_PROFILE_DEFINITIONS
}

pub fn profile_by_id(id: &str) -> Option<&'static HostProfile> {
    HOST_PROFILE_DEFINITIONS
        .iter()
        .find(|profile| profile.id == id)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CompatibilityStatus {
    Pass,
    Warn,
    Fail,
    Unknown,
}

impl CompatibilityStatus {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pass => "pass",
            Self::Warn => "warn",
            Self::Fail => "fail",
            Self::Unknown => "unknown",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProfileCompatibilityResult {
    pub profile: String,
    pub status: CompatibilityStatus,
    pub finding_ids: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    #[test]
    fn host_profiles_are_stable_and_unique() {
        assert_eq!(
            HOST_PROFILES,
            &[
                "agent-skills-spec",
                "claude-code",
                "codex",
                "github-copilot",
                "vscode-copilot",
                "generic",
            ]
        );

        let mut sorted = HOST_PROFILES.to_vec();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), HOST_PROFILES.len());
    }

    #[test]
    fn profiles_are_returned_in_deterministic_registry_order() {
        let profile_ids = profile_ids(profiles());

        assert_eq!(profile_ids, HOST_PROFILES);
    }

    #[test]
    fn profile_registry_apis_are_consistent() {
        assert_eq!(profiles(), HOST_PROFILE_DEFINITIONS);
        assert_eq!(profiles().len(), HOST_PROFILES.len());

        for (index, id) in HOST_PROFILES.iter().enumerate() {
            let profile = profile_by_id(id).unwrap_or_else(|| panic!("{id} profile exists"));

            assert_eq!(profile, &HOST_PROFILE_DEFINITIONS[index]);
            assert_eq!(profile, &profiles()[index]);
            assert_eq!(profile.id, *id);
        }

        assert_eq!(profile_by_id("unknown-host"), None);
    }

    macro_rules! expected_profile_shape {
        (
            id: $id:expr,
            display_name: $display_name:expr,
            required_fields: $required_fields:expr,
            accepted_optional_fields: $accepted_optional_fields:expr,
            known_ignored_fields: $known_ignored_fields:expr,
            metadata_fields: $metadata_fields:expr,
            path_conventions: $path_conventions:expr,
            manifest_size_limit: $manifest_size_limit:expr $(,)?
        ) => {
            ProfileShape {
                id: $id,
                display_name: $display_name,
                required_fields: $required_fields,
                accepted_optional_fields: $accepted_optional_fields,
                known_ignored_fields: $known_ignored_fields,
                metadata_fields: $metadata_fields,
                path_conventions: $path_conventions,
                manifest_size_limit: $manifest_size_limit,
            }
        };
    }

    #[test]
    fn profile_registry_shape_is_complete_and_stable() {
        let registry_shape: Vec<_> = profiles().iter().map(profile_shape).collect();

        assert_eq!(
            registry_shape,
            vec![
                expected_profile_shape!(
                    id: "agent-skills-spec",
                    display_name: "Agent Skills Specification",
                    required_fields: vec!["name", "description"],
                    accepted_optional_fields: vec![],
                    known_ignored_fields: vec!["license"],
                    metadata_fields: vec![(None, "tools")],
                    path_conventions: vec!["SKILL.md", "scripts/", "references/", "assets/"],
                    manifest_size_limit: 32 * 1024,
                ),
                expected_profile_shape!(
                    id: "claude-code",
                    display_name: "Claude Code",
                    required_fields: vec!["name"],
                    accepted_optional_fields: vec!["description", "allowed-tools"],
                    known_ignored_fields: vec!["tools"],
                    metadata_fields: vec![(Some("claude"), "allowed-tools")],
                    path_conventions: vec![
                        ".claude/skills/**/SKILL.md",
                        "SKILL.md",
                        "scripts/",
                        "references/"
                    ],
                    manifest_size_limit: 32 * 1024,
                ),
                expected_profile_shape!(
                    id: "codex",
                    display_name: "Codex",
                    required_fields: vec!["name"],
                    accepted_optional_fields: vec!["description", "tools"],
                    known_ignored_fields: vec!["allowed-tools"],
                    metadata_fields: vec![(Some("codex"), "tools")],
                    path_conventions: vec![
                        ".agents/skills/**/SKILL.md",
                        "SKILL.md",
                        "scripts/",
                        "assets/"
                    ],
                    manifest_size_limit: 32 * 1024,
                ),
                expected_profile_shape!(
                    id: "github-copilot",
                    display_name: "GitHub Copilot",
                    required_fields: vec!["name"],
                    accepted_optional_fields: vec!["description", "tools"],
                    known_ignored_fields: vec!["allowed-tools"],
                    metadata_fields: vec![(Some("github"), "github")],
                    path_conventions: vec![".github/skills/**/SKILL.md", "SKILL.md", "references/"],
                    manifest_size_limit: 24 * 1024,
                ),
                expected_profile_shape!(
                    id: "vscode-copilot",
                    display_name: "VS Code Copilot",
                    required_fields: vec!["name"],
                    accepted_optional_fields: vec!["description", "tools"],
                    known_ignored_fields: vec!["allowed-tools"],
                    metadata_fields: vec![(Some("vscode"), "vscode")],
                    path_conventions: vec![".github/skills/**/SKILL.md", "SKILL.md", "assets/"],
                    manifest_size_limit: 24 * 1024,
                ),
                expected_profile_shape!(
                    id: "generic",
                    display_name: "Generic Agent",
                    required_fields: vec!["name"],
                    accepted_optional_fields: vec!["description", "tools"],
                    known_ignored_fields: vec!["allowed-tools"],
                    metadata_fields: vec![(None, "metadata")],
                    path_conventions: vec!["**/SKILL.md", "references/", "assets/"],
                    manifest_size_limit: 16 * 1024,
                ),
            ]
        );
    }

    #[test]
    fn profile_definitions_expose_supported_static_data() {
        for profile in profiles() {
            assert!(!profile.id.is_empty());
            assert!(!profile.display_name.is_empty(), "{}", profile.id);
            assert!(!profile.required_fields.is_empty(), "{}", profile.id);
            assert!(!profile.known_ignored_fields.is_empty(), "{}", profile.id);
            assert!(!profile.metadata_fields.is_empty(), "{}", profile.id);
            assert!(!profile.metadata_namespaces.is_empty(), "{}", profile.id);
            assert!(!profile.path_conventions.is_empty(), "{}", profile.id);
            assert!(
                profile.recommended_manifest_size_limit.bytes > 0,
                "{}",
                profile.id
            );
            assert!(
                !profile.tool_expectation.summary.is_empty(),
                "{}",
                profile.id
            );
            assert!(!profile.script_support.summary.is_empty(), "{}", profile.id);
            assert!(
                !profile.artifact_support.summary.is_empty(),
                "{}",
                profile.id
            );
            assert!(
                !profile.known_incompatibilities.is_empty(),
                "{}",
                profile.id
            );
            assert!(!profile.warnings.is_empty(), "{}", profile.id);
            assert!(!profile.documentation_notes.is_empty(), "{}", profile.id);
            assert_eq!(profile_by_id(profile.id), Some(profile));
        }
    }

    #[test]
    fn profile_documentation_fields_are_non_empty() {
        for profile in profiles() {
            assert_profile_identity_documented(profile);
            assert_profile_manifest_fields_documented(profile);
            assert_profile_metadata_documented(profile);
            assert_profile_limit_documented(profile);
            assert_profile_documentation_notes_present(profile);
        }
    }

    #[test]
    fn profile_data_is_internally_coherent_for_future_evaluators() {
        for profile in profiles() {
            assert_unique_manifest_fields(profile.id, "required_fields", profile.required_fields);
            assert_unique_manifest_fields(
                profile.id,
                "accepted_optional_fields",
                profile.accepted_optional_fields,
            );
            assert_unique_manifest_fields(
                profile.id,
                "known_ignored_fields",
                profile.known_ignored_fields,
            );
            assert_unique_metadata_fields(profile.id, profile.metadata_fields);

            for convention in profile.path_conventions {
                assert_not_blank(profile.id, "path convention pattern", convention.pattern);
                assert_not_blank(
                    profile.id,
                    "path convention description",
                    convention.description,
                );
            }

            assert!(
                profile.recommended_manifest_size_limit.bytes > 0,
                "{}",
                profile.id
            );

            assert_capability_expectation_documented(
                profile.id,
                "tool_expectation",
                profile.tool_expectation,
            );
            assert_capability_expectation_documented(
                profile.id,
                "script_support",
                profile.script_support,
            );
            assert_capability_expectation_documented(
                profile.id,
                "artifact_support",
                profile.artifact_support,
            );

            for notice in profile.known_incompatibilities {
                assert_notice_documented(profile.id, "known_incompatibilities", notice);
            }

            for notice in profile.warnings {
                assert_notice_documented(profile.id, "warnings", notice);
            }
        }
    }

    #[test]
    fn agent_skills_spec_requires_name_and_description() {
        let profile = profile_by_id("agent-skills-spec").expect("baseline profile exists");
        let required_fields: Vec<_> = profile
            .required_fields
            .iter()
            .map(|field| field.name)
            .collect();
        let optional_fields: Vec<_> = profile
            .accepted_optional_fields
            .iter()
            .map(|field| field.name)
            .collect();

        assert_eq!(required_fields, vec!["name", "description"]);
        assert!(!optional_fields.contains(&"description"));
    }

    #[test]
    fn compatibility_status_labels_are_stable() {
        assert_eq!(CompatibilityStatus::Pass.as_str(), "pass");
        assert_eq!(CompatibilityStatus::Warn.as_str(), "warn");
        assert_eq!(CompatibilityStatus::Fail.as_str(), "fail");
        assert_eq!(CompatibilityStatus::Unknown.as_str(), "unknown");
    }

    #[test]
    fn compatibility_status_serializes_as_stable_lowercase_names() {
        assert_eq!(
            serde_json::to_value([
                CompatibilityStatus::Pass,
                CompatibilityStatus::Warn,
                CompatibilityStatus::Fail,
                CompatibilityStatus::Unknown,
            ])
            .expect("serialize statuses"),
            serde_json::json!(["pass", "warn", "fail", "unknown"])
        );
    }

    #[test]
    fn profile_compatibility_result_preserves_caller_order() {
        let result = ProfileCompatibilityResult {
            profile: "codex".to_owned(),
            status: CompatibilityStatus::Warn,
            finding_ids: vec!["HOST020".to_owned(), "SKILL050".to_owned()],
        };

        assert_eq!(
            serde_json::to_value(&result).expect("serialize profile result"),
            serde_json::json!({
                "profile": "codex",
                "status": "warn",
                "finding_ids": ["HOST020", "SKILL050"]
            })
        );
    }

    fn profile_ids(profiles: &[HostProfile]) -> Vec<&'static str> {
        profiles.iter().map(|profile| profile.id).collect()
    }

    #[derive(Debug, PartialEq, Eq)]
    struct ProfileShape {
        id: &'static str,
        display_name: &'static str,
        required_fields: Vec<&'static str>,
        accepted_optional_fields: Vec<&'static str>,
        known_ignored_fields: Vec<&'static str>,
        metadata_fields: Vec<(Option<&'static str>, &'static str)>,
        path_conventions: Vec<&'static str>,
        manifest_size_limit: usize,
    }

    fn profile_shape(profile: &HostProfile) -> ProfileShape {
        ProfileShape {
            id: profile.id,
            display_name: profile.display_name,
            required_fields: manifest_field_names(profile.required_fields),
            accepted_optional_fields: manifest_field_names(profile.accepted_optional_fields),
            known_ignored_fields: manifest_field_names(profile.known_ignored_fields),
            metadata_fields: metadata_field_keys(profile.metadata_fields),
            path_conventions: path_patterns(profile.path_conventions),
            manifest_size_limit: profile.recommended_manifest_size_limit.bytes,
        }
    }

    fn manifest_field_names(fields: &[ManifestField]) -> Vec<&'static str> {
        fields.iter().map(|field| field.name).collect()
    }

    fn metadata_field_keys(
        fields: &[HostMetadataField],
    ) -> Vec<(Option<&'static str>, &'static str)> {
        fields
            .iter()
            .map(|field| (field.namespace, field.field))
            .collect()
    }

    fn path_patterns(conventions: &[PathConvention]) -> Vec<&'static str> {
        conventions
            .iter()
            .map(|convention| convention.pattern)
            .collect()
    }

    fn assert_manifest_field_documented(profile_id: &str, category: &str, field: &ManifestField) {
        assert_not_blank(profile_id, category, field.name);
        assert_not_blank(profile_id, category, field.description);
    }

    fn assert_profile_identity_documented(profile: &HostProfile) {
        assert_not_blank(profile.id, "id", profile.id);
        assert_not_blank(profile.id, "display_name", profile.display_name);
    }

    fn assert_profile_manifest_fields_documented(profile: &HostProfile) {
        for field in profile.required_fields {
            assert_manifest_field_documented(profile.id, "required_fields", field);
        }

        for field in profile.accepted_optional_fields {
            assert_manifest_field_documented(profile.id, "accepted_optional_fields", field);
        }

        for field in profile.known_ignored_fields {
            assert_manifest_field_documented(profile.id, "known_ignored_fields", field);
        }
    }

    fn assert_profile_metadata_documented(profile: &HostProfile) {
        for field in profile.metadata_fields {
            assert_metadata_field_documented(profile.id, field);
        }

        for namespace in profile.metadata_namespaces {
            assert_not_blank(profile.id, "metadata namespace", namespace);
        }
    }

    fn assert_metadata_field_documented(profile_id: &str, field: &HostMetadataField) {
        assert_not_blank(profile_id, "metadata field name", field.field);
        assert_not_blank(profile_id, "metadata field description", field.description);

        if let Some(namespace) = field.namespace {
            assert_not_blank(profile_id, "metadata field namespace", namespace);
        }
    }

    fn assert_profile_limit_documented(profile: &HostProfile) {
        assert_not_blank(
            profile.id,
            "manifest size limit description",
            profile.recommended_manifest_size_limit.description,
        );
    }

    fn assert_profile_documentation_notes_present(profile: &HostProfile) {
        for note in profile.documentation_notes {
            assert_not_blank(profile.id, "documentation note", note);
        }
    }

    fn assert_capability_expectation_documented(
        profile_id: &str,
        category: &str,
        expectation: CapabilityExpectation,
    ) {
        assert_not_blank(profile_id, category, expectation.summary);
        assert!(
            !expectation.notes.is_empty(),
            "{profile_id} {category} notes must not be empty"
        );

        for note in expectation.notes {
            assert_not_blank(profile_id, category, note);
        }
    }

    fn assert_notice_documented(profile_id: &str, category: &str, notice: &ProfileNotice) {
        assert_not_blank(profile_id, category, notice.code);
        assert_not_blank(profile_id, category, notice.summary);
    }

    fn assert_unique_manifest_fields(profile_id: &str, category: &str, fields: &[ManifestField]) {
        let mut names = BTreeSet::new();

        for field in fields {
            assert!(
                names.insert(field.name),
                "{profile_id} {category} contains duplicate field {}",
                field.name
            );
        }
    }

    fn assert_unique_metadata_fields(profile_id: &str, fields: &[HostMetadataField]) {
        let mut names = BTreeSet::new();

        for field in fields {
            assert!(
                names.insert((field.namespace, field.field)),
                "{profile_id} metadata_fields contains duplicate field {:?}/{}",
                field.namespace,
                field.field
            );
        }
    }

    fn assert_not_blank(profile_id: &str, field: &str, value: &str) {
        assert!(
            !value.trim().is_empty(),
            "{profile_id} {field} must not be blank"
        );
    }
}
