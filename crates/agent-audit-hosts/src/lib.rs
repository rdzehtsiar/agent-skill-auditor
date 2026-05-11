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

pub const HOST_PROFILE_DEFINITIONS: &[HostProfile] = &[
    HostProfile {
        id: "agent-skills-spec",
        display_name: "Agent Skills Specification",
        required_fields: &[
            ManifestField {
                name: "name",
                description: "Stable skill name declared in SKILL.md frontmatter.",
            },
            ManifestField {
                name: "description",
                description: "Short human-readable summary of the skill behavior.",
            },
        ],
        accepted_optional_fields: &[],
        known_ignored_fields: &[ManifestField {
            name: "license",
            description: "License metadata is useful to auditors but not part of the base skill contract.",
        }],
        metadata_fields: &[HostMetadataField {
            field: "tools",
            namespace: None,
            description: "Optional declaration of tools the skill expects an agent to provide.",
        }],
        metadata_namespaces: &["agent-skills"],
        path_conventions: &[
            PathConvention {
                pattern: "SKILL.md",
                description: "Manifest and instructions live in the root of each skill directory.",
            },
            PathConvention {
                pattern: "scripts/",
                description: "Referenced scripts are colocated under the skill directory.",
            },
            PathConvention {
                pattern: "references/",
                description: "Large supporting documents are stored outside the manifest body.",
            },
            PathConvention {
                pattern: "assets/",
                description: "Images and other static assets are stored with the skill package.",
            },
        ],
        recommended_manifest_size_limit: ManifestSizeLimit {
            bytes: 32 * 1024,
            description: "Keep SKILL.md concise enough for agents to load without truncation.",
        },
        tool_expectation: CapabilityExpectation {
            summary: "Tools should be declared when the skill depends on agent capabilities.",
            notes: &["Undeclared tools may still work on permissive hosts but reduce portability."],
        },
        script_support: CapabilityExpectation {
            summary: "Scripts may be packaged but should not be executed unless an agent explicitly allows them.",
            notes: &["Static analysis should treat scripts as inert artifacts by default."],
        },
        artifact_support: CapabilityExpectation {
            summary: "scripts/, references/, and assets/ are expected package artifacts.",
            notes: &["Referenced artifacts should use relative paths inside the skill directory."],
        },
        known_incompatibilities: &[ProfileNotice {
            code: "SPEC001",
            summary: "Host-specific metadata may be ignored by strict spec consumers.",
        }],
        warnings: &[ProfileNotice {
            code: "SPEC-W001",
            summary: "Oversized manifests can be truncated or skipped by context-limited agents.",
        }],
        documentation_notes: &[
            "Use this profile as the portable baseline for deterministic skill package checks.",
        ],
    },
    HostProfile {
        id: "claude-code",
        display_name: "Claude Code",
        required_fields: &[ManifestField {
            name: "name",
            description: "Skill name used to identify the package.",
        }],
        accepted_optional_fields: &[
            ManifestField {
                name: "description",
                description: "Description used by agents and reviewers to understand when to use the skill.",
            },
            ManifestField {
                name: "allowed-tools",
                description: "Host-specific allowlist of tools the skill may request.",
            },
        ],
        known_ignored_fields: &[ManifestField {
            name: "tools",
            description: "Portable tool declarations may be ignored in favor of host-specific tool allowlists.",
        }],
        metadata_fields: &[HostMetadataField {
            field: "allowed-tools",
            namespace: Some("claude"),
            description: "Claude-style tool permission declaration.",
        }],
        metadata_namespaces: &["claude", "anthropic"],
        path_conventions: &[
            PathConvention {
                pattern: ".claude/skills/**/SKILL.md",
                description: "Claude-specific skill discovery path.",
            },
            PathConvention {
                pattern: "SKILL.md",
                description: "Each skill package is rooted at a manifest file.",
            },
            PathConvention {
                pattern: "scripts/",
                description: "Optional scripts referenced by the skill.",
            },
            PathConvention {
                pattern: "references/",
                description: "Optional supporting reference material.",
            },
        ],
        recommended_manifest_size_limit: ManifestSizeLimit {
            bytes: 32 * 1024,
            description: "Keep host instructions compact enough for reliable agent loading.",
        },
        tool_expectation: CapabilityExpectation {
            summary: "Tool declarations should use the host allowlist format when present.",
            notes: &["Portable declarations are useful documentation but may not control host permissions."],
        },
        script_support: CapabilityExpectation {
            summary: "Scripts are supported as packaged references, with execution controlled by the host.",
            notes: &["Audits must not assume scripts execute automatically."],
        },
        artifact_support: CapabilityExpectation {
            summary: "References and scripts may be bundled with the skill.",
            notes: &["Relative references should remain inside the skill directory."],
        },
        known_incompatibilities: &[ProfileNotice {
            code: "CLAUDE001",
            summary: "Non-Claude metadata namespaces may be ignored.",
        }],
        warnings: &[ProfileNotice {
            code: "CLAUDE-W001",
            summary: "Broad tool allowlists reduce reviewability and portability.",
        }],
        documentation_notes: &[
            "Model this profile around Claude Code skill packaging and permission metadata.",
        ],
    },
    HostProfile {
        id: "codex",
        display_name: "Codex",
        required_fields: &[ManifestField {
            name: "name",
            description: "Skill name used by Codex to present available skills.",
        }],
        accepted_optional_fields: &[
            ManifestField {
                name: "description",
                description: "Description that explains when Codex should apply the skill.",
            },
            ManifestField {
                name: "tools",
                description: "Tool or capability hints documented by the package.",
            },
        ],
        known_ignored_fields: &[ManifestField {
            name: "allowed-tools",
            description: "Claude-style allowlists may be documentation only for Codex.",
        }],
        metadata_fields: &[HostMetadataField {
            field: "tools",
            namespace: Some("codex"),
            description: "Codex-facing capability declarations when present.",
        }],
        metadata_namespaces: &["codex", "openai"],
        path_conventions: &[
            PathConvention {
                pattern: ".agents/skills/**/SKILL.md",
                description: "Agent skill discovery path used by Codex-style packages.",
            },
            PathConvention {
                pattern: "SKILL.md",
                description: "Root manifest for the skill package.",
            },
            PathConvention {
                pattern: "scripts/",
                description: "Helper scripts shipped with the skill.",
            },
            PathConvention {
                pattern: "assets/",
                description: "Images and static files referenced by instructions.",
            },
        ],
        recommended_manifest_size_limit: ManifestSizeLimit {
            bytes: 32 * 1024,
            description: "Keep instructions short enough to fit predictable context budgets.",
        },
        tool_expectation: CapabilityExpectation {
            summary: "Tool needs should be documented explicitly and treated as host-mediated capabilities.",
            notes: &["Tool declarations do not imply automatic access."],
        },
        script_support: CapabilityExpectation {
            summary: "Scripts can be included as artifacts, but execution is host-mediated and should be reviewed.",
            notes: &["Auditors should inspect scripts without running them."],
        },
        artifact_support: CapabilityExpectation {
            summary: "scripts/, references/, and assets/ are supported package conventions.",
            notes: &["Artifact links should be relative and deterministic."],
        },
        known_incompatibilities: &[ProfileNotice {
            code: "CODEX001",
            summary: "Claude-only permission metadata may not be enforced.",
        }],
        warnings: &[ProfileNotice {
            code: "CODEX-W001",
            summary: "Skills that require network access or script execution are less portable.",
        }],
        documentation_notes: &[
            "Use this profile for Codex-compatible offline skill package review.",
        ],
    },
    HostProfile {
        id: "github-copilot",
        display_name: "GitHub Copilot",
        required_fields: &[ManifestField {
            name: "name",
            description: "Skill or instruction package name.",
        }],
        accepted_optional_fields: &[
            ManifestField {
                name: "description",
                description: "Summary used by reviewers to understand intended behavior.",
            },
            ManifestField {
                name: "tools",
                description: "Documented tool expectations for environments that expose them.",
            },
        ],
        known_ignored_fields: &[ManifestField {
            name: "allowed-tools",
            description: "Host may ignore explicit tool allowlists embedded in skill metadata.",
        }],
        metadata_fields: &[HostMetadataField {
            field: "github",
            namespace: Some("github"),
            description: "GitHub-specific metadata namespace for future compatibility checks.",
        }],
        metadata_namespaces: &["github", "copilot"],
        path_conventions: &[
            PathConvention {
                pattern: ".github/skills/**/SKILL.md",
                description: "Repository-scoped GitHub skill discovery path.",
            },
            PathConvention {
                pattern: "SKILL.md",
                description: "Portable skill manifest location.",
            },
            PathConvention {
                pattern: "references/",
                description: "Reference material packaged with the skill.",
            },
        ],
        recommended_manifest_size_limit: ManifestSizeLimit {
            bytes: 24 * 1024,
            description: "Prefer compact repository instructions for predictable host consumption.",
        },
        tool_expectation: CapabilityExpectation {
            summary: "Tool expectations should be documented but may not map to explicit host permissions.",
            notes: &["Repository context and available tools vary by host surface."],
        },
        script_support: CapabilityExpectation {
            summary: "Scripts should be treated as reviewable artifacts, not automatically supported actions.",
            notes: &["CI and local developer environments may differ."],
        },
        artifact_support: CapabilityExpectation {
            summary: "Reference files are useful; executable artifacts require careful review.",
            notes: &["Keep package references repository-relative."],
        },
        known_incompatibilities: &[ProfileNotice {
            code: "GHCOPILOT001",
            summary: "Skill packages that depend on explicit host tool allowlists may not transfer directly.",
        }],
        warnings: &[ProfileNotice {
            code: "GHCOPILOT-W001",
            summary: "Repository-specific assumptions can reduce portability across Copilot surfaces.",
        }],
        documentation_notes: &[
            "Use this profile for GitHub-hosted skill package compatibility notes.",
        ],
    },
    HostProfile {
        id: "vscode-copilot",
        display_name: "VS Code Copilot",
        required_fields: &[ManifestField {
            name: "name",
            description: "Skill or instruction package name.",
        }],
        accepted_optional_fields: &[
            ManifestField {
                name: "description",
                description: "Summary of when the skill should apply.",
            },
            ManifestField {
                name: "tools",
                description: "Documented local tool expectations.",
            },
        ],
        known_ignored_fields: &[ManifestField {
            name: "allowed-tools",
            description: "Host-specific allowlists from other agents may be ignored.",
        }],
        metadata_fields: &[HostMetadataField {
            field: "vscode",
            namespace: Some("vscode"),
            description: "VS Code specific metadata namespace for future compatibility checks.",
        }],
        metadata_namespaces: &["vscode", "copilot"],
        path_conventions: &[
            PathConvention {
                pattern: ".github/skills/**/SKILL.md",
                description: "Repository skill path often shared with Copilot workflows.",
            },
            PathConvention {
                pattern: "SKILL.md",
                description: "Portable skill manifest location.",
            },
            PathConvention {
                pattern: "assets/",
                description: "Static assets referenced by the skill.",
            },
        ],
        recommended_manifest_size_limit: ManifestSizeLimit {
            bytes: 24 * 1024,
            description: "Keep local editor instructions compact and scannable.",
        },
        tool_expectation: CapabilityExpectation {
            summary: "Local tool expectations should be described rather than assumed.",
            notes: &["Available editor tools depend on extensions, workspace trust, and user configuration."],
        },
        script_support: CapabilityExpectation {
            summary: "Scripts are local artifacts and should require explicit user or host action.",
            notes: &["Workspace trust and shell availability affect script behavior."],
        },
        artifact_support: CapabilityExpectation {
            summary: "References and assets can be useful when paths remain workspace-relative.",
            notes: &["Absolute local paths reduce portability."],
        },
        known_incompatibilities: &[ProfileNotice {
            code: "VSCOPILOT001",
            summary: "Workspace-specific assumptions may not hold outside VS Code.",
        }],
        warnings: &[ProfileNotice {
            code: "VSCOPILOT-W001",
            summary: "Local shell or extension dependencies should be documented explicitly.",
        }],
        documentation_notes: &[
            "Use this profile for editor-oriented Copilot compatibility checks.",
        ],
    },
    HostProfile {
        id: "generic",
        display_name: "Generic Agent",
        required_fields: &[ManifestField {
            name: "name",
            description: "Portable skill name.",
        }],
        accepted_optional_fields: &[
            ManifestField {
                name: "description",
                description: "Portable description of skill behavior.",
            },
            ManifestField {
                name: "tools",
                description: "Optional human-readable tool expectations.",
            },
        ],
        known_ignored_fields: &[ManifestField {
            name: "allowed-tools",
            description: "Host-specific tool permission fields may be ignored by generic agents.",
        }],
        metadata_fields: &[HostMetadataField {
            field: "metadata",
            namespace: None,
            description: "Unrecognized metadata should be treated conservatively.",
        }],
        metadata_namespaces: &["generic"],
        path_conventions: &[
            PathConvention {
                pattern: "**/SKILL.md",
                description: "Discover skill manifests regardless of host-specific parent directory.",
            },
            PathConvention {
                pattern: "references/",
                description: "Reference material remains optional and package-relative.",
            },
            PathConvention {
                pattern: "assets/",
                description: "Static assets remain optional and package-relative.",
            },
        ],
        recommended_manifest_size_limit: ManifestSizeLimit {
            bytes: 16 * 1024,
            description: "Use a conservative manifest size for broad agent portability.",
        },
        tool_expectation: CapabilityExpectation {
            summary: "Tool requirements should be documented as assumptions, not guarantees.",
            notes: &["Generic agents may not expose matching tools or permission controls."],
        },
        script_support: CapabilityExpectation {
            summary: "Do not assume script execution support.",
            notes: &["Generic compatibility requires behavior to be understandable without running code."],
        },
        artifact_support: CapabilityExpectation {
            summary: "Artifacts are optional and should degrade gracefully when ignored.",
            notes: &["Core behavior should remain clear from SKILL.md."],
        },
        known_incompatibilities: &[ProfileNotice {
            code: "GENERIC001",
            summary: "Host-specific metadata and path conventions may not be recognized.",
        }],
        warnings: &[ProfileNotice {
            code: "GENERIC-W001",
            summary: "Features requiring a specific agent host are not generically portable.",
        }],
        documentation_notes: &[
            "Use this profile as the broadest compatibility target when no host is selected.",
        ],
    },
];

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
            assert_not_blank(profile.id, "id", profile.id);
            assert_not_blank(profile.id, "display_name", profile.display_name);

            for field in profile.required_fields {
                assert_manifest_field_documented(profile.id, "required_fields", field);
            }

            for field in profile.accepted_optional_fields {
                assert_manifest_field_documented(profile.id, "accepted_optional_fields", field);
            }

            for field in profile.known_ignored_fields {
                assert_manifest_field_documented(profile.id, "known_ignored_fields", field);
            }

            for field in profile.metadata_fields {
                assert_not_blank(profile.id, "metadata field name", field.field);
                assert_not_blank(profile.id, "metadata field description", field.description);
                if let Some(namespace) = field.namespace {
                    assert_not_blank(profile.id, "metadata field namespace", namespace);
                }
            }

            for namespace in profile.metadata_namespaces {
                assert_not_blank(profile.id, "metadata namespace", namespace);
            }

            assert_not_blank(
                profile.id,
                "manifest size limit description",
                profile.recommended_manifest_size_limit.description,
            );

            for note in profile.documentation_notes {
                assert_not_blank(profile.id, "documentation note", note);
            }
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

            assert!(profile.recommended_manifest_size_limit.bytes > 0, "{}", profile.id);

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

    fn assert_manifest_field_documented(
        profile_id: &str,
        category: &str,
        field: &ManifestField,
    ) {
        assert_not_blank(profile_id, category, field.name);
        assert_not_blank(profile_id, category, field.description);
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

    fn assert_unique_manifest_fields(
        profile_id: &str,
        category: &str,
        fields: &[ManifestField],
    ) {
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
