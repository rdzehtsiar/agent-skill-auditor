// SPDX-License-Identifier: Apache-2.0

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum RuleId {
    Skill001,
    Skill002,
    Skill010,
    Skill020,
    Skill030,
    Skill040,
    Skill041,
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
        }
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum RuleCategory {
    Spec,
    Compatibility,
    Security,
    Quality,
    Portability,
    Reproducibility,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum RuleInputNodeType {
    SkillManifest,
    Frontmatter,
    RelativeReference,
    SkillPackage,
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
    summary: "Use only portable frontmatter fields in the initial scanner.",
    non_compliant: "---\nname: reviewer\ndescription: Reviews changes.\nowner: security\n---\n",
    compliant: "---\nname: reviewer\ndescription: Reviews changes.\n---\n",
}];

const SKILL041_EXAMPLES: &[RuleExample] = &[RuleExample {
    summary: "Keep YAML frontmatter parseable.",
    non_compliant: "---\nname: [unterminated\n---\n",
    compliant: "---\nname: reviewer\ndescription: Reviews changes.\n---\n",
}];

pub const RULE_METADATA: &[RuleMetadata] = &[
    RuleMetadata {
        id: RuleId::Skill001,
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
];

pub const RULE_REGISTRY: RuleRegistry = RuleRegistry::new(RULE_METADATA);

pub fn rule_metadata(rule_id: &str) -> Option<&'static RuleMetadata> {
    RULE_REGISTRY.metadata(rule_id)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn structural_rule_ids_cover_current_implemented_rules() {
        assert_eq!(
            STRUCTURAL_RULE_IDS,
            &["SKILL001", "SKILL002", "SKILL010", "SKILL020", "SKILL030", "SKILL040", "SKILL041",]
        );
    }

    #[test]
    fn metadata_covers_current_structural_rule_ids_in_deterministic_order() {
        let metadata_ids = RULE_REGISTRY
            .rules()
            .iter()
            .map(|metadata| metadata.id.as_str())
            .collect::<Vec<_>>();

        assert_eq!(metadata_ids, STRUCTURAL_RULE_IDS);
        assert!(metadata_ids.windows(2).all(|ids| ids[0] < ids[1]));
    }

    #[test]
    fn registry_rules_are_unique_sorted_and_match_current_implemented_set() {
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
            ]
        );
        assert_eq!(registry_ids, STRUCTURAL_RULE_IDS);
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
}
