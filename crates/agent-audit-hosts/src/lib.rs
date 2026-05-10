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
}
