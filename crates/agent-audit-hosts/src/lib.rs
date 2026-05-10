// SPDX-License-Identifier: Apache-2.0

pub const HOST_PROFILES: &[&str] = &[
    "agent-skills-spec",
    "claude-code",
    "codex",
    "github-copilot",
    "vscode-copilot",
    "generic",
];

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
}
