// SPDX-License-Identifier: Apache-2.0

pub const FIXTURE_GROUPS: &[&str] = &["spec", "compatibility", "security", "behavior"];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixture_groups_match_planned_fixture_directories() {
        assert_eq!(
            FIXTURE_GROUPS,
            &["spec", "compatibility", "security", "behavior"]
        );
    }
}
