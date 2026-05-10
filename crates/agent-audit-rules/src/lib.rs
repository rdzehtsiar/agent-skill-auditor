// SPDX-License-Identifier: Apache-2.0

pub const STRUCTURAL_RULE_IDS: &[&str] = &[
    "SKILL001", "SKILL002", "SKILL010", "SKILL020", "SKILL030", "SKILL040",
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn structural_rule_ids_cover_current_implemented_rules() {
        assert_eq!(
            STRUCTURAL_RULE_IDS,
            &["SKILL001", "SKILL002", "SKILL010", "SKILL020", "SKILL030", "SKILL040"]
        );
    }
}
