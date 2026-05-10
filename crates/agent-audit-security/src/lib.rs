// SPDX-License-Identifier: Apache-2.0

pub const INITIAL_SECURITY_RULE_IDS: &[&str] = &[
    "SEC001", "SEC002", "SEC003", "SEC004", "SEC005", "SEC006", "SEC007", "SEC008", "SEC009",
    "SEC010", "SEC011", "SEC012",
];

#[cfg(test)]
mod tests {
    use super::*;

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
}
