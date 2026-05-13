// SPDX-License-Identifier: Apache-2.0

pub(crate) fn normalized_match_text(value: &str) -> String {
    value
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .trim_matches(|character: char| matches!(character, '.' | ',' | ';' | ':'))
        .to_ascii_lowercase()
}
