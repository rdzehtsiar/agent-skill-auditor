// SPDX-License-Identifier: Apache-2.0

pub const SUPPORTED_REPORT_FORMATS: &[&str] = &["summary", "json"];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn supported_report_formats_match_phase_one_outputs() {
        assert_eq!(SUPPORTED_REPORT_FORMATS, &["summary", "json"]);
    }
}
