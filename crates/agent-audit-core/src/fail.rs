// SPDX-License-Identifier: Apache-2.0

use crate::model::{ScanReport, Severity};

pub fn report_matches_fail_on(report: &ScanReport, fail_on: &[Severity]) -> bool {
    !fail_on.is_empty()
        && report
            .findings
            .iter()
            .any(|finding| fail_on.contains(&finding.severity))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{
        CompatibilityMatrix, FindingCategory, FindingLocation, ScanSummary, SkillFinding,
        SuppressedFinding, SuppressionMatch,
    };

    #[test]
    fn empty_fail_on_never_matches() {
        let report = report_with_findings(vec![finding("SKILL001", Severity::Low)], Vec::new());

        assert!(!report_matches_fail_on(&report, &[]));
    }

    #[test]
    fn matches_unsuppressed_findings_by_exact_severity() {
        let report = report_with_findings(vec![finding("SKILL001", Severity::Low)], Vec::new());

        assert!(report_matches_fail_on(&report, &[Severity::Low]));
        assert!(!report_matches_fail_on(&report, &[Severity::High]));
    }

    #[test]
    fn ignores_suppressed_findings_when_matching_fail_on() {
        let report = report_with_findings(
            Vec::new(),
            vec![SuppressedFinding {
                finding: finding("SKILL001", Severity::Low),
                suppression: SuppressionMatch {
                    matched_rule: "SKILL001".to_owned(),
                    matched_path: "SKILL.md".to_owned(),
                    reason: "Accepted fixture.".to_owned(),
                },
            }],
        );

        assert!(!report_matches_fail_on(&report, &[Severity::Low]));
    }

    fn report_with_findings(
        findings: Vec<SkillFinding>,
        suppressed_findings: Vec<SuppressedFinding>,
    ) -> ScanReport {
        ScanReport {
            packages: Vec::new(),
            summary: ScanSummary {
                package_count: 0,
                finding_count: findings.len(),
                suppressed_finding_count: suppressed_findings.len(),
                invalid_manifest_count: 0,
                broken_reference_count: 0,
            },
            findings,
            suppressed_findings,
            compatibility: CompatibilityMatrix::default(),
        }
    }

    fn finding(rule_id: &str, severity: Severity) -> SkillFinding {
        SkillFinding {
            rule_id: rule_id.to_owned(),
            severity,
            category: FindingCategory::Spec,
            title: "Fixture finding".to_owned(),
            message: "Fixture finding message.".to_owned(),
            location: FindingLocation {
                path: "SKILL.md".to_owned(),
                line: Some(1),
            },
            rationale: "Fixture rationale.".to_owned(),
            remediation: "Fixture remediation.".to_owned(),
            suppression: "Fixture suppression.".to_owned(),
        }
    }
}
