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
        CompatibilityMatrix, FindingCategory, FindingConfidence, FindingLocation, ScanSummary,
        SkillFinding, SupplyChainInventory, SuppressedFinding, SuppressionMatch,
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
    fn matches_unsuppressed_compatibility_findings_by_exact_severity() {
        let report = report_with_findings(
            vec![compatibility_finding("SKILL040", Severity::Low)],
            Vec::new(),
        );

        assert!(report_matches_fail_on(&report, &[Severity::Low]));
        assert!(!report_matches_fail_on(&report, &[Severity::Medium]));
    }

    #[test]
    fn matches_unsuppressed_security_findings_by_exact_severity() {
        let report =
            report_with_findings(vec![security_finding("SEC009", Severity::Low)], Vec::new());

        assert!(report_matches_fail_on(&report, &[Severity::Low]));
        assert!(!report_matches_fail_on(&report, &[Severity::Medium]));
    }

    #[test]
    fn ignores_suppressed_findings_when_matching_fail_on() {
        let report = report_with_findings(
            Vec::new(),
            vec![SuppressedFinding {
                finding: finding("SKILL001", Severity::Low),
                suppression: SuppressionMatch {
                    matched_rule: "SKILL001".to_owned(),
                    matched_path: Some("SKILL.md".to_owned()),
                    matched_match: None,
                    reason: "Accepted fixture.".to_owned(),
                },
            }],
        );

        assert!(!report_matches_fail_on(&report, &[Severity::Low]));
    }

    #[test]
    fn ignores_suppressed_compatibility_findings_when_matching_fail_on() {
        let report = report_with_findings(
            Vec::new(),
            vec![SuppressedFinding {
                finding: compatibility_finding("SKILL040", Severity::Low),
                suppression: SuppressionMatch {
                    matched_rule: "SKILL040".to_owned(),
                    matched_path: Some("SKILL.md".to_owned()),
                    matched_match: None,
                    reason: "Accepted host metadata fixture.".to_owned(),
                },
            }],
        );

        assert!(!report_matches_fail_on(&report, &[Severity::Low]));
    }

    #[test]
    fn ignores_suppressed_security_findings_when_matching_fail_on() {
        let report = report_with_findings(
            Vec::new(),
            vec![SuppressedFinding {
                finding: security_finding("SEC009", Severity::Low),
                suppression: SuppressionMatch {
                    matched_rule: "SEC009".to_owned(),
                    matched_path: Some("scripts/install.sh".to_owned()),
                    matched_match: None,
                    reason: "Accepted reviewed package install fixture.".to_owned(),
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
            audit: crate::model::AuditMetadata::default(),
            packages: Vec::new(),
            summary: ScanSummary {
                package_count: 0,
                finding_count: findings.len(),
                suppressed_finding_count: suppressed_findings.len(),
                invalid_manifest_count: 0,
                broken_reference_count: 0,
                actual_secret_evidence_count: 0,
                prompt_secret_exposure_count: 0,
            },
            findings,
            finding_groups: Vec::new(),
            suppressed_findings,
            supply_chain: SupplyChainInventory::default(),
            compatibility: CompatibilityMatrix::default(),
        }
    }

    fn finding(rule_id: &str, severity: Severity) -> SkillFinding {
        SkillFinding {
            rule_id: rule_id.to_owned(),
            fingerprint: String::new(),
            severity,
            confidence: FindingConfidence::Medium,
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

    fn compatibility_finding(rule_id: &str, severity: Severity) -> SkillFinding {
        SkillFinding {
            category: FindingCategory::Compatibility,
            ..finding(rule_id, severity)
        }
    }

    fn security_finding(rule_id: &str, severity: Severity) -> SkillFinding {
        SkillFinding {
            category: FindingCategory::Security,
            location: FindingLocation {
                path: "scripts/install.sh".to_owned(),
                line: Some(3),
            },
            ..finding(rule_id, severity)
        }
    }
}
