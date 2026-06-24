//! `--fail-on` 閘門（ADR-006 / FR-005）。

use cytrace_types::{Severity, Vulnerability};

/// 當任一弱點的嚴重度 **≥ 門檻** 時觸發（CI 據此以退出碼 2 結束）。
///
/// 注意 `Severity` 的 `Ord`：`Unknown` 最低，故 `--fail-on unknown` 會對任何弱點觸發，
/// `--fail-on critical` 只對嚴峻觸發。
pub fn triggered(findings: &[Vulnerability], threshold: Severity) -> bool {
    findings.iter().any(|v| v.severity >= threshold)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vuln(sev: Severity) -> Vulnerability {
        Vulnerability {
            id: "CVE-TEST".into(),
            severity: sev,
            cvss: None,
            component: "lib".into(),
            fixed_version: None,
            source: "test".into(),
        }
    }

    #[test]
    fn triggers_when_a_finding_meets_threshold() {
        let findings = vec![vuln(Severity::Medium), vuln(Severity::High)];
        assert!(triggered(&findings, Severity::High));
    }

    #[test]
    fn does_not_trigger_when_all_below_threshold() {
        let findings = vec![vuln(Severity::Low), vuln(Severity::Medium)];
        assert!(!triggered(&findings, Severity::High));
    }

    #[test]
    fn threshold_is_inclusive() {
        assert!(triggered(&[vuln(Severity::High)], Severity::High));
    }

    #[test]
    fn no_findings_never_triggers() {
        assert!(!triggered(&[], Severity::Unknown));
    }
}
