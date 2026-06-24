//! 嚴重度分級與風險總評（ADR-006 / FR-004）。

use cytrace_types::{Severity, Summary, Vulnerability};
use std::collections::BTreeMap;

/// 風險總評＝出現的最高嚴重度等級；無弱點時為 [`Severity::Unknown`] 之上的「無風險」用 `Negligible`？
///
/// 設計：無弱點回 `None` 由呼叫端決定呈現；有弱點時取最高等級（`Severity` 的 `Ord` 保證
/// 真實等級高於 `Unknown`，全 `Unknown` 時總評才是 `Unknown`）。
pub fn overall_risk(findings: &[Vulnerability]) -> Option<Severity> {
    findings.iter().map(|v| v.severity).max()
}

/// 各嚴重度計數（六級都列出，缺者為 0，供報表固定欄位）。
pub fn counts_by_severity(findings: &[Vulnerability]) -> BTreeMap<Severity, u64> {
    let mut counts: BTreeMap<Severity, u64> = Severity::all_high_to_low()
        .into_iter()
        .map(|s| (s, 0))
        .collect();
    for v in findings {
        *counts.entry(v.severity).or_insert(0) += 1;
    }
    counts
}

/// 由弱點清單彙整 [`Summary`]。無弱點時 `overall_risk` 取 `Negligible`（代表掃到但無風險）。
pub fn summarize(findings: &[Vulnerability]) -> Summary {
    Summary {
        counts_by_severity: counts_by_severity(findings),
        overall_risk: overall_risk(findings).unwrap_or(Severity::Negligible),
    }
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
    fn overall_risk_is_highest_present_severity() {
        let findings = vec![
            vuln(Severity::Low),
            vuln(Severity::Critical),
            vuln(Severity::Medium),
        ];
        assert_eq!(overall_risk(&findings), Some(Severity::Critical));
    }

    #[test]
    fn overall_risk_none_when_no_findings() {
        assert_eq!(overall_risk(&[]), None);
    }

    #[test]
    fn real_severity_outranks_unknown() {
        let findings = vec![vuln(Severity::Unknown), vuln(Severity::Low)];
        assert_eq!(overall_risk(&findings), Some(Severity::Low));
    }

    #[test]
    fn counts_list_all_six_levels_even_when_zero() {
        let counts = counts_by_severity(&[vuln(Severity::High)]);
        assert_eq!(counts.len(), 6);
        assert_eq!(counts[&Severity::High], 1);
        assert_eq!(counts[&Severity::Critical], 0);
    }

    #[test]
    fn summarize_empty_is_negligible() {
        assert_eq!(summarize(&[]).overall_risk, Severity::Negligible);
    }
}
