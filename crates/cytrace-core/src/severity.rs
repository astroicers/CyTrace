//! 嚴重度分級與風險總評（ADR-006 / FR-004）。

use cytrace_types::{Component, OverallRisk, Severity, Summary, Vulnerability};
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

/// 由元件與弱點清單彙整 [`Summary`]（#78）：
/// - 有弱點：`overall_risk` 為最高嚴重度。
/// - 有元件、沒有弱點：`Negligible`（掃到了、比對後沒有風險）。
/// - 沒有元件也沒有弱點：`NotAssessed`——沒有可比對的對象，不能當成低風險（ADR-009 修訂：schema v4）。
pub fn summarize(components: &[Component], findings: &[Vulnerability]) -> Summary {
    let overall_risk = match overall_risk(findings) {
        Some(s) => s.into(),
        None if components.is_empty() => OverallRisk::NotAssessed,
        None => OverallRisk::Negligible,
    };
    Summary {
        counts_by_severity: counts_by_severity(findings),
        overall_risk,
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
            component_version: None,
            component_purl: None,
            locations: vec![],
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

    fn component() -> Component {
        serde_json::from_str(r#"{"name":"lib","version":"1.0","type":"library"}"#).unwrap()
    }

    /// #78：有元件、沒有弱點才是 Negligible；連元件都沒有時為 NotAssessed，不得呈現為低風險。
    #[test]
    fn summarize_distinguishes_no_findings_from_no_components() {
        assert_eq!(
            summarize(&[component()], &[]).overall_risk,
            OverallRisk::Negligible
        );
        assert_eq!(summarize(&[], &[]).overall_risk, OverallRisk::NotAssessed);
        assert_eq!(
            summarize(&[component()], &[vuln(Severity::High)]).overall_risk,
            OverallRisk::High
        );
        // 沒有元件卻有弱點（不應發生，但弱點本身就是證據）：仍以最高嚴重度呈現，不蓋成「無法評估」
        assert_eq!(
            summarize(&[], &[vuln(Severity::Medium)]).overall_risk,
            OverallRisk::Medium
        );
        assert_eq!(summarize(&[], &[]).counts_by_severity.len(), 6);
    }
}
