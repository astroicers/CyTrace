//! `--fail-on` 閘門（ADR-006 / FR-005）與 `--fail-on-quantum-vulnerable`（ADR-013 決策 9）。

use cytrace_types::{CbomStatus, CryptoInventory, QuantumStatus, Severity, Vulnerability};

/// 量子閘門判定結果（ADR-013 決策 9）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QuantumGate {
    /// 掃描完成且無量子脆弱資產。
    Pass,
    /// 存在量子脆弱（或無法判定）的資產 → CLI 以退出碼 2 結束。
    Vulnerable,
    /// **未取得完整結果** → CLI 以退出碼 1 結束（fail-closed）。
    NoResult,
}

/// 量子閘門：**fail-closed**——「沒掃到」絕不等於「通過」。
///
/// 判定順序（兩條獨立的軸，不可互相遮蔽）：
///
/// 1. 引擎缺席 / 執行失敗 / 未請求 / 無 `crypto` 區段 → [`QuantumGate::NoResult`]（退出碼 1）
/// 2. 任一資產為 `Vulnerable` 或 `Unknown` → [`QuantumGate::Vulnerable`]（退出碼 2）
///    （`Unknown` 視為未通過：軍規場域寧可誤報不可漏報）
/// 3. 無脆弱資產、但有項目未掃描（`unscanned_total() > 0`）→ [`QuantumGate::NoResult`]
/// 4. 掃描完成、無脆弱資產、無漏掃 → [`QuantumGate::Pass`]（與「沒掃到」必須區分）
///
/// **清單不完整只能否定「通過」，不能否定「已偵測到脆弱」**：真實映像幾乎必然含
/// 超過 1 MiB 的 libcrypto/libstdc++；若把不完整一律壓成 `NoResult`，本閘門在 image
/// 目標上會三態塌縮為恆 `NoResult`，報表裡數千項脆弱資產反而被說成「沒掃到」。
pub fn quantum_gate(crypto: Option<&CryptoInventory>) -> QuantumGate {
    let Some(inv) = crypto else {
        return QuantumGate::NoResult;
    };
    if !matches!(inv.status, CbomStatus::Completed) {
        return QuantumGate::NoResult;
    }
    let flagged = inv.assets.iter().any(|a| {
        matches!(
            a.quantum,
            QuantumStatus::Vulnerable | QuantumStatus::Unknown
        )
    });
    if flagged {
        // 已經抓到脆弱資產——漏掃只會讓實際情況更糟，不可因此改判
        QuantumGate::Vulnerable
    } else if inv.unscanned_total() > 0 {
        // 沒抓到，但清單不完整 → 不宣告通過
        QuantumGate::NoResult
    } else {
        QuantumGate::Pass
    }
}

/// 當任一弱點的嚴重度 **≥ 門檻** 時觸發（CI 據此以退出碼 2 結束）。
///
/// 注意 `Severity` 的 `Ord`：`Unknown` 最低，故 `--fail-on unknown` 會對任何弱點觸發，
/// `--fail-on critical` 只對極高觸發。
pub fn triggered(findings: &[Vulnerability], threshold: Severity) -> bool {
    findings.iter().any(|v| v.severity >= threshold)
}

#[cfg(test)]
mod tests {
    use super::*;
    use cytrace_types::{CbomStatus, CryptoAsset, CryptoInventory, QuantumStatus};

    fn asset(q: QuantumStatus) -> CryptoAsset {
        CryptoAsset {
            name: "RSA-2048".into(),
            asset_type: "algorithm".into(),
            quantum: q,
            weak_key: false,
            location: "x".into(),
            primitive: None,
            key_size: None,
            not_after: None,
        }
    }

    fn inventory(status: CbomStatus, assets: Vec<CryptoAsset>) -> CryptoInventory {
        CryptoInventory {
            status,
            assets,
            unscanned_unreadable: 0,
            unscanned_oversize: 0,
            unscanned_undetermined: 0,
        }
    }

    // ── 量子閘門（ADR-013 決策 9）──

    #[test]
    fn quantum_gate_passes_when_all_assets_are_safe() {
        let inv = inventory(CbomStatus::Completed, vec![asset(QuantumStatus::Safe)]);
        assert_eq!(quantum_gate(Some(&inv)), QuantumGate::Pass);
    }

    #[test]
    fn quantum_gate_flags_vulnerable_assets() {
        let inv = inventory(
            CbomStatus::Completed,
            vec![asset(QuantumStatus::Safe), asset(QuantumStatus::Vulnerable)],
        );
        assert_eq!(quantum_gate(Some(&inv)), QuantumGate::Vulnerable);
    }

    #[test]
    fn quantum_gate_treats_unknown_as_not_passing() {
        // 軍規場域寧可誤報不可漏報
        let inv = inventory(CbomStatus::Completed, vec![asset(QuantumStatus::Unknown)]);
        assert_eq!(quantum_gate(Some(&inv)), QuantumGate::Vulnerable);
    }

    #[test]
    fn quantum_gate_ignores_not_applicable() {
        let inv = inventory(
            CbomStatus::Completed,
            vec![asset(QuantumStatus::NotApplicable)],
        );
        assert_eq!(quantum_gate(Some(&inv)), QuantumGate::Pass);
    }

    #[test]
    fn quantum_gate_is_fail_closed_when_no_result() {
        // 「沒掃到」絕不等於「通過」——引擎缺席 / 失敗 / 未請求 / 無 crypto 區段皆為 NoResult
        assert_eq!(quantum_gate(None), QuantumGate::NoResult);
        assert_eq!(
            quantum_gate(Some(&inventory(CbomStatus::EngineAbsent, vec![]))),
            QuantumGate::NoResult
        );
        assert_eq!(
            quantum_gate(Some(&inventory(CbomStatus::NotRequested, vec![]))),
            QuantumGate::NoResult
        );
        assert_eq!(
            quantum_gate(Some(&inventory(
                CbomStatus::Failed {
                    reason_key: "cbom.err.empty_output".into(),
                    reason_detail: None
                },
                vec![]
            ))),
            QuantumGate::NoResult
        );
    }

    #[test]
    fn quantum_gate_passes_on_completed_scan_with_zero_assets() {
        // 跑完且確實沒有密碼資產 → 通過（與「沒掃到」必須區分）
        assert_eq!(
            quantum_gate(Some(&inventory(CbomStatus::Completed, vec![]))),
            QuantumGate::Pass
        );
    }

    #[test]
    fn incomplete_scan_does_not_mask_detected_vulnerabilities() {
        // 清單不完整只能否定「通過」，**不能否定「已偵測到脆弱」**。
        // 真實映像必然含 >1 MiB 的 libcrypto/libstdc++，oversize>0 幾乎必然；
        // 若一律壓成 NoResult，--fail-on-quantum-vulnerable 在 image 目標上三態塌縮、
        // 永遠拿不到 Vulnerable，報表裡幾千項脆弱資產反而被說成「沒掃到」。
        let mut inv = inventory(
            CbomStatus::Completed,
            vec![asset(QuantumStatus::Vulnerable)],
        );
        inv.unscanned_oversize = 26;
        assert_eq!(
            quantum_gate(Some(&inv)),
            QuantumGate::Vulnerable,
            "已偵測到脆弱資產時，不完整不得改判為 NoResult"
        );
    }

    #[test]
    fn incomplete_scan_without_findings_is_no_result() {
        // 沒偵測到脆弱、但有東西沒掃到 → 不得宣告通過
        let mut inv = inventory(CbomStatus::Completed, vec![asset(QuantumStatus::Safe)]);
        inv.unscanned_oversize = 1;
        assert_eq!(quantum_gate(Some(&inv)), QuantumGate::NoResult);
    }

    #[test]
    fn quantum_gate_flags_unscanned_items_as_no_result() {
        // 有東西因權限沒掃到 → 結論不完整，不得宣告通過
        let mut inv = inventory(CbomStatus::Completed, vec![asset(QuantumStatus::Safe)]);
        inv.unscanned_unreadable = 2;
        assert_eq!(quantum_gate(Some(&inv)), QuantumGate::NoResult);
    }

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
