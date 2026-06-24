//! CyTrace 共用領域型別（SDS §2）。
//!
//! 本 crate 只放資料型別與其純函式行為，**不含**子程序編排、解析或 I/O。
//! 業務邏輯（風險總評、fail-on、解析）一律在 `cytrace-core`。

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// 弱點嚴重度六級（ADR-006）。
///
/// 變體**宣告順序即排序**（`Ord` derive）：`Unknown` 最低、`Critical` 最高，
/// 因此 `findings.iter().map(|v| v.severity).max()` 會選出最高真實等級；
/// 全為 `Unknown` 時總評才是 `Unknown`。
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum Severity {
    Unknown,
    Negligible,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    /// 由 Grype 輸出的嚴重度字串解析（大小寫不敏感）；無法辨識者歸為 [`Severity::Unknown`]。
    pub fn from_grype_str(s: &str) -> Self {
        match s.trim().to_ascii_lowercase().as_str() {
            "critical" => Severity::Critical,
            "high" => Severity::High,
            "medium" => Severity::Medium,
            "low" => Severity::Low,
            "negligible" => Severity::Negligible,
            _ => Severity::Unknown,
        }
    }

    /// i18n 訊息鍵（ADR-004 / ADR-006）。前端 react-i18next 與 CLI catalog 共用同一鍵。
    pub fn i18n_key(&self) -> &'static str {
        match self {
            Severity::Critical => "severity.critical",
            Severity::High => "severity.high",
            Severity::Medium => "severity.medium",
            Severity::Low => "severity.low",
            Severity::Negligible => "severity.negligible",
            Severity::Unknown => "severity.unknown",
        }
    }

    /// 六級由高到低，供報表/總評列舉時固定順序。
    pub fn all_high_to_low() -> [Severity; 6] {
        [
            Severity::Critical,
            Severity::High,
            Severity::Medium,
            Severity::Low,
            Severity::Negligible,
            Severity::Unknown,
        ]
    }
}

/// 軟體元件（→ 報表「軟體產品文件表」/ SBOM）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Component {
    pub name: String,
    pub version: String,
    #[serde(rename = "type")]
    pub kind: String,
    #[serde(default)]
    pub licenses: Vec<String>,
}

/// 單一弱點（CVE 比對結果）。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Vulnerability {
    pub id: String,
    pub severity: Severity,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub cvss: Option<f64>,
    pub component: String,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub fixed_version: Option<String>,
    pub source: String,
}

/// 漏洞 DB 離線快照資訊（ADR-003；報表須揭露時效）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DbSnapshot {
    pub version: String,
    pub built: String,
}

/// 引擎版本（釘選；NFR-02 / ADR-002）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ToolVersions {
    pub syft: String,
    pub grype: String,
}

/// 掃描元資料。`generated_at` 為非決定性欄位，golden baseline 比對前須正規化/排除（ADR-008/009）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Meta {
    pub target: String,
    pub tool_versions: ToolVersions,
    pub db_snapshot: DbSnapshot,
    pub generated_at: String,
}

/// 風險摘要。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Summary {
    pub counts_by_severity: BTreeMap<Severity, u64>,
    pub overall_risk: Severity,
}

/// 統一掃描結果——core ↔ report 的穩定資料契約（ADR-009）。
///
/// `schema_version` 版本化稽核產物；新版 `cytrace report` 須能重現舊版 JSON。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ScanResult {
    pub schema_version: u32,
    pub meta: Meta,
    pub components: Vec<Component>,
    pub findings: Vec<Vulnerability>,
    pub summary: Summary,
}

/// 目前的 ScanResult schema 版本（ADR-009 相容政策）。
pub const SCHEMA_VERSION: u32 = 1;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn grype_strings_map_to_severity_case_insensitively() {
        assert_eq!(Severity::from_grype_str("Critical"), Severity::Critical);
        assert_eq!(Severity::from_grype_str("high"), Severity::High);
        assert_eq!(Severity::from_grype_str("  MEDIUM "), Severity::Medium);
        assert_eq!(Severity::from_grype_str("Negligible"), Severity::Negligible);
    }

    #[test]
    fn unrecognized_severity_is_unknown() {
        assert_eq!(Severity::from_grype_str(""), Severity::Unknown);
        assert_eq!(Severity::from_grype_str("bogus"), Severity::Unknown);
        assert_eq!(Severity::from_grype_str("Unknown"), Severity::Unknown);
    }

    #[test]
    fn severity_orders_critical_highest_unknown_lowest() {
        assert!(Severity::Critical > Severity::High);
        assert!(Severity::High > Severity::Medium);
        assert!(Severity::Medium > Severity::Low);
        assert!(Severity::Low > Severity::Negligible);
        assert!(Severity::Negligible > Severity::Unknown);
        // 一個真實等級永遠勝過 Unknown
        assert_eq!(
            [Severity::Unknown, Severity::Low].into_iter().max(),
            Some(Severity::Low)
        );
    }

    #[test]
    fn i18n_keys_are_stable() {
        assert_eq!(Severity::Critical.i18n_key(), "severity.critical");
        assert_eq!(Severity::Unknown.i18n_key(), "severity.unknown");
    }
}
