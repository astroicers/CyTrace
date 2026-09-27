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

/// 引擎版本（釘選；NFR-02 / ADR-002 / ADR-013）。
///
/// `theia` 為 CBOM 引擎（ADR-013）；v1 ScanResult 無此欄位，故帶 `default`（NFR-03）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ToolVersions {
    pub syft: String,
    pub grype: String,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub theia: Option<String>,
}

/// 掃描元資料。`generated_at` 為非決定性欄位，golden baseline 比對前須正規化/排除（ADR-008/009）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Meta {
    pub target: String,
    pub tool_versions: ToolVersions,
    pub db_snapshot: DbSnapshot,
    pub generated_at: String,
    /// 執行掃描的身分（ADR-013 決策 10）。權限會影響 `dir` 模式的偵測完整度，故須可稽核。
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub scan_identity: Option<String>,
}

/// 風險摘要。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Summary {
    pub counts_by_severity: BTreeMap<Severity, u64>,
    pub overall_risk: Severity,
}

/// 量子脆弱判定結果（ADR-013 決策 6）。
///
/// **與弱金鑰是兩條獨立的軸**：RSA-4096 為 [`QuantumStatus::Vulnerable`] 但非弱金鑰。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum QuantumStatus {
    /// 後量子安全（PQC 演算法，或 NIST 量子安全等級達門檻）。
    Safe,
    /// 量子脆弱（可被 Shor 演算法破解之公鑰系統）。
    Vulnerable,
    /// 不適用（對稱演算法、雜湊等非公鑰系統）。
    NotApplicable,
    /// 無法判定（未知演算法或曲線）——**不臆測**。
    Unknown,
}

impl QuantumStatus {
    /// i18n 訊息鍵（ADR-004）。前端與 CLI catalog 共用同一鍵。
    pub fn i18n_key(&self) -> &'static str {
        match self {
            QuantumStatus::Safe => "crypto.quantum.safe",
            QuantumStatus::Vulnerable => "crypto.quantum.vulnerable",
            QuantumStatus::NotApplicable => "crypto.quantum.not_applicable",
            QuantumStatus::Unknown => "crypto.quantum.unknown",
        }
    }
}

/// CBOM 掃描狀態（ADR-013 決策 4/7）。
///
/// 「沒開」「引擎不在」「失敗」「跑了但 0 項」四者必須可區分——
/// 空輸出**絕不**映射為「掃到 0 項」。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CbomStatus {
    /// 使用者未指定 `--cbom`。
    NotRequested,
    /// 指定了，但引擎 binary 不存在（降級，不影響主流程）。
    EngineAbsent,
    /// 執行或解析失敗。
    ///
    /// `reason_key` 為**純 i18n 鍵**（如 `cbom.err.timeout`），不含散文——
    /// 黏上中文散文的話 `--lang en-US` 會吐中文，且該字串會寫進 `scan-result.json`
    /// 並經 API 對外（違反 i18n 雙語強制鐵則）。不可翻譯的細節放 `reason_detail`。
    Failed {
        reason_key: String,
        #[serde(skip_serializing_if = "Option::is_none", default)]
        reason_detail: Option<String>,
    },
    /// 正常完成（`assets` 可能為空，代表確實沒掃到密碼資產）。
    Completed,
}

/// 單一密碼學資產（CycloneDX `cryptographic-asset` 子集；ADR-013 決策 7）。
///
/// **不含金鑰內容**（NFR-09）——只記錄存在、型別、長度、位置。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CryptoAsset {
    pub name: String,
    pub asset_type: String,
    pub quantum: QuantumStatus,
    /// 弱金鑰（RSA < 2048、ECC 曲線強度 < 128-bit）；與 `quantum` 為獨立兩軸。
    pub weak_key: bool,
    pub location: String,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub primitive: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub key_size: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub not_after: Option<String>,
}

/// CBOM 盤點結果（ADR-013 決策 7）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CryptoInventory {
    pub status: CbomStatus,
    #[serde(default)]
    pub assets: Vec<CryptoAsset>,
    /// 因**權限不可讀**而未掃描的項目數（ADR-013 決策 10）。
    ///
    /// 與 [`CryptoInventory::unscanned_oversize`] 分開記：兩者的處置完全不同——
    /// 這一項可由操作員調整權限或改以適當身分重跑解決。
    #[serde(default)]
    pub unscanned_unreadable: u64,
    /// 因**引擎自身大小門檻**（theia 略過 >1 MiB 的檔案）而未掃描的檔案數。
    ///
    /// 操作員**無法**以權限或身分解決；theia 1.1.2 亦無可調門檻的旗標。
    #[serde(default)]
    pub unscanned_oversize: u64,
    /// 引擎**自承偵測到、但未出現在輸出**的資產數（例如 OpenSSH 格式私鑰）。
    ///
    /// 操作員同樣無法以權限或參數解決；屬引擎建模覆蓋率的缺口。
    #[serde(default)]
    pub unscanned_undetermined: u64,
}

impl CryptoInventory {
    /// 未掃描項目總數——量子閘門以此判定結論是否完整（ADR-013 決策 9）。
    pub fn unscanned_total(&self) -> u64 {
        self.unscanned_unreadable + self.unscanned_oversize + self.unscanned_undetermined
    }
}

impl Default for CryptoInventory {
    fn default() -> Self {
        Self {
            status: CbomStatus::NotRequested,
            assets: Vec::new(),
            unscanned_unreadable: 0,
            unscanned_oversize: 0,
            unscanned_undetermined: 0,
        }
    }
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
    /// CBOM 密碼學資產盤點（ADR-013）。v1 檔無此欄位 → `None`。
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub crypto: Option<CryptoInventory>,
}

/// 目前的 ScanResult schema 版本（ADR-009 相容政策；v2 起含 `crypto`，見 ADR-013）。
pub const SCHEMA_VERSION: u32 = 2;

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

    // ── T903：CBOM 資料契約（ADR-013 決策 7；修訂 ADR-009）──

    fn v1_scanresult_json() -> &'static str {
        // 真實 v1 形狀（無 crypto 欄位）——ADR-009 向後相容的驗收標的
        r#"{
            "schema_version": 1,
            "meta": {
                "target": "dir:/tmp/x",
                "tool_versions": {"syft": "1.45.1", "grype": "0.114.0"},
                "db_snapshot": {"version": "5", "built": "2026-07-01T00:00:00Z"},
                "generated_at": "2026-07-01T00:00:00Z"
            },
            "components": [],
            "findings": [],
            "summary": {"counts_by_severity": {}, "overall_risk": "Unknown"}
        }"#
    }

    #[test]
    fn schema_version_is_2() {
        assert_eq!(SCHEMA_VERSION, 2);
    }

    #[test]
    fn v1_scanresult_without_crypto_still_deserializes() {
        let r: ScanResult = serde_json::from_str(v1_scanresult_json()).expect("v1 須可讀入");
        assert_eq!(r.schema_version, 1);
        assert!(r.crypto.is_none(), "v1 檔無 crypto 欄位 → None");
    }

    #[test]
    fn v1_scanresult_tool_versions_without_theia_still_deserializes() {
        let r: ScanResult = serde_json::from_str(v1_scanresult_json()).expect("v1 須可讀入");
        assert_eq!(r.meta.tool_versions.theia, None, "theia 欄位須有 default");
        assert_eq!(r.meta.scan_identity, None, "scan_identity 須有 default");
    }

    #[test]
    fn cbom_status_distinguishes_not_requested_from_completed_with_zero_assets() {
        // ADR-013 決策 4/7：「沒開」「引擎不在」「失敗」「跑了但 0 項」必須可區分
        let not_requested = CryptoInventory {
            status: CbomStatus::NotRequested,
            ..CryptoInventory::default()
        };
        let completed_empty = CryptoInventory {
            status: CbomStatus::Completed,
            ..CryptoInventory::default()
        };
        assert_ne!(not_requested.status, completed_empty.status);
        assert!(not_requested.assets.is_empty());
        assert!(completed_empty.assets.is_empty());
    }

    /// `CbomStatus` 的**序列化形式**是跨語言契約：`frontend/src/types.ts` 宣告
    /// 單位變體為字串、`Failed` 為 `{ Failed: { reason_key, reason_detail? } }`
    /// （serde 預設的 externally-tagged 形式）。在 Rust 端加 `#[serde(tag=…)]`、
    /// 改變體名或改欄位名，前端的 `'Failed' in s` 判定會**靜默**失效——報表把
    /// 失敗顯示成「掃到 0 項」，正是 ADR-013 決策 4 要防的那件事。
    ///
    /// （原測試把 reason_key 放進去再取出來比對，只驗證了 Rust 的 struct literal
    /// 語意，換成任何欄位名都會通過；第六輪複審 minor。）
    #[test]
    fn cbom_status_serialization_matches_the_frontend_contract() {
        use serde_json::json;
        let cases = [
            (CbomStatus::NotRequested, json!("NotRequested")),
            (CbomStatus::EngineAbsent, json!("EngineAbsent")),
            (CbomStatus::Completed, json!("Completed")),
            (
                CbomStatus::Failed {
                    reason_key: "cbom.err.stdout_not_json".into(),
                    reason_detail: None,
                },
                json!({"Failed": {"reason_key": "cbom.err.stdout_not_json"}}),
            ),
            (
                CbomStatus::Failed {
                    reason_key: "cbom.err.timeout".into(),
                    reason_detail: Some("600".into()),
                },
                json!({"Failed": {"reason_key": "cbom.err.timeout", "reason_detail": "600"}}),
            ),
        ];
        for (status, expected) in cases {
            let actual = serde_json::to_value(&status).expect("序列化");
            assert_eq!(actual, expected, "序列化形式與前端契約不符");
            // 往返：舊報表重建（cytrace report）依賴反序列化回同一變體
            let back: CbomStatus = serde_json::from_value(actual).expect("反序列化");
            assert_eq!(
                serde_json::to_value(&back).unwrap(),
                expected,
                "往返後形式須不變"
            );
        }
    }

    #[test]
    fn quantum_status_i18n_keys_are_stable() {
        assert_eq!(QuantumStatus::Safe.i18n_key(), "crypto.quantum.safe");
        assert_eq!(
            QuantumStatus::Vulnerable.i18n_key(),
            "crypto.quantum.vulnerable"
        );
        assert_eq!(
            QuantumStatus::NotApplicable.i18n_key(),
            "crypto.quantum.not_applicable"
        );
        assert_eq!(QuantumStatus::Unknown.i18n_key(), "crypto.quantum.unknown");
    }

    #[test]
    fn crypto_asset_omits_optional_fields_when_none() {
        // golden 穩定性（ADR-013 決策 7）：未知欄位不得序列化成 null
        let a = CryptoAsset {
            name: "RSA-2048".into(),
            asset_type: "related-crypto-material".into(),
            quantum: QuantumStatus::Vulnerable,
            weak_key: false,
            location: "app/server.key".into(),
            primitive: None,
            key_size: None,
            not_after: None,
        };
        let j = serde_json::to_string(&a).expect("序列化");
        assert!(!j.contains("primitive"), "None 欄位不得出現：{j}");
        assert!(!j.contains("null"), "不得有 null：{j}");
        assert!(j.contains("\"weak_key\":false"), "weak_key 須恆常序列化");
    }

    #[test]
    fn unscanned_count_defaults_to_zero_and_survives_roundtrip() {
        // ADR-013 決策 10：因權限未掃描的項目數不得無聲消失
        let inv = CryptoInventory {
            status: CbomStatus::Completed,
            unscanned_unreadable: 3,
            unscanned_oversize: 2,
            ..CryptoInventory::default()
        };
        let j = serde_json::to_string(&inv).expect("序列化");
        let back: CryptoInventory = serde_json::from_str(&j).expect("反序列化");
        assert_eq!(back.unscanned_unreadable, 3);
        assert_eq!(back.unscanned_oversize, 2);
        assert_eq!(back.unscanned_total(), 5, "兩種成因合計才是閘門的判準");
        assert_eq!(CryptoInventory::default().unscanned_total(), 0);
    }
}
