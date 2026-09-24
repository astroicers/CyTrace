//! CyTrace 核心邏輯（SDS §2-5）：解析、嚴重度分級、fail-on。
//!
//! 模組邊界鐵律：業務規則只在本 crate；型別只在 `cytrace-types`；CLI 不含業務邏輯。
//! 嚴重度分級與 fail-on 為**純函式**，不依賴 live 引擎，可用 fixture 完整測試（air-gapped 設計）。

pub mod engine;
pub mod error;
pub mod failon;
pub mod parse;
pub mod quantum;
pub mod severity;
pub mod timefmt;

pub use error::{CytraceError, Result};

use cytrace_types::{Meta, ScanResult, SCHEMA_VERSION};

/// 由已解析的元件與弱點組裝 [`ScanResult`]（注入 meta 與摘要）。
///
/// CBOM 未啟用時 `crypto` 為 `None`；啟用時見 [`assemble_with_crypto`]。
pub fn assemble(
    meta: Meta,
    components: Vec<cytrace_types::Component>,
    findings: Vec<cytrace_types::Vulnerability>,
) -> ScanResult {
    assemble_with_crypto(meta, components, findings, None)
}

/// 檢查 ScanResult 的 `schema_version` 是否超前本 binary 支援的版本（ADR-013 決策 7）。
///
/// 超前代表該檔由**更新版**的 CyTrace 產生：serde 會靜默丟棄未知欄位，
/// 使用者會拿到一份少了東西卻看起來正常的報表。回傳 i18n 鍵讓呼叫端顯性警告。
pub fn schema_warning(schema_version: u32) -> Option<&'static str> {
    (schema_version > cytrace_types::SCHEMA_VERSION).then_some("cli.schema_ahead")
}

/// 遞迴清點目錄下**開檔失敗**的檔案數（ADR-013 決策 10）。
///
/// T901b 實測：`dir` 模式下 theia 讀不到的檔案會被**靜默跳過**——無錯誤、無警告、exit 0。
/// 報表若不標示這件事，等於謊稱資產清單完整。掃描前自行清點，讓缺口可見。
///
/// 讀不到的**目錄**本身也計為一項（其下內容無從得知）。
pub fn unreadable_count(root: &std::path::Path) -> u64 {
    let Ok(entries) = std::fs::read_dir(root) else {
        return 1; // 目錄不可讀：內容無從得知，整體計為一項缺口
    };
    let mut n = 0;
    for entry in entries.flatten() {
        let path = entry.path();
        // symlink 不追（避免循環與重複計數）
        let Ok(meta) = std::fs::symlink_metadata(&path) else {
            n += 1;
            continue;
        };
        if meta.is_symlink() {
            continue;
        }
        if meta.is_dir() {
            n += unreadable_count(&path);
        } else if std::fs::File::open(&path).is_err() {
            n += 1;
        }
    }
    n
}

/// 執行 CBOM 掃描並組成 [`cytrace_types::CryptoInventory`]（ADR-013 決策 4）。
///
/// **永不回傳錯誤**——CBOM 的任何問題都只反映在 `status`，不中止 SBOM / CVE 主流程：
/// 引擎缺席 → `EngineAbsent`；執行失敗或輸出無法解析 → `Failed { reason_key }`。
/// 解析成功（即使 0 項資產）→ `Completed`。
pub fn collect_cbom(
    engine: &dyn engine::ScanEngine,
    target: &str,
) -> cytrace_types::CryptoInventory {
    collect_cbom_with_raw(engine, target).0
}

/// 同 [`collect_cbom`]，另回傳引擎的**原始 JSON**供原樣落地（ADR-013 決策 5）。
///
/// 呼叫端**不得**為了取得原始輸出而再跑一次引擎：那會讓掃描成本加倍，
/// 在 server 併發下也加倍干擾。
pub fn collect_cbom_with_raw(
    engine: &dyn engine::ScanEngine,
    target: &str,
) -> (cytrace_types::CryptoInventory, Option<String>) {
    use cytrace_types::{CbomStatus, CryptoInventory};

    let failed = |e: CytraceError| CryptoInventory {
        status: CbomStatus::Failed {
            reason_key: e.to_string(),
        },
        ..Default::default()
    };

    let raw = match engine.cbom(target) {
        Ok(None) => {
            return (
                CryptoInventory {
                    status: CbomStatus::EngineAbsent,
                    ..Default::default()
                },
                None,
            )
        }
        Ok(Some(out)) => out,
        Err(e) => return (failed(e), None),
    };

    let inv = match parse::parse_cbom(&raw.json) {
        Ok(assets) => CryptoInventory {
            status: CbomStatus::Completed,
            assets,
            // 兩種靜默漏檢都要計入，否則 unscanned_count=0 會讓量子閘門回報假 Pass：
            //   1. 權限不足：dir 模式下 theia 讀不到的檔案被無聲跳過（image 模式讀 layer，不適用）
            //   2. 引擎門檻：theia 略過 >1 MiB 的檔案，只在 stderr 警告、exit 仍為 0
            // 兩種成因分開記：權限可由操作員解決，引擎門檻不行（文案與處置都不同）。
            // `raw.skipped` 隨該次呼叫回傳，不經共用狀態——server 併發下不會互相污染。
            unscanned_oversize: raw.skipped,
            unscanned_unreadable: match engine::cbom_target(target) {
                Ok(engine::CbomTarget::Dir(p)) => unreadable_count(&p),
                _ => 0,
            },
        },
        Err(e) => failed(e),
    };
    (inv, Some(raw.json))
}

/// 同 [`assemble`]，並附上 CBOM 盤點結果（ADR-013）。
pub fn assemble_with_crypto(
    meta: Meta,
    components: Vec<cytrace_types::Component>,
    findings: Vec<cytrace_types::Vulnerability>,
    crypto: Option<cytrace_types::CryptoInventory>,
) -> ScanResult {
    let summary = severity::summarize(&findings);
    ScanResult {
        schema_version: SCHEMA_VERSION,
        meta,
        components,
        findings,
        summary,
        crypto,
    }
}
