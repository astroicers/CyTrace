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

/// 執行 CBOM 掃描並組成 [`cytrace_types::CryptoInventory`]（ADR-013 決策 4）。
///
/// **永不回傳錯誤**——CBOM 的任何問題都只反映在 `status`，不中止 SBOM / CVE 主流程：
/// 引擎缺席 → `EngineAbsent`；執行失敗或輸出無法解析 → `Failed { reason_key }`。
/// 解析成功（即使 0 項資產）→ `Completed`。
pub fn collect_cbom(
    engine: &dyn engine::ScanEngine,
    target: &str,
) -> cytrace_types::CryptoInventory {
    use cytrace_types::{CbomStatus, CryptoInventory};

    let failed = |e: CytraceError| CryptoInventory {
        status: CbomStatus::Failed {
            reason_key: e.to_string(),
        },
        ..Default::default()
    };

    match engine.cbom(target) {
        Ok(None) => CryptoInventory {
            status: CbomStatus::EngineAbsent,
            ..Default::default()
        },
        Ok(Some(json)) => match parse::parse_cbom(&json) {
            Ok(assets) => CryptoInventory {
                status: CbomStatus::Completed,
                assets,
                unscanned_count: 0,
            },
            Err(e) => failed(e),
        },
        Err(e) => failed(e),
    }
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
