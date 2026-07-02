//! CyTrace 核心邏輯（SDS §2-5）：解析、嚴重度分級、fail-on。
//!
//! 模組邊界鐵律：業務規則只在本 crate；型別只在 `cytrace-types`；CLI 不含業務邏輯。
//! 嚴重度分級與 fail-on 為**純函式**，不依賴 live 引擎，可用 fixture 完整測試（air-gapped 設計）。

pub mod engine;
pub mod error;
pub mod failon;
pub mod parse;
pub mod severity;
pub mod timefmt;

pub use error::{CytraceError, Result};

use cytrace_types::{Meta, ScanResult, SCHEMA_VERSION};

/// 由已解析的元件與弱點組裝 [`ScanResult`]（注入 meta 與摘要）。
pub fn assemble(
    meta: Meta,
    components: Vec<cytrace_types::Component>,
    findings: Vec<cytrace_types::Vulnerability>,
) -> ScanResult {
    let summary = severity::summarize(&findings);
    ScanResult {
        schema_version: SCHEMA_VERSION,
        meta,
        components,
        findings,
        summary,
    }
}
