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
    let mut visited = std::collections::HashSet::new();
    unreadable_count_inner(root, &mut visited, 0)
}

/// [`unreadable_count`] 的遞迴本體。
///
/// **追隨 symlink**（與 theia 的 dir 模式一致）：symlink 是引擎的實際掃描對象，
/// 一律 `continue` 會把整個類別排除在缺口帳外——解開的容器 rootfs 上
/// `/etc/ssl/certs/*.pem` 多為絕對 symlink，逃根後讀不到卻不被計數，
/// 於是報表宣稱清單完整、閘門回 Pass（fail-open）。
///
/// 以已訪問的 canonical 路徑集合防循環，並設遞迴深度上限。
fn unreadable_count_inner(
    dir: &std::path::Path,
    visited: &mut std::collections::HashSet<std::path::PathBuf>,
    depth: usize,
) -> u64 {
    const MAX_DEPTH: usize = 64;
    if depth > MAX_DEPTH {
        return 0;
    }
    // 同一個實體目錄只走一次（symlink 循環防護）
    match std::fs::canonicalize(dir) {
        Ok(real) => {
            if !visited.insert(real) {
                return 0;
            }
        }
        Err(_) => return 1, // 連 canonicalize 都失敗：內容無從得知
    }

    let Ok(entries) = std::fs::read_dir(dir) else {
        return 1; // 目錄不可讀：內容無從得知，整體計為一項缺口
    };
    let mut n = 0;
    for entry in entries.flatten() {
        let path = entry.path();
        // 追隨 symlink：用 metadata（非 symlink_metadata）判定型別。
        // 斷鏈或指向不可讀處時 metadata 本身就會失敗 → 計為缺口。
        let Ok(meta) = std::fs::metadata(&path) else {
            n += 1;
            continue;
        };
        if meta.is_dir() {
            n += unreadable_count_inner(&path, visited, depth + 1);
        } else if meta.is_file() {
            // 只對一般檔開檔：FIFO / socket / device 開下去會阻塞
            if std::fs::File::open(&path).is_err() {
                n += 1;
            }
        }
    }
    n
}

/// 清點 stdout 中的**私鑰**資產數（與引擎自承的「private key」同量綱）。
pub fn modelled_key_count(assets: &[cytrace_types::CryptoAsset]) -> u64 {
    assets
        .iter()
        .filter(|a| a.primitive.as_deref() == Some("private-key"))
        .count() as u64
}

/// 清點 stdout 中的**憑證**資產數（與引擎自承的「certificate」同量綱）。
pub fn modelled_cert_count(assets: &[cytrace_types::CryptoAsset]) -> u64 {
    assets
        .iter()
        .filter(|a| a.asset_type == "certificate")
        .count() as u64
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

    // 解析失敗不得把已算出的漏檢成因歸零——那是操作員唯一的處置線索
    // （唯一的資產可能就在那個被略過的 CA bundle 裡）。
    let failed = |e: CytraceError, oversize: u64| CryptoInventory {
        status: match &e {
            // 純鍵 + 細節分開存，供呼叫端依語系渲染
            CytraceError::Cbom { key, detail } => CbomStatus::Failed {
                reason_key: (*key).to_string(),
                reason_detail: detail.clone(),
            },
            // 其他錯誤型別沒有對應鍵，以通用鍵承接。
            // **細節只放不可翻譯的部分**，不得帶 CytraceError 的中文 Display 前綴
            // ——否則 --lang en-US 下仍會吐中文（第六輪 finding C）。
            // 走型別上的單一出口，而非在此逐變體 match：第六輪在這裡只列了三個變體，
            // Io 與 DbMissing 落到 `_ => to_string()` 繼續帶中文（第七輪複審）。
            other => CbomStatus::Failed {
                reason_key: "cbom.err.engine".to_string(),
                reason_detail: other.untranslatable_detail(),
            },
        },
        assets: Vec::new(),
        unscanned_oversize: oversize,
        unscanned_unreadable: 0,
        unscanned_undetermined: 0,
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
        Err(e) => return (failed(e, 0), None),
    };

    let inv = match parse::parse_cbom(&raw.json) {
        Ok(assets) => CryptoInventory {
            status: CbomStatus::Completed,
            // **分類別**對帳：自承私鑰數扣建模私鑰數、自承憑證數扣建模憑證數。
            // 跨類別相減會讓混合資產目標抵銷成 0（第五輪複審實測）。
            unscanned_undetermined: engine::undetermined_count(
                raw.admitted_keys,
                modelled_key_count(&assets),
            ) + engine::undetermined_count(
                raw.admitted_certs,
                modelled_cert_count(&assets),
            ),
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
        Err(e) => failed(e, raw.skipped),
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
