//! T905：CBOM 收集的降級語意（ADR-013 決策 4）。
//!
//! 以 fake 引擎驗證——**不需要 theia binary**（air-gapped CI 可跑）。
//! 關鍵不變量：CBOM 出任何問題都只影響 CBOM 區段，絕不中止 SBOM / CVE 主流程。

use cytrace_core::engine::ScanEngine;
use cytrace_core::{collect_cbom, CytraceError, Result};
use cytrace_types::{CbomStatus, QuantumStatus};

struct Engine(Result<Option<String>>);

impl ScanEngine for Engine {
    fn sbom(&self, _t: &str) -> Result<String> {
        Ok("{}".into())
    }
    fn vuln(&self, _s: &str) -> Result<String> {
        Ok(r#"{"matches":[]}"#.into())
    }
    fn cbom(&self, _t: &str) -> Result<Option<String>> {
        match &self.0 {
            Ok(v) => Ok(v.clone()),
            Err(e) => Err(CytraceError::Engine(e.to_string())),
        }
    }
}

fn cbom_json() -> String {
    std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/cbom.json"
    ))
    .expect("讀取 fixture")
}

#[test]
fn absent_engine_degrades_to_engine_absent() {
    let inv = collect_cbom(&Engine(Ok(None)), "dir:/x");
    assert_eq!(inv.status, CbomStatus::EngineAbsent);
    assert!(inv.assets.is_empty());
}

#[test]
fn engine_failure_is_recorded_not_propagated() {
    let inv = collect_cbom(&Engine(Err(CytraceError::Engine("boom".into()))), "dir:/x");
    assert!(
        matches!(inv.status, CbomStatus::Failed { .. }),
        "執行失敗須記為 Failed，不得中止主流程"
    );
}

#[test]
fn unparseable_output_is_failed_not_zero_assets() {
    // 空輸出/壞 JSON 絕不可變成「掃到 0 項」
    let inv = collect_cbom(&Engine(Ok(Some("{ not json".into()))), "dir:/x");
    assert!(matches!(inv.status, CbomStatus::Failed { .. }));
    assert!(inv.assets.is_empty());
}

#[test]
fn successful_scan_yields_completed_with_assets() {
    let inv = collect_cbom(&Engine(Ok(Some(cbom_json()))), "dir:/x");
    assert_eq!(inv.status, CbomStatus::Completed);
    assert_eq!(inv.assets.len(), 12);
    assert!(inv
        .assets
        .iter()
        .any(|a| a.quantum == QuantumStatus::Vulnerable));
}

/// 真實引擎端到端（需要 `cbomkit-theia` 在 PATH，故預設略過）。
///
/// 跑法：`cargo test -p cytrace-core --test collect_cbom -- --ignored`
#[test]
#[ignore = "需要 cbomkit-theia binary；air-gapped CI 預設略過"]
fn real_engine_end_to_end_against_temp_fixture() {
    use cytrace_core::engine::RealEngine;
    use std::fs;

    let dir = std::env::temp_dir().join(format!("cytrace-cbom-e2e-{}", std::process::id()));
    fs::create_dir_all(&dir).expect("建立暫存目錄");
    // 自簽憑證（非真實金鑰）：只驗管線，不驗密碼學強度
    fs::write(
        dir.join("test.crt"),
        include_str!("fixtures/e2e-selfsigned.crt"),
    )
    .expect("寫入 fixture 憑證");

    let inv = collect_cbom(&RealEngine, dir.to_str().unwrap());
    let _ = fs::remove_dir_all(&dir);

    assert_eq!(
        inv.status,
        CbomStatus::Completed,
        "真實引擎應能完成掃描（未安裝 theia 時請用 --ignored 以外的方式略過）"
    );
    assert!(!inv.assets.is_empty(), "自簽憑證應產生密碼學資產");
    let json = serde_json::to_string(&inv.assets).expect("序列化");
    assert!(!json.contains("PRIVATE KEY"), "NFR-09：輸出不得含金鑰內容");
}

#[test]
fn empty_but_valid_cbom_is_completed_with_zero_assets() {
    // 跑完確實沒資產 → Completed（與 Failed / EngineAbsent 必須可區分）
    let inv = collect_cbom(
        &Engine(Ok(Some(r#"{"bomFormat":"CycloneDX"}"#.into()))),
        "dir:/x",
    );
    assert_eq!(inv.status, CbomStatus::Completed);
    assert!(inv.assets.is_empty());
}
