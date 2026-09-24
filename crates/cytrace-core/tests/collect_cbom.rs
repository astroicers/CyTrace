//! T905：CBOM 收集的降級語意（ADR-013 決策 4）。
//!
//! 以 fake 引擎驗證——**不需要 theia binary**（air-gapped CI 可跑）。
//! 關鍵不變量：CBOM 出任何問題都只影響 CBOM 區段，絕不中止 SBOM / CVE 主流程。

use cytrace_core::engine::ScanEngine;
use cytrace_core::{collect_cbom, CytraceError, Result};
use cytrace_types::{CbomStatus, QuantumStatus};

struct Engine(Result<Option<String>>);

/// 引擎回報「因大小門檻略過 N 個檔案」的 fake。
struct SkippingEngine(u64);

impl ScanEngine for SkippingEngine {
    fn sbom(&self, _t: &str) -> Result<String> {
        Ok("{}".into())
    }
    fn vuln(&self, _s: &str) -> Result<String> {
        Ok(r#"{"matches":[]}"#.into())
    }
    fn cbom(&self, _t: &str) -> Result<Option<String>> {
        Ok(Some(r#"{"bomFormat":"CycloneDX"}"#.into()))
    }
    fn cbom_skipped(&self) -> u64 {
        self.0
    }
}

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

// ── 因權限未掃描的項目計數（ADR-013 決策 10）──

#[test]
#[cfg(unix)]
fn unreadable_files_in_dir_target_are_counted() {
    // T901b 實測：dir 模式下 theia 讀不到的檔案會被**靜默跳過**（無錯誤、exit 0）。
    // 報表若顯示「0 項未掃描」等於謊稱清單完整，故必須自行清點。
    use cytrace_core::unreadable_count;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;

    let dir = std::env::temp_dir().join(format!("cytrace-unreadable-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(dir.join("sub")).expect("建立目錄");
    fs::write(dir.join("readable.crt"), b"x").expect("可讀檔");
    fs::write(dir.join("sub/secret.key"), b"x").expect("不可讀檔");
    fs::set_permissions(
        dir.join("sub/secret.key"),
        fs::Permissions::from_mode(0o000),
    )
    .expect("設定權限");

    let root_can_read_anything = fs::File::open(dir.join("sub/secret.key")).is_ok();
    let n = unreadable_count(&dir);
    let _ = fs::remove_dir_all(&dir);

    if root_can_read_anything {
        assert_eq!(n, 0, "以 root 執行時本就讀得到，計數應為 0");
    } else {
        assert_eq!(n, 1, "應清點出 1 個不可讀檔案（遞迴含子目錄）");
    }
}

#[test]
#[cfg(unix)]
fn collect_cbom_reports_unscanned_items_for_dir_targets() {
    // 接線驗證：掃描完成但有讀不到的檔 → unscanned_count 必須反映出來，
    // 否則報表會謊稱清單完整（決策 10 的唯一緩解手段）
    use std::fs;
    use std::os::unix::fs::PermissionsExt;

    let dir = std::env::temp_dir().join(format!("cytrace-collect-unscan-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).expect("建立目錄");
    fs::write(dir.join("ok.crt"), b"x").expect("可讀檔");
    fs::write(dir.join("locked.key"), b"x").expect("不可讀檔");
    fs::set_permissions(dir.join("locked.key"), fs::Permissions::from_mode(0o000))
        .expect("設定權限");
    let skipped = fs::File::open(dir.join("locked.key")).is_err();

    let inv = collect_cbom(
        &Engine(Ok(Some(r#"{"bomFormat":"CycloneDX"}"#.into()))),
        dir.to_str().unwrap(),
    );
    let _ = fs::remove_dir_all(&dir);

    assert_eq!(inv.status, CbomStatus::Completed);
    if skipped {
        assert_eq!(
            inv.unscanned_count, 1,
            "讀不到的檔案必須計入 unscanned_count"
        );
    }
}

#[test]
fn fully_readable_dir_counts_zero_unreadable() {
    use cytrace_core::unreadable_count;
    use std::fs;
    let dir = std::env::temp_dir().join(format!("cytrace-readable-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).expect("建立目錄");
    fs::write(dir.join("a.crt"), b"x").expect("寫檔");
    let n = unreadable_count(&dir);
    let _ = fs::remove_dir_all(&dir);
    assert_eq!(n, 0);
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

#[test]
fn engine_skipped_files_are_counted_as_unscanned() {
    // 複審實測：theia 略過 >1 MiB 的檔案且 exit 0；不併入 unscanned_count 的話，
    // 量子閘門會對「其實沒掃完」的目標回報 Pass（假通過）。
    let inv = collect_cbom(&SkippingEngine(3), "dir:/x");
    assert_eq!(inv.status, CbomStatus::Completed);
    assert_eq!(
        inv.unscanned_count, 3,
        "引擎因大小門檻略過的檔案必須計入 unscanned_count"
    );
}

#[test]
fn quantum_gate_does_not_pass_when_engine_skipped_files() {
    use cytrace_core::failon::{quantum_gate, QuantumGate};
    let inv = collect_cbom(&SkippingEngine(1), "dir:/x");
    assert_eq!(
        quantum_gate(Some(&inv)),
        QuantumGate::NoResult,
        "有檔案沒掃到時閘門不得回報通過"
    );
}

// ── schema_version 超前警告（ADR-013 決策 7）──

#[test]
fn future_schema_version_is_detected() {
    use cytrace_core::schema_warning;
    // 舊版 binary 讀到新版檔案會靜默丟棄未知欄位——唯一的提示就是這個警告
    assert!(schema_warning(3).is_some(), "超前版本須有警告");
    assert!(schema_warning(2).is_none(), "同版不警告");
    assert!(schema_warning(1).is_none(), "舊版可讀，不警告");
}

// ── NFR-03 可稽核：報表須標示真實工具版本與執行身分 ──

#[test]
fn version_output_is_parsed_from_engine_banner() {
    use cytrace_core::engine::parse_version_output;
    assert_eq!(parse_version_output("syft 1.51.1\n"), Some("1.51.1".into()));
    assert_eq!(
        parse_version_output("grype 0.114.0"),
        Some("0.114.0".into())
    );
    // 多行輸出取第一行
    assert_eq!(
        parse_version_output("grype 0.114.0\nApplication: grype\n"),
        Some("0.114.0".into())
    );
    assert_eq!(parse_version_output(""), None);
    assert_eq!(parse_version_output("garbage"), None);
}

#[test]
fn scan_identity_reports_the_effective_uid() {
    use cytrace_core::engine::scan_identity;
    let id = scan_identity();
    // 權限會決定 dir 模式的偵測完整度，故執行身分必須可稽核（ADR-013 決策 10）
    assert!(id.starts_with("uid="), "須為 uid=<n> 形式，實得 {id}");
    assert!(
        id["uid=".len()..].chars().all(|c| c.is_ascii_digit()),
        "uid 須為數字，實得 {id}"
    );
}
