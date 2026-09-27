//! T905：CBOM 收集的降級語意（ADR-013 決策 4）。
//!
//! 以 fake 引擎驗證——**不需要 theia binary**（air-gapped CI 可跑）。
//! 關鍵不變量：CBOM 出任何問題都只影響 CBOM 區段，絕不中止 SBOM / CVE 主流程。

use cytrace_core::engine::CbomOutput;
use cytrace_core::engine::ScanEngine;
use cytrace_core::{collect_cbom, CytraceError, Result};
use cytrace_types::{CbomStatus, QuantumStatus};

struct Engine(Result<Option<String>>);

fn out(json: &str, skipped: u64) -> CbomOutput {
    CbomOutput {
        json: json.into(),
        skipped,
        admitted_keys: 0,
        admitted_certs: 0,
    }
}

/// 引擎回報「因大小門檻略過 N 個檔案」的 fake。
struct SkippingEngine(u64);

impl ScanEngine for SkippingEngine {
    fn sbom(&self, _t: &str) -> Result<String> {
        Ok("{}".into())
    }
    fn vuln(&self, _s: &str) -> Result<String> {
        Ok(r#"{"matches":[]}"#.into())
    }
    fn cbom(&self, _t: &str) -> Result<Option<CbomOutput>> {
        Ok(Some(out(r#"{"bomFormat":"CycloneDX"}"#, self.0)))
    }
}

impl ScanEngine for Engine {
    fn sbom(&self, _t: &str) -> Result<String> {
        Ok("{}".into())
    }
    fn vuln(&self, _s: &str) -> Result<String> {
        Ok(r#"{"matches":[]}"#.into())
    }
    fn cbom(&self, _t: &str) -> Result<Option<CbomOutput>> {
        match &self.0 {
            Ok(v) => Ok(v.clone().map(|j| out(&j, 0))),
            Err(e) => Err(CytraceError::Engine(e.to_string())),
        }
    }
}

/// 會觸碰共用 temp 目錄的測試需序列化執行——否則彼此的暫存 HOME 會互相計入。
static TEMP_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

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
            inv.unscanned_total(),
            1,
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
        inv.unscanned_total(),
        3,
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

// ── 併發下 unscanned_count 不得互相污染（複審實測 15/80 出錯）──

#[test]
fn concurrent_collect_cbom_does_not_cross_contaminate_unscanned() {
    use std::sync::Arc;
    use std::thread;

    // server 預設 max_concurrent_scans=2，兩個 job 共用同一個 Arc<RealEngine>。
    // 若 skipped 數經行程內全域狀態傳遞，兩者會互相覆寫——最危險的方向是
    // 「真的有大檔被略過」被回報成 unscanned=0，fail-closed 保護靜默消失。
    let big: Arc<dyn ScanEngine> = Arc::new(SkippingEngine(4));
    let small: Arc<dyn ScanEngine> = Arc::new(SkippingEngine(0));

    let h_big = {
        let e = Arc::clone(&big);
        thread::spawn(move || {
            (0..200)
                .map(|_| collect_cbom(e.as_ref(), "dir:/big").unscanned_total())
                .collect::<Vec<_>>()
        })
    };
    let h_small = {
        let e = Arc::clone(&small);
        thread::spawn(move || {
            (0..200)
                .map(|_| collect_cbom(e.as_ref(), "dir:/small").unscanned_total())
                .collect::<Vec<_>>()
        })
    };

    let bigs = h_big.join().expect("big 執行緒");
    let smalls = h_small.join().expect("small 執行緒");

    assert!(
        bigs.iter().all(|&n| n == 4),
        "有大檔被略過的目標不得回報為乾淨：{:?}",
        bigs.iter().filter(|&&n| n != 4).take(5).collect::<Vec<_>>()
    );
    assert!(
        smalls.iter().all(|&n| n == 0),
        "沒有略過的目標不得被灌入他人的數字"
    );
}

#[test]
fn absent_engine_must_not_stamp_a_theia_version() {
    use cytrace_core::engine::tool_versions;
    use cytrace_types::CbomStatus;

    // 報表是要併入交件、可簽章稽核的證據：引擎沒跑卻蓋上版本號，等於不實陳述。
    // syft/grype 查不到時誠實回 unknown，theia 也必須一致。
    let absent = tool_versions(&CbomStatus::EngineAbsent);
    assert_eq!(absent.theia, None, "引擎缺席不得填版本");

    let failed = tool_versions(&CbomStatus::Failed {
        reason_key: "x".into(),
        reason_detail: None,
    });
    assert_eq!(failed.theia, None, "執行失敗不得填版本");

    let not_requested = tool_versions(&CbomStatus::NotRequested);
    assert_eq!(not_requested.theia, None, "未請求不得填版本");

    // 只有真的跑完才標版本
    let done = tool_versions(&CbomStatus::Completed);
    assert!(done.theia.is_some(), "完成掃描須標示引擎版本（NFR-03）");
}

#[test]
fn scan_identity_is_concurrency_safe() {
    use cytrace_core::engine::scan_identity;
    use std::thread;
    // 併發呼叫不得因共用暫存檔而互相刪除彼此的探測檔
    let hs: Vec<_> = (0..8)
        .map(|_| thread::spawn(|| (0..50).map(|_| scan_identity()).collect::<Vec<_>>()))
        .collect();
    for h in hs {
        let ids = h.join().expect("執行緒");
        assert!(
            ids.iter()
                .all(|i| i.starts_with("uid=") && !i.ends_with("unknown")),
            "併發下不得出現 uid=unknown：{:?}",
            ids.iter()
                .filter(|i| i.ends_with("unknown"))
                .take(3)
                .collect::<Vec<_>>()
        );
    }
}

#[test]
fn vuln_temp_paths_are_unique_per_call() {
    use cytrace_core::engine::sbom_temp_path;
    use std::collections::HashSet;
    use std::thread;

    // server 的 job 跑在同一行程（spawn_blocking，預設併發 2）。
    // 暫存 SBOM 若是每行程一個固定路徑，兩個 job 會互寫互刪——
    // 最糟的情形是 A 的元件配到 B 的 CVE，grype 退出碼 0、JSON 合法，攔不到。
    let hs: Vec<_> = (0..8)
        .map(|_| thread::spawn(|| (0..100).map(|_| sbom_temp_path()).collect::<Vec<_>>()))
        .collect();
    let mut all = Vec::new();
    for h in hs {
        all.extend(h.join().expect("執行緒"));
    }
    let uniq: HashSet<_> = all.iter().collect();
    assert_eq!(uniq.len(), all.len(), "暫存 SBOM 路徑不得重複");
}

#[test]
fn engine_leaves_no_temp_home_behind() {
    use cytrace_core::engine::cbom;
    use std::fs;

    let _guard = TEMP_LOCK.lock().unwrap_or_else(|e| e.into_inner());

    // 所有離開路徑都要清理（含引擎缺席、spawn 失敗的 early return）。
    // 以「呼叫前後 temp 目錄中 cytrace-theia-home-* 的數量不變」驗證。
    let count = || {
        fs::read_dir(std::env::temp_dir())
            .map(|d| {
                d.flatten()
                    .filter(|e| {
                        e.file_name()
                            .to_string_lossy()
                            .starts_with("cytrace-theia-home-")
                    })
                    .count()
            })
            .unwrap_or(0)
    };

    let before = count();
    let dir = std::env::temp_dir().join(format!("cytrace-leak-{}", std::process::id()));
    fs::create_dir_all(&dir).expect("建立目標");
    for _ in 0..5 {
        let _ = cbom(dir.to_str().unwrap()); // 成功或失敗都不得殘留
    }
    let _ = fs::remove_dir_all(&dir);
    assert_eq!(count(), before, "暫存 HOME 目錄不得殘留");
}

// ── symlink 必須與引擎行為一致（第四輪複審實測）──

#[test]
#[cfg(unix)]
fn unreadable_symlink_target_is_counted() {
    use cytrace_core::unreadable_count;
    use std::fs;
    use std::os::unix::fs::{symlink, PermissionsExt};

    // theia 的 dir 模式**會追隨 symlink**，所以 symlink 是引擎的實際掃描對象。
    // CyTrace 原本一律 continue，把整個類別排除在缺口帳外——
    // 解開的容器 rootfs 上 /etc/ssl/certs/*.pem 多為絕對 symlink，這是常態而非對抗性輸入。
    let base = std::env::temp_dir().join(format!("cytrace-symlink-{}", std::process::id()));
    let _ = fs::remove_dir_all(&base);
    fs::create_dir_all(base.join("outside")).expect("建立目錄");
    fs::create_dir_all(base.join("target")).expect("建立目標");
    let secret = base.join("outside/secret.key");
    fs::write(&secret, b"x").expect("寫檔");
    fs::set_permissions(&secret, fs::Permissions::from_mode(0o000)).expect("chmod");
    symlink(&secret, base.join("target/tls.key")).expect("建立 symlink");
    // 斷鏈 symlink 同樣無從得知內容
    symlink(
        base.join("outside/missing"),
        base.join("target/dangling.key"),
    )
    .expect("斷鏈");

    let readable = fs::File::open(&secret).is_ok();
    let n = unreadable_count(&base.join("target"));
    let _ = fs::remove_dir_all(&base);

    if readable {
        // root 讀得到不可讀檔，只剩斷鏈那一個
        assert_eq!(n, 1, "斷鏈 symlink 須計入");
    } else {
        assert_eq!(n, 2, "不可讀的 symlink 目標與斷鏈 symlink 都須計入");
    }
}

#[test]
#[cfg(unix)]
fn symlink_loops_do_not_hang_the_count() {
    use cytrace_core::unreadable_count;
    use std::fs;
    use std::os::unix::fs::symlink;

    // 追隨 symlink 後必須防循環，否則清點會無限遞迴
    let base = std::env::temp_dir().join(format!("cytrace-symloop-{}", std::process::id()));
    let _ = fs::remove_dir_all(&base);
    fs::create_dir_all(base.join("d")).expect("建立目錄");
    symlink(&base, base.join("d/loop")).expect("建立循環 symlink");
    let n = unreadable_count(&base); // 不得掛死
    let _ = fs::remove_dir_all(&base);
    assert!(n < 1000, "循環不得造成計數爆炸，實得 {n}");
}

// ── 子程序逾時（第四輪複審實測：FIFO 導致永久掛死）──

#[test]
#[cfg(unix)]
fn fifo_in_target_does_not_hang_the_scan() {
    use cytrace_core::engine::cbom_with_timeout;
    use std::fs;
    use std::time::{Duration, Instant};

    let _guard = TEMP_LOCK.lock().unwrap_or_else(|e| e.into_inner());

    // 實測：目標樹含一個 FIFO 時 theia 永久阻塞，CLI 只印「掃描中」再也不返回；
    // server 端 permit 永不釋放、Running job 不可取消，預設併發 2 → 兩個卡住即服務停擺。
    // 真實 root filesystem 本身就含 FIFO（/run/initctl 之類），屬普通輸入。
    let dir = std::env::temp_dir().join(format!("cytrace-fifo-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).expect("建立目錄");
    let fifo = dir.join("pipe.key");
    let ok = std::process::Command::new("mkfifo")
        .arg(&fifo)
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    if !ok {
        let _ = fs::remove_dir_all(&dir);
        return; // 無 mkfifo 的環境跳過
    }

    let started = Instant::now();
    // 注入短逾時：驗的是「會返回」，不是預設值多長
    let _ = cbom_with_timeout(dir.to_str().unwrap(), Duration::from_secs(5));
    let elapsed = started.elapsed();
    let _ = fs::remove_dir_all(&dir);

    assert!(
        elapsed < Duration::from_secs(60),
        "含 FIFO 的目標必須在逾時內返回，實耗 {elapsed:?}"
    );
}

#[test]
fn failed_status_carries_a_pure_i18n_key_not_prose() {
    // 曾經 reason_key = e.to_string()，把鍵與中文散文黏成一串：
    // --lang en-US 會吐中文，且該字串會寫進 scan-result.json 並經 API 對外。
    let inv = collect_cbom(&Engine(Ok(Some("{ not json".into()))), "dir:/x");
    match &inv.status {
        CbomStatus::Failed {
            reason_key,
            reason_detail,
        } => {
            assert!(
                reason_key.starts_with("cbom.err."),
                "reason_key 須為純鍵，實得 {reason_key}"
            );
            assert!(
                !reason_key.chars().any(|c| c as u32 > 0x7f),
                "reason_key 不得含非 ASCII（散文）：{reason_key}"
            );
            assert!(
                reason_detail.is_some(),
                "不可翻譯的細節應放 reason_detail 而非鍵裡"
            );
        }
        other => panic!("應為 Failed，實得 {other:?}"),
    }
}
