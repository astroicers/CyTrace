//! 真引擎 × 真實輸入形態的整合測試（ADR-013）。
//!
//! **存在理由**：M9 的四輪獨立複審共抓出 14 項阻斷級，其中後兩輪的全部缺陷都是
//! 「釘選版 theia 在常見輸入上的實際行為」——零資產目標輸出 `components: null`、
//! dir 模式追隨 symlink、FIFO 導致永久掛死、OpenSSH 格式私鑰只在 stderr 留痕。
//! 這些用 fixture 與 fake engine **一個都測不到**，只有真的跑才會知道。
//!
//! 本檔的每個案例都對應一個曾經漏掉的缺陷，作為回歸網。
//!
//! 跑法：`make test-real-engine`（或 `cargo test -p cytrace-core --test real_engine -- --ignored`）。
//! 需要 `cbomkit-theia` 在 PATH；air-gapped CI 無引擎時預設略過（`#[ignore]`）。

#![cfg(unix)]

use cytrace_core::engine::{cbom_with_timeout, CbomTarget};
use cytrace_core::failon::{quantum_gate, QuantumGate};
use cytrace_core::{collect_cbom, engine};
use cytrace_types::{CbomStatus, CryptoInventory};
use std::fs;
use std::os::unix::fs::{symlink, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

/// 觸碰共用 temp 目錄的案例需序列化（暫存 HOME 會互相計入）。
static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn theia_present() -> bool {
    Command::new("cbomkit-theia")
        .arg("--help")
        .output()
        .map(|o| o.status.success() || !o.stdout.is_empty())
        .unwrap_or(false)
}

/// 缺工具時**必須失敗**，不得靜默通過。
///
/// 本檔全部案例帶 `#[ignore]`，無引擎環境根本不會跑；一旦有人明確下
/// `--ignored` 要跑，「因為缺 openssl 所以什麼都沒驗、但回報 PASS」就是
/// 假綠燈——這正是本檔存在要防的那種東西（第六輪複審 finding H：11 案中
/// 9 案在缺工具時靜默 return）。前置工具由 `make test-real-engine` 與
/// CI 的 real-engine job 事前檢查並告知。
fn require(tool: &str, present: bool) {
    assert!(
        present,
        "缺少 {tool}：本案例無法驗證任何事，不得回報通過。\n\
         請安裝該工具，或不要以 --ignored 執行 real_engine（見 make test-real-engine）"
    );
}

fn require_theia() {
    require("cbomkit-theia", theia_present());
}

/// 建立乾淨的暫存目標目錄。
fn workspace(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("cytrace-real-{}-{tag}", std::process::id()));
    let _ = fs::remove_dir_all(&d);
    fs::create_dir_all(&d).expect("建立暫存目錄");
    d
}

/// 以 openssl 產生自簽憑證與私鑰（不用任何真實金鑰）。
fn gen_cert(dir: &Path, stem: &str, bits: u32) -> bool {
    Command::new("openssl")
        .args([
            "req",
            "-x509",
            "-newkey",
            &format!("rsa:{bits}"),
            "-keyout",
            dir.join(format!("{stem}.key")).to_str().unwrap(),
            "-out",
            dir.join(format!("{stem}.crt")).to_str().unwrap(),
            "-days",
            "30",
            "-nodes",
            "-subj",
            "/CN=cytrace-real-engine-test",
        ])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

fn scan(dir: &Path) -> CryptoInventory {
    collect_cbom(&engine::RealEngine, dir.to_str().unwrap())
}

/// 斷言輸出不含任何金鑰內容（NFR-09）。
fn assert_no_key_material(inv: &CryptoInventory) {
    let json = serde_json::to_string(inv).expect("序列化");
    assert!(!json.contains("PRIVATE KEY"), "不得含 PEM 標記");
    assert!(!json.contains("BEGIN "), "不得含 PEM 標頭");
    let longest = json
        .split(|c: char| !c.is_ascii_alphanumeric() && c != '+' && c != '/')
        .map(str::len)
        .max()
        .unwrap_or(0);
    assert!(longest < 60, "疑似 base64 金鑰內容（長度 {longest}）");
}

// ── 案例 1：零資產目標（第四輪阻斷級：components: null 被判解析失敗）──

#[test]
#[ignore = "需要 cbomkit-theia"]
fn clean_target_is_completed_with_zero_assets() {
    require_theia();
    let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let d = workspace("clean");
    fs::write(d.join("readme.txt"), b"no crypto here").unwrap();

    let inv = scan(&d);
    let _ = fs::remove_dir_all(&d);

    assert_eq!(
        inv.status,
        CbomStatus::Completed,
        "乾淨目標必須是「跑完且 0 項」，不得判為盤點失敗"
    );
    assert!(inv.assets.is_empty());
    assert_eq!(
        quantum_gate(Some(&inv)),
        QuantumGate::Pass,
        "乾淨目標的閘門應通過，否則使用者會把護欄整條關掉"
    );
}

// ── 案例 2：憑證與私鑰（基本偵測 + NFR-09）──

#[test]
#[ignore = "需要 cbomkit-theia"]
fn certificate_and_key_are_detected_without_leaking_material() {
    require_theia();
    let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let d = workspace("basic");
    if !gen_cert(&d, "server", 2048) {
        let _ = fs::remove_dir_all(&d);
        panic!("openssl 產憑證失敗：本案例無法驗證任何事，不得回報通過");
    }

    let inv = scan(&d);
    let _ = fs::remove_dir_all(&d);

    assert_eq!(inv.status, CbomStatus::Completed);
    assert!(!inv.assets.is_empty(), "自簽憑證應產生資產");
    assert_no_key_material(&inv);
}

// ── 案例 3：symlink 指向目標外的不可讀檔（第四輪阻斷級：完全不進缺口帳）──

#[test]
#[ignore = "需要 cbomkit-theia"]
fn unreadable_symlink_makes_the_gate_withhold_pass() {
    require_theia();
    let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let base = workspace("symlink");
    fs::create_dir_all(base.join("outside")).unwrap();
    fs::create_dir_all(base.join("target")).unwrap();
    let secret = base.join("outside/secret.key");
    fs::write(&secret, b"x").unwrap();
    fs::set_permissions(&secret, fs::Permissions::from_mode(0o000)).unwrap();
    symlink(&secret, base.join("target/tls.key")).unwrap();
    fs::write(base.join("target/openssl.cnf"), b"[system_default_sect]\n").unwrap();

    let readable_by_us = fs::File::open(&secret).is_ok();
    let inv = scan(&base.join("target"));
    let _ = fs::remove_dir_all(&base);

    if readable_by_us {
        // 以 root 跑時 0o000 仍讀得到，「權限不可讀」這個前提不成立。
        // 不靜默略過——改斷言對 root **仍然成立**的反向不變量（第六輪複審 finding H：
        // 本分支原本零斷言，在 root 環境下整個案例形同不存在）：
        // 讀得到就不該被計為缺口，否則會造出一個永遠 NoResult 的假警報，
        // 而 root 正是地端掃描最常用的身分。
        assert_eq!(
            inv.unscanned_unreadable, 0,
            "以 root 執行時 0o000 檔案實際讀得到，不得誤計為不可讀缺口\n\
             （誤計的後果：--fail-on-quantum-vulnerable 在 root 下恆為 NoResult 假警報）"
        );
        assert!(
            matches!(inv.status, CbomStatus::Completed),
            "讀得到全部檔案時盤點應完成，實為 {:?}",
            inv.status
        );
        return;
    }
    assert!(
        inv.unscanned_unreadable > 0,
        "讀不到的 symlink 目標必須計入缺口（theia 的 dir 模式會追隨 symlink）"
    );
    assert_ne!(
        quantum_gate(Some(&inv)),
        QuantumGate::Pass,
        "清單不完整時不得宣告通過"
    );
}

// ── 案例 4：symlink 循環（追隨後必須防無限遞迴）──

#[test]
#[ignore = "需要 cbomkit-theia"]
fn symlink_loop_does_not_hang() {
    require_theia();
    let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let d = workspace("symloop");
    fs::create_dir_all(d.join("sub")).unwrap();
    symlink(&d, d.join("sub/loop")).unwrap();

    let started = std::time::Instant::now();
    let inv = scan(&d);
    let elapsed = started.elapsed();
    let _ = fs::remove_dir_all(&d);

    assert!(elapsed < Duration::from_secs(120), "循環不得掛死");
    assert!(inv.unscanned_unreadable < 1000, "循環不得造成計數爆炸");
}

// ── 案例 5：FIFO（第四輪阻斷級：永久掛死）──

#[test]
#[ignore = "需要 cbomkit-theia"]
fn fifo_target_returns_within_timeout() {
    require_theia();
    let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let d = workspace("fifo");
    fs::write(d.join("openssl.cnf"), b"[x]\n").unwrap();
    if !Command::new("mkfifo")
        .arg(d.join("pipe.key"))
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
    {
        let _ = fs::remove_dir_all(&d);
        panic!("mkfifo 失敗：本案例（FIFO 永久阻塞回歸）無法驗證任何事，不得回報通過");
    }

    let started = std::time::Instant::now();
    let r = cbom_with_timeout(d.to_str().unwrap(), Duration::from_secs(5));
    let elapsed = started.elapsed();
    let _ = fs::remove_dir_all(&d);

    assert!(
        elapsed < Duration::from_secs(60),
        "含 FIFO 的目標必須在逾時內返回，實耗 {elapsed:?}"
    );
    // 逾時歸 Err（呼叫端記為 Failed）；若引擎版本已修則為 Ok，兩者皆可接受
    let _ = r;
}

// ── 案例 6：超過引擎 1 MiB 門檻的檔案（第三輪阻斷級：假 Pass）──

#[test]
#[ignore = "需要 cbomkit-theia"]
fn oversize_file_is_reported_as_unscanned() {
    require_theia();
    let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let d = workspace("oversize");
    if !gen_cert(&d, "big", 2048) {
        let _ = fs::remove_dir_all(&d);
        panic!("openssl 產憑證失敗：本案例無法驗證任何事，不得回報通過");
    }
    // 把憑證墊到 >1 MiB：內容仍是合法 PEM 開頭，但引擎會因大小略過
    let mut pem = fs::read(d.join("big.crt")).unwrap();
    pem.extend(std::iter::repeat_n(b'\n', 1_200_000));
    fs::write(d.join("big.crt"), &pem).unwrap();

    let inv = scan(&d);
    let _ = fs::remove_dir_all(&d);

    assert!(
        inv.unscanned_oversize > 0,
        "引擎因大小門檻略過的檔案必須計入（否則報表會宣稱清單完整）"
    );
}

// ── 案例 7：OpenSSH 格式私鑰（第四輪阻斷級：引擎自承卻不計數）──

#[test]
#[ignore = "需要 cbomkit-theia"]
fn engine_admitted_findings_are_not_silently_dropped() {
    require_theia();
    let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let d = workspace("openssh");
    let key = d.join("ssh_host_ed25519_key");
    if !Command::new("ssh-keygen")
        .args(["-t", "ed25519", "-N", "", "-f", key.to_str().unwrap()])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
    {
        let _ = fs::remove_dir_all(&d);
        panic!("ssh-keygen 產金鑰失敗：本案例無法驗證任何事，不得回報通過");
    }

    let inv = scan(&d);
    let _ = fs::remove_dir_all(&d);

    // 引擎偵測到卻無法建模時，缺口必須可見：不是列為資產，就是計入未確定
    let visible = !inv.assets.is_empty() || inv.unscanned_undetermined > 0;
    assert!(
        visible,
        "引擎自承偵測到私鑰時，不得同時「0 項資產」且「0 項未掃描」——那是靜默漏檢"
    );
    assert_no_key_material(&inv);
}

// ── 案例 8：零外連（第二輪阻斷級：殘檔命名為映像名 → 載入他人映像）──

#[test]
#[ignore = "需要 cbomkit-theia"]
fn gzip_remnant_named_after_an_image_does_not_load_foreign_assets() {
    require_theia();
    let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let d = workspace("remnant");
    // 8 bytes 的 gzip 殘檔，命名為常見映像名
    fs::write(d.join("nginx"), [0x1f, 0x8b, 0x08, 0x00, 0, 0, 0, 0]).unwrap();

    let prev = std::env::current_dir().unwrap();
    std::env::set_current_dir(&d).unwrap();
    let t = engine::cbom_target("nginx");
    let inv = collect_cbom(&engine::RealEngine, "nginx");
    std::env::set_current_dir(prev).unwrap();
    let _ = fs::remove_dir_all(&d);

    // 交給引擎的必為絕對路徑——theia 才不會把它當映像參照
    if let Ok(t) = t {
        assert!(t.path().is_absolute(), "路徑必須絕對化");
        assert!(matches!(t, CbomTarget::Image(_)));
    }
    assert!(
        inv.assets.is_empty(),
        "殘檔不得產出任何資產（曾實測載入本機 nginx 映像、輸出 10,807 元件）"
    );
    assert_ne!(
        inv.status,
        CbomStatus::Completed,
        "無法解析的輸入應歸 Failed，不得偽裝成「跑完 0 項」"
    );
}

// ── 案例 9：非封存檔一律拒絕 ──

#[test]
#[ignore = "需要 cbomkit-theia"]
fn plain_file_target_is_rejected_before_spawning() {
    require_theia();
    let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let d = workspace("plain");
    let f = d.join("firmware.bin");
    fs::write(&f, [0u8, 1, 2, 3]).unwrap();

    let r = engine::cbom_target(f.to_str().unwrap());
    let _ = fs::remove_dir_all(&d);
    assert!(r.is_err(), "非 tar/gzip 檔案不得被當成映像");
}

// ── 案例 10：大輸出（第五輪阻斷級：逾時輪詢不抽管線 → 死鎖）──

#[test]
#[ignore = "需要 cbomkit-theia 與 openssl"]
fn large_output_does_not_deadlock_the_pipe() {
    require_theia();
    let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let d = workspace("largeout");

    // 60 組憑證 → theia 輸出約 285 KB，遠超 Linux 預設 64 KiB 管線容量。
    // 逾時輪詢若只呼叫 try_wait() 而不讀管線，子程序會阻塞在 write() 永不結束，
    // 於是必然跑到 deadline 被 kill——實測：theia 單獨跑 5 秒完成，經 CyTrace 卡滿逾時。
    let mut made = 0;
    for i in 0..60 {
        if gen_cert(&d, &format!("t{i}"), 2048) {
            made += 1;
        }
    }
    if made < 40 {
        let _ = fs::remove_dir_all(&d);
        panic!("缺少 openssl 或產憑證失敗（僅 {made} 組）；本層不接受靜默略過");
    }

    let started = std::time::Instant::now();
    // 逾時給 90 秒：若管線有被正常抽乾，這個規模應在數秒內完成
    let r = cbom_with_timeout(d.to_str().unwrap(), Duration::from_secs(90));
    let elapsed = started.elapsed();
    let _ = fs::remove_dir_all(&d);

    let out = r.expect("大輸出不得失敗").expect("引擎存在時不得回 None");
    assert!(
        out.json.len() > 64 * 1024,
        "本案例須產生超過管線容量的輸出才有意義，實得 {} bytes",
        out.json.len()
    );
    assert!(
        elapsed < Duration::from_secs(60),
        "大輸出不得因管線未抽乾而卡到逾時，實耗 {elapsed:?}"
    );
}

// ── 案例 11：混合資產目標（第五輪阻斷級：量綱不符使 undetermined 歸零）──

#[test]
#[ignore = "需要 cbomkit-theia、openssl 與 ssh-keygen"]
fn mixed_target_still_reports_unmodelled_findings() {
    require_theia();
    let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let d = workspace("mixed");

    // 同時含「會被建模的憑證」與「不會被建模的 OpenSSH 金鑰」。
    // 案例 7 只放 ssh key，故 admitted=1、keyish=0，相減仍為 1——看不到量綱錯誤。
    // 本案例 admitted=2（a.key + ssh key），若拿 assets.len() 相減會歸零、閘門誤回 Pass。
    if !gen_cert(&d, "a", 2048) {
        let _ = fs::remove_dir_all(&d);
        panic!("缺少 openssl；本層不接受靜默略過");
    }
    let key = d.join("ssh_host_ed25519_key");
    if !Command::new("ssh-keygen")
        .args(["-t", "ed25519", "-N", "", "-q", "-f", key.to_str().unwrap()])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
    {
        let _ = fs::remove_dir_all(&d);
        panic!("缺少 ssh-keygen；本層不接受靜默略過");
    }

    let inv = scan(&d);
    let _ = fs::remove_dir_all(&d);

    assert_eq!(inv.status, CbomStatus::Completed);
    assert!(!inv.assets.is_empty(), "憑證應產生資產");
    assert!(
        inv.unscanned_undetermined > 0,
        "引擎自承的未建模金鑰不得被其他類別資產的數量抵銷（量綱須一致）"
    );
    assert_ne!(
        quantum_gate(Some(&inv)),
        QuantumGate::Pass,
        "有未建模的金鑰時不得宣告通過"
    );
    assert_no_key_material(&inv);
}

// ── 案例 12：落地的 cbom.cdx.json（theia 原樣輸出）不得含私鑰內容（NFR-09）──

/// 前 11 個案例的 `assert_no_key_material` 只看**我們解析後的** `CryptoInventory`；
/// 但 `cytrace scan --cbom` 另外把 theia 的 **stdout 原樣落地**為 `cbom.cdx.json`，
/// 而那份才是可能併入交件的檔案。兩者是不同的東西，前者乾淨不代表後者乾淨
/// （第六輪複審的證據缺口）。
///
/// v1.1.2 實測（2026-09-27）：theia 對 `type: private-key` 的元件**不填 `value`**，
/// 只有 `public-key` 才帶 base64 值（公鑰本身非機密）。**這是引擎行為，不是我們的保證**——
/// 上游哪天開始輸出私鑰 value，交付報表就會夾帶私鑰，而現行程式碼完全不會察覺。
/// 本案例即為那道警報。
#[test]
#[ignore = "需要 cbomkit-theia 與 openssl"]
fn raw_cbom_json_never_carries_private_key_material() {
    require_theia();
    let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let d = workspace("rawkeys");

    // 四種私鑰格式：傳統 PEM / PKCS#8 / EC / OpenSSH，涵蓋建模與未建模兩種路徑
    let ok = Command::new("openssl")
        .args([
            "genrsa",
            "-out",
            d.join("trad.key").to_str().unwrap(),
            "2048",
        ])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
        && Command::new("openssl")
            .args([
                "genpkey",
                "-algorithm",
                "RSA",
                "-pkeyopt",
                "rsa_keygen_bits:2048",
                "-out",
                d.join("pkcs8.key").to_str().unwrap(),
            ])
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
        && Command::new("openssl")
            .args([
                "ecparam",
                "-name",
                "prime256v1",
                "-genkey",
                "-noout",
                "-out",
                d.join("ec.key").to_str().unwrap(),
            ])
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false);
    if !ok {
        let _ = fs::remove_dir_all(&d);
        panic!("openssl 產私鑰失敗：本案例無法驗證任何事，不得回報通過");
    }
    // OpenSSH 格式：走「偵測到但未建模」那條路（只在 stderr 留痕），
    // 註解聲稱涵蓋四種格式就得真的有四種——第七輪複審指認此處原只產三種。
    if !Command::new("ssh-keygen")
        .args([
            "-t",
            "ed25519",
            "-N",
            "",
            "-q",
            "-f",
            d.join("ssh_host_ed25519_key").to_str().unwrap(),
        ])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
    {
        let _ = fs::remove_dir_all(&d);
        panic!("ssh-keygen 產金鑰失敗：本案例無法驗證任何事，不得回報通過");
    }
    // 一併放一張憑證，確保輸出裡真的有東西（空輸出會讓斷言變成空轉）
    if !gen_cert(&d, "server", 2048) {
        let _ = fs::remove_dir_all(&d);
        panic!("openssl 產憑證失敗：本案例無法驗證任何事，不得回報通過");
    }

    let (inv, raw) = cytrace_core::collect_cbom_with_raw(&engine::RealEngine, d.to_str().unwrap());
    let _ = fs::remove_dir_all(&d);

    assert_eq!(inv.status, CbomStatus::Completed, "盤點應完成");
    let raw = raw.expect("Completed 時必有原始 JSON 可落地");
    assert!(!raw.trim().is_empty(), "原始 JSON 不得為空");

    // 1) 不得含 PEM 封裝標記
    for marker in ["PRIVATE KEY", "-----BEGIN", "-----END"] {
        assert!(
            !raw.contains(marker),
            "原樣落地的 cbom.cdx.json 不得含 PEM 標記 {marker:?}（NFR-09）"
        );
    }

    // 2) 逐元件檢查：任何 private-key 一律不得帶 value
    //    （不以「最長 base64 長度」把關——公鑰的 value 合法地可達數百字元，
    //      用長度判斷會同時漏掉真洩漏又誤報正常公鑰）
    let doc: serde_json::Value = serde_json::from_str(&raw).expect("原始輸出須為合法 JSON");
    let comps = doc
        .get("components")
        .and_then(|c| c.as_array())
        .cloned()
        .unwrap_or_default();
    assert!(!comps.is_empty(), "本目標應產生元件，否則斷言在空轉");

    let mut private_seen = 0usize;
    for c in &comps {
        let Some(rp) = c
            .get("cryptoProperties")
            .and_then(|p| p.get("relatedCryptoMaterialProperties"))
        else {
            continue;
        };
        if rp.get("type").and_then(|t| t.as_str()) != Some("private-key") {
            continue;
        }
        private_seen += 1;
        let value = rp.get("value").and_then(|v| v.as_str()).unwrap_or("");
        assert!(
            value.is_empty(),
            "private-key 元件夾帶了金鑰內容（{} 字元）——上游行為已變，\
             交付報表正在洩漏私鑰，必須先過濾再落地（NFR-09）\nname={:?}",
            value.len(),
            c.get("name")
        );
    }
    assert!(
        private_seen > 0,
        "目標含多把私鑰卻沒有任何 private-key 元件——斷言在空轉，\
         引擎行為或建模路徑已變，須先確認再談通過"
    );
    // 未建模路徑也要有警報：ssh-keygen 那把只在 stderr 留痕，故自承數必然高於建模數。
    // 少了這條，「涵蓋建模與未建模兩種路徑」就只是註解裡的話。
    assert!(
        inv.unscanned_undetermined > 0,
        "OpenSSH 格式金鑰不被建模，其缺口必須出現在 unscanned_undetermined 裡"
    );

    // 3) 我們解析後的結構同樣不得含金鑰內容
    assert_no_key_material(&inv);
}

// ── 案例 13：憑證自承計數的漂移哨兵（第七輪複審 blocker）──

/// **凍結的 stderr fixture 只能證明過去**。
///
/// 第六輪修好了憑證計數（theia 走 `numberOfDetectedCertificates=N`，不印
/// `Found N certificate(s)`），但唯一的把關是 `tests/cbom.rs` 裡一段凍結字串。
/// 上游下次改欄位名時：`admitted_certs` 靜默回到 0 → 憑證類的「偵測到卻未建模」
/// 恆算 0 → 閘門一律放行，而全部案例照樣全綠——fail-open 原路返回，
/// 沒有任何東西會轉紅（第七輪複審指認：12 案中沒有一條斷言碰過 `admitted_certs`）。
///
/// 本案例直接對真引擎斷言計數本身，故欄位改名當下就會紅。
#[test]
#[ignore = "需要 cbomkit-theia 與 openssl"]
fn certificate_admitted_count_tracks_the_real_engine() {
    require_theia();
    let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());

    // (a) 三張獨立憑證
    let d = workspace("certcount");
    for i in 1..=3 {
        if !gen_cert(&d, &format!("c{i}"), 2048) {
            let _ = fs::remove_dir_all(&d);
            panic!("openssl 產憑證失敗：本案例無法驗證任何事，不得回報通過");
        }
    }
    let single = cbom_with_timeout(d.to_str().unwrap(), Duration::from_secs(120));

    // (b) 同樣三張，但連成一個 PEM bundle：計數應仍為 3（不是 1 個檔案）
    //
    // 這一段的每個 unwrap 都在清理之前，失敗即殘留含未加密私鑰的暫存目錄
    // （第九輪複審 finding：finding J 只修了斷言側，I/O 這側還在）。
    // 以 closure 收束，讓任何失敗都經同一條清理路徑。
    let bundle_dir = workspace("certbundle");
    let empty = workspace("certzero");
    let dirs = [d.clone(), bundle_dir.clone(), empty.clone()];
    let cleanup = || {
        for dir in &dirs {
            let _ = fs::remove_dir_all(dir);
        }
    };
    let prepared = (|| -> std::io::Result<()> {
        let mut bundle = Vec::new();
        for i in 1..=3 {
            bundle.extend(fs::read(d.join(format!("c{i}.crt")))?);
        }
        fs::write(bundle_dir.join("bundle.pem"), &bundle)?;
        fs::write(empty.join("openssl.cnf"), b"[system_default_sect]\n")?;
        Ok(())
    })();
    if let Err(e) = prepared {
        cleanup();
        panic!("準備 fixture 失敗：{e}");
    }
    let bundled = cbom_with_timeout(bundle_dir.to_str().unwrap(), Duration::from_secs(120));
    let zero = cbom_with_timeout(empty.to_str().unwrap(), Duration::from_secs(120));

    // **先清理再斷言**：斷言失敗時 panic 會跳過其後的清理，留下含憑證與私鑰的暫存目錄
    // （同檔前面的案例已建立此慣例；第八輪複審 finding J 指出本案例沒沿用）。
    cleanup();

    let single = single
        .expect("盤點應成功")
        .expect("theia 存在時不得回報缺席");
    assert_eq!(
        single.admitted_certs, 3,
        "三張憑證的自承數須為 3——若為 0，表示引擎的憑證計數欄位已改名而解析沒跟上，\n\
         後果是憑證類的未建模缺口恆為 0、量子閘門一律放行（fail-open）"
    );
    assert_eq!(
        single.admitted_keys, 3,
        "openssl req -nodes 為每張憑證另產一把未加密私鑰，三張即三把，皆由 \
         theia 的 Secret Detection Plugin 自承（`Found 1 private key(s) in …`）"
    );

    let bundled = bundled
        .expect("盤點應成功")
        .expect("theia 存在時不得回報缺席");
    assert_eq!(
        bundled.admitted_certs, 3,
        "3-in-1 bundle 的自承數須為 3（依憑證數而非檔案數）"
    );

    let zero = zero.expect("盤點應成功").expect("theia 存在時不得回報缺席");
    assert_eq!(zero.admitted_certs, 0, "無憑證時自承數須為 0");
    assert_eq!(zero.admitted_keys, 0, "無私鑰時自承數須為 0");
}

// ── 案例 14：正常路徑確實抽到了 stderr（第八輪複審 finding D 的對照面）──

/// 「抽不到輸出不得當成空的」那條邏輯由 `engine::tests::drain_*` 四支單元測試精確把關
/// （用永不送值的 channel 觸發，比注入 0ms 寬限可靠——後者對已就緒的 channel 立即返回，
/// 根本觸發不到）。**這裡要釘的是另一半**：正常路徑真的抽到了 stderr 而非湊巧為空。
///
/// 少了這條，把 `drain` 改成「總是回空 Vec」會讓漏檢計數全部歸零，而
/// 13 個案例裡沒有一個會紅——`skipped` / `admitted_*` 恰好都只在有警告時才非零。
#[test]
#[ignore = "需要 cbomkit-theia 與 openssl"]
fn stderr_is_actually_drained_on_the_normal_path() {
    require_theia();
    let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let d = workspace("drainnormal");
    if !gen_cert(&d, "server", 2048) {
        let _ = fs::remove_dir_all(&d);
        panic!("openssl 產憑證失敗：本案例無法驗證任何事，不得回報通過");
    }
    // 墊一個 >1 MiB 的憑證，讓 theia 必然印出 "Skipping large file"
    let mut pem = fs::read(d.join("server.crt")).unwrap();
    pem.extend(std::iter::repeat_n(b'\n', 1_200_000));
    fs::write(d.join("big.crt"), &pem).unwrap();

    let out = cbom_with_timeout(d.to_str().unwrap(), Duration::from_secs(120));
    let _ = fs::remove_dir_all(&d);
    let out = out.expect("盤點應成功").expect("theia 存在時不得回報缺席");

    // 三個計數都源自 stderr；全為零就表示 stderr 沒被讀到（或被當成空的）
    assert!(
        out.skipped > 0,
        "超過門檻的檔案數須取自 stderr，為 0 表示 stderr 未被抽到"
    );
    assert!(
        out.admitted_certs > 0,
        "自承憑證數須取自 stderr 的 numberOfDetectedCertificates"
    );
    assert!(
        out.admitted_keys > 0,
        "自承私鑰數須取自 stderr 的 Found N private key(s)"
    );
}
