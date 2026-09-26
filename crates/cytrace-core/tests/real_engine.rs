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
    if !theia_present() {
        return;
    }
    let _g = LOCK.lock().unwrap();
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
    if !theia_present() {
        return;
    }
    let _g = LOCK.lock().unwrap();
    let d = workspace("basic");
    if !gen_cert(&d, "server", 2048) {
        let _ = fs::remove_dir_all(&d);
        return; // 無 openssl 的環境跳過
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
    if !theia_present() {
        return;
    }
    let _g = LOCK.lock().unwrap();
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
        return; // 以 root 跑時讀得到，本案例不適用
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
    if !theia_present() {
        return;
    }
    let _g = LOCK.lock().unwrap();
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
    if !theia_present() {
        return;
    }
    let _g = LOCK.lock().unwrap();
    let d = workspace("fifo");
    fs::write(d.join("openssl.cnf"), b"[x]\n").unwrap();
    if !Command::new("mkfifo")
        .arg(d.join("pipe.key"))
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
    {
        let _ = fs::remove_dir_all(&d);
        return;
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
    if !theia_present() {
        return;
    }
    let _g = LOCK.lock().unwrap();
    let d = workspace("oversize");
    if !gen_cert(&d, "big", 2048) {
        let _ = fs::remove_dir_all(&d);
        return;
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
    if !theia_present() {
        return;
    }
    let _g = LOCK.lock().unwrap();
    let d = workspace("openssh");
    let key = d.join("ssh_host_ed25519_key");
    if !Command::new("ssh-keygen")
        .args(["-t", "ed25519", "-N", "", "-f", key.to_str().unwrap()])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
    {
        let _ = fs::remove_dir_all(&d);
        return; // 無 ssh-keygen 的環境跳過
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
    if !theia_present() {
        return;
    }
    let _g = LOCK.lock().unwrap();
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
    if !theia_present() {
        return;
    }
    let _g = LOCK.lock().unwrap();
    let d = workspace("plain");
    let f = d.join("firmware.bin");
    fs::write(&f, [0u8, 1, 2, 3]).unwrap();

    let r = engine::cbom_target(f.to_str().unwrap());
    let _ = fs::remove_dir_all(&d);
    assert!(r.is_err(), "非 tar/gzip 檔案不得被當成映像");
}
