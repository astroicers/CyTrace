//! CLI 閘門退出碼的端到端測試（ADR-013 決策 9 成功指標；ROADMAP T907）。
//!
//! 以 shim 腳本假扮 syft/grype，並把 `cbomkit-theia` 排除在 PATH 外，
//! 藉此在**不需要任何真實引擎**的情況下驗證退出碼語意（air-gapped CI 可跑）。
//!
//! 釘住的不變量：`EXIT_ERR`(1) 優先於 `EXIT_FAILON`(2)——
//! 「根本沒掃到」不得被「有脆弱資產」的 2 蓋掉，否則 CI 會誤判為掃描成功。

#![cfg(unix)]

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

const FIXTURES: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../cytrace-core/tests/fixtures"
);

fn cytrace_bin() -> PathBuf {
    // target/<profile>/deps/<test binary> → target/<profile>/cytrace
    let mut p = std::env::current_exe().expect("測試執行檔路徑");
    p.pop();
    if p.ends_with("deps") {
        p.pop();
    }
    p.join("cytrace")
}

/// 寫可執行檔（shim）與產生子程序互斥（T912 複審 newgates#6）。
///
/// fork 出的子程序在 exec 之前帶著父行程當下所有開著的 fd——包括另一條測試執行緒正在寫的
/// shim。這時去 exec 那個 shim，核心回 ETXTBSY（"Text file busy"）；複審實測 400 次約 2 次。
/// 寫 shim 取寫鎖、產生子程序取讀鎖：寫入期間沒有人 fork。
static SPAWN: std::sync::RwLock<()> = std::sync::RwLock::new(());

fn writing() -> std::sync::RwLockWriteGuard<'static, ()> {
    SPAWN
        .write()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn spawning() -> std::sync::RwLockReadGuard<'static, ()> {
    SPAWN
        .read()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn write_shim(path: &Path, fixture: &str) {
    let _w = writing();
    fs::write(path, format!("#!/bin/sh\ncat {FIXTURES}/{fixture}\n")).expect("寫入 shim");
    fs::set_permissions(path, fs::Permissions::from_mode(0o755)).expect("chmod");
}

struct Env {
    dir: PathBuf,
}

impl Env {
    fn new(tag: &str) -> Self {
        let dir = std::env::temp_dir().join(format!("cytrace-gates-{}-{tag}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(dir.join("bin")).expect("建立 bin");
        fs::create_dir_all(dir.join("target")).expect("建立 target");
        fs::write(dir.join("target/a.crt"), b"x").expect("建立掃描目標");
        write_shim(&dir.join("bin/syft"), "cyclonedx.json");
        write_shim(&dir.join("bin/grype"), "grype.json");
        Env { dir }
    }

    /// 以受控 PATH 執行：只含 shim 與系統目錄，**刻意不含 cbomkit-theia**。
    fn run(&self, args: &[&str]) -> i32 {
        let out = {
            let _g = spawning();
            Command::new(cytrace_bin())
                .args(args)
                .env("PATH", format!("{}/bin:/usr/bin:/bin", self.dir.display()))
                .output()
                .expect("執行 cytrace")
        };
        out.status.code().expect("退出碼")
    }

    fn target(&self) -> String {
        self.dir.join("target").display().to_string()
    }
    fn out(&self, name: &str) -> String {
        self.dir.join(name).display().to_string()
    }
}

impl Drop for Env {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.dir);
    }
}

#[test]
fn quantum_gate_without_result_exits_one() {
    let e = Env::new("q-only");
    let code = e.run(&[
        "run",
        &e.target(),
        "--cbom",
        "--fail-on-quantum-vulnerable",
        "-o",
        &e.out("r.html"),
    ]);
    assert_eq!(code, 1, "引擎缺席 → fail-closed 必須 exit 1");
}

#[test]
fn quantum_no_result_is_not_masked_by_failon() {
    // 複審 finding：--fail-on 原本先行 return 2，遮蔽了量子閘門的 1
    let e = Env::new("both");
    let code = e.run(&[
        "run",
        &e.target(),
        "--cbom",
        "--fail-on-quantum-vulnerable",
        "--fail-on",
        "high",
        "-o",
        &e.out("r.html"),
    ]);
    assert_eq!(code, 1, "兩閘門同時觸發時，exit 1 須優先於 exit 2");
}

#[test]
fn failon_alone_exits_two() {
    let e = Env::new("failon");
    let code = e.run(&[
        "run",
        &e.target(),
        "--fail-on",
        "high",
        "-o",
        &e.out("r.html"),
    ]);
    assert_eq!(code, 2, "政策閘觸發為 exit 2");
}

#[test]
fn clean_scan_exits_zero() {
    let e = Env::new("clean");
    let code = e.run(&["run", &e.target(), "-o", &e.out("r.html")]);
    assert_eq!(code, 0);
}

#[test]
fn batch_propagates_exit_one_over_two() {
    let e = Env::new("batch");
    let t = e.target();
    let code = e.run(&[
        "batch",
        &t,
        &t,
        "--cbom",
        "--fail-on-quantum-vulnerable",
        "--fail-on",
        "high",
        "-o",
        &e.dir.display().to_string(),
    ]);
    assert_eq!(code, 1, "批次彙整同樣須讓 exit 1 優先");
}

/// db_snapshot 在 shim 環境（grype 對 `db status` 回 vuln fixture）須為 sentinel，
/// **不得**把不相干的 JSON 誤轉成假快照值。
///
/// release-prep 複審 minor #4：真值路徑此前零整合覆蓋——shim 讓整條整合測試
/// 全走 sentinel，唯一真值覆蓋是繞過管線的純 parser 單元測試。本測試把
/// 「shim 下確實收斂到 sentinel」這半釘住；真值那半由 parser 單元測試（凍結的
/// grype 0.114 實地樣本）與 release 前的釘選版 E2E 承接。
#[test]
fn db_snapshot_is_sentinel_when_grype_cannot_report_status() {
    let e = Env::new("dbsnap");
    let out_html = e.out("r.html");
    let code = e.run(&["run", &e.target(), "--out", &out_html]);
    assert_eq!(code, 0, "shim 掃描應成功");
    let html = fs::read_to_string(&out_html).expect("讀報表");
    assert!(
        html.contains(r#""db_snapshot":{"version":"unavailable","built":"unavailable"}"#),
        "shim 的 grype 對 db status 回 vuln fixture（無 schemaVersion/built），\n\
         db_snapshot 必須收斂到顯性 sentinel，而非假值或缺欄"
    );
}

/// 報表內嵌的 ScanResult（`<script id="cytrace-data">`；注入時 `</` 跳脫為 `<\/`）。
fn embedded_scanresult(html: &str) -> serde_json::Value {
    let start = r#"<script id="cytrace-data" type="application/json">"#;
    let from = html.find(start).expect("報表應內嵌 ScanResult") + start.len();
    let to = from + html[from..].find("</script>").expect("資料區塊應結束");
    serde_json::from_str(&html[from..to].replace("<\\/", "</")).expect("內嵌資料為 JSON")
}

/// T925：`run` 走的管線要把弱點對應到元件位置（ADR-009「修訂：schema v3」）。
/// fixture 的 Grype artifact 不帶位置，必須經對應鏈才拿得到；各段的取捨由 parse.rs 的單元測試釘住。
#[test]
fn run_links_findings_to_component_locations() {
    let e = Env::new("provenance");
    let out_html = e.out("r.html");
    assert_eq!(e.run(&["run", &e.target(), "--out", &out_html]), 0);
    let v = embedded_scanresult(&fs::read_to_string(&out_html).expect("讀報表"));

    assert_eq!(v["schema_version"], 3);
    let comps = v["components"].as_array().unwrap();
    assert_eq!(
        comps[1]["locations"],
        serde_json::json!(["/package-lock.json", "/web/package-lock.json"])
    );
    assert_eq!(comps[1]["purl"], "pkg:npm/barlib@1.4.0");

    let loc = |id: &str| {
        v["findings"]
            .as_array()
            .unwrap()
            .iter()
            .find(|f| f["id"] == id)
            .unwrap_or_else(|| panic!("找不到 {id}"))["locations"]
            .clone()
    };
    assert_eq!(
        loc("CVE-2024-1111"),
        serde_json::json!(["/var/lib/dpkg/status"]),
        "libfoo 應以 purl 對到位置"
    );
    assert_eq!(
        loc("CVE-2024-2222"),
        serde_json::json!(["/package-lock.json", "/web/package-lock.json"]),
        "barlib 應對到位置（fixture 的 id 與 purl 都對得上：這支驗的是管線有做對應，不驗走哪一段）"
    );
}

/// ADR-009 相容政策：v3 的 `cytrace report` 必須能重建 v1、v2 的 ScanResult（缺來源欄位視為空）。
/// v2 檔取自 schema v3 之前的 golden baseline（真正由 v2 產出）。
#[test]
fn report_rebuilds_v1_and_v2_scanresults() {
    let e = Env::new("oldschema");
    let v1 = r#"{
        "schema_version": 1,
        "meta": {
            "target": "dir:/tmp/x",
            "tool_versions": {"syft": "1.45.1", "grype": "0.114.0"},
            "db_snapshot": {"version": "5", "built": "2026-07-01T00:00:00Z"},
            "generated_at": "2026-07-01T00:00:00Z"
        },
        "components": [{"name": "libfoo", "version": "3.0.1", "type": "library", "licenses": []}],
        "findings": [{"id": "CVE-1", "severity": "High", "component": "libfoo", "source": "nvd"}],
        "summary": {"counts_by_severity": {"High": 1}, "overall_risk": "High"}
    }"#;
    let v1_path = e.out("v1.json");
    fs::write(&v1_path, v1).expect("寫 v1");
    let v2_path = format!("{FIXTURES}/scanresult-v2.json");

    for (label, input, version) in [("v1", v1_path.as_str(), 1), ("v2", v2_path.as_str(), 2)] {
        let out_html = e.out(&format!("{label}.html"));
        assert_eq!(
            e.run(&["report", input, "--out", &out_html]),
            0,
            "{label} 應可重建報表"
        );
        let v = embedded_scanresult(&fs::read_to_string(&out_html).expect("讀報表"));
        assert_eq!(v["schema_version"], version, "{label}：保留原版本號");
        assert!(
            v["components"][0].get("locations").is_none(),
            "{label}：缺來源欄位視為空，不補假值"
        );
        assert!(v["findings"][0].get("locations").is_none(), "{label}：同上");
    }
}
