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

fn write_shim(path: &Path, fixture: &str) {
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
        let out = Command::new(cytrace_bin())
            .args(args)
            .env("PATH", format!("{}/bin:/usr/bin:/bin", self.dir.display()))
            .output()
            .expect("執行 cytrace");
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
