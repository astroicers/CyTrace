//! 操作者終端訊息的語言與退出碼（T912）——以真實 binary 端到端驗證。
//!
//! 以修正前的 binary（476c150）執行本檔，9 支情境測試全數轉紅（`--lang en-US` 下印出
//! 「錯誤 / error: 引擎子程序錯誤：…」、serve 啟動錯誤整句中文、clap 用法錯誤回 2）。
//! 每支在第一個不符的斷言就停下，故這不代表同一支裡的每個樣本都逐一驗過紅燈。
//!
//! 斷言只針對**我方文字**：細節裡的系統訊息（`No such file or directory`）語言由 OS 決定，
//! 這裡的 CI 與開發機都是英文 locale，但不斷言其內容。
//!
//! 未涵蓋：`hash-password` 沒有 tty 的錯誤——有 tty 的終端機上執行測試時 rpassword 會改讀
//! /dev/tty 而卡住，無法在這裡穩定重現；該路徑只有單元層級的渲染驗證。

#![cfg(unix)]

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::Command;

const FIXTURES: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../cytrace-core/tests/fixtures"
);

/// 與 i18n 棘輪同範圍：漢字 + CJK 標點 + 全形字元。
fn has_cjk(s: &str) -> bool {
    s.chars()
        .any(|c| matches!(c as u32, 0x4E00..=0x9FFF | 0x3000..=0x303F | 0xFF00..=0xFFEF))
}

/// 輸出中出現 `cli.xxx`／`server.xxx`／`cbom.xxx`＝有鍵沒被翻譯就印出去了。
fn bare_key(s: &str) -> Option<&str> {
    ["cli.", "server.", "cbom.", "severity."]
        .into_iter()
        .find(|ns| {
            s.match_indices(ns).any(|(i, _)| {
                // 前一字元是字母數字或 `-` 時不是鍵開頭（`cytrace-server.` 之類）
                let before_ok = s[..i]
                    .chars()
                    .last()
                    .is_none_or(|c| !(c.is_alphanumeric() || c == '-' || c == '_'));
                let after = s[i + ns.len()..].chars().next();
                before_ok && after.is_some_and(|c| c.is_ascii_lowercase())
            })
        })
}

struct Sandbox {
    dir: PathBuf,
}

struct Out {
    code: i32,
    stderr: String,
}

impl Sandbox {
    fn new(tag: &str) -> Self {
        let dir = std::env::temp_dir().join(format!("cytrace-lang-{}-{tag}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(dir.join("bin")).unwrap();
        fs::create_dir_all(dir.join("target")).unwrap();
        fs::write(dir.join("target/a.txt"), b"x").unwrap();
        Sandbox { dir }
    }

    fn path(&self, rel: &str) -> String {
        self.dir.join(rel).display().to_string()
    }

    fn shim(&self, name: &str, fixture: &str) {
        let p = self.dir.join("bin").join(name);
        fs::write(&p, format!("#!/bin/sh\ncat {FIXTURES}/{fixture}\n")).unwrap();
        fs::set_permissions(&p, fs::Permissions::from_mode(0o755)).unwrap();
    }

    /// 乾淨環境執行：只帶受控 PATH 與明確給的變數（不讓開發機的 CYTRACE_* 滲入）。
    fn run(&self, args: &[&str], env: &[(&str, &str)]) -> Out {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_cytrace"));
        cmd.args(args)
            .env_clear()
            .env("PATH", format!("{}/bin:/usr/bin:/bin", self.dir.display()))
            .current_dir(&self.dir)
            .stdin(std::process::Stdio::null());
        for (k, v) in env {
            cmd.env(k, v);
        }
        let out = cmd.output().expect("執行 cytrace");
        Out {
            code: out.status.code().expect("退出碼"),
            stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
        }
    }
}

impl Drop for Sandbox {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.dir);
    }
}

/// 同一情境各以兩種語言跑一次：en-US 不得有 CJK、zh-TW 必須有 CJK，兩者都不得有裸鍵，
/// 且各自含預期的我方文字片段。回傳兩次的輸出供個別情境加驗。
fn both_langs(
    sb: &Sandbox,
    args: &[&str],
    env: &[(&str, &str)],
    expect_code: i32,
    en_has: &str,
    zh_has: &str,
) -> (Out, Out) {
    let mut outs = Vec::new();
    for (lang, has) in [("en-US", en_has), ("zh-TW", zh_has)] {
        let mut full = vec!["--lang", lang];
        full.extend_from_slice(args);
        let o = sb.run(&full, env);
        let ctx = format!("{lang} {args:?}\nstderr:\n{}", o.stderr);
        assert_eq!(o.code, expect_code, "退出碼：{ctx}");
        assert!(o.stderr.contains(has), "應含「{has}」：{ctx}");
        assert_eq!(bare_key(&o.stderr), None, "裸鍵：{ctx}");
        if lang == "en-US" {
            assert!(!has_cjk(&o.stderr), "en-US 不得出現中文：{ctx}");
        } else {
            assert!(has_cjk(&o.stderr), "zh-TW 應為中文：{ctx}");
        }
        outs.push(o);
    }
    let zh = outs.pop().unwrap();
    let en = outs.pop().unwrap();
    (en, zh)
}

#[test]
fn self_check_detectors() {
    assert!(has_cjk("錯誤：x") && has_cjk("a（b") && !has_cjk("error: x — “y”"));
    assert_eq!(bare_key("error: cli.err.prefix"), Some("cli."));
    assert_eq!(bare_key("x server.startup.tls_unpaired"), Some("server."));
    assert_eq!(bare_key("cytrace-server: Corrupt job.json"), None);
    assert_eq!(bare_key("see job.json (cli.)"), None);
}

#[test]
fn report_read_and_parse_failures_name_the_path() {
    let sb = Sandbox::new("report");
    let missing = sb.path("nope.json");
    let (en, _) = both_langs(
        &sb,
        &["report", &missing],
        &[],
        1,
        "error: Cannot read",
        "錯誤：無法讀取",
    );
    assert!(en.stderr.contains(&missing), "應指名路徑：{}", en.stderr);

    fs::write(sb.dir.join("bad.json"), "{not json").unwrap();
    let bad = sb.path("bad.json");
    both_langs(
        &sb,
        &["report", &bad],
        &[],
        1,
        "is not a valid ScanResult JSON",
        "不是合法的 ScanResult JSON",
    );
}

#[test]
fn engine_failure_uses_the_error_kind_key() {
    // 沒有 syft：CytraceError::Engine——T912 前以中文 Display「引擎子程序錯誤：」印出
    let sb = Sandbox::new("nosyft");
    both_langs(
        &sb,
        &["scan", &sb.path("target")],
        &[],
        1,
        "error: Engine subprocess error: syft:",
        "錯誤：引擎子程序錯誤：syft:",
    );
}

#[test]
fn scan_cbom_non_cbom_error_is_localized() {
    // theia 存在但不可執行 → engine::cbom 回 Engine 變體（非 Cbom）。
    // T912 前 scan 路徑印 Display：「CBOM inventory failed: 引擎子程序錯誤：cbomkit-theia: …」
    let sb = Sandbox::new("theia");
    sb.shim("syft", "cyclonedx.json");
    sb.shim("grype", "grype.json");
    let theia = sb.dir.join("bin/cbomkit-theia");
    fs::write(&theia, "#!/bin/sh\n").unwrap();
    fs::set_permissions(&theia, fs::Permissions::from_mode(0o644)).unwrap();
    both_langs(
        &sb,
        &[
            "scan",
            &sb.path("target"),
            "--cbom",
            "--out-dir",
            &sb.path(""),
        ],
        &[],
        0,
        "CBOM inventory failed: Engine error",
        "引擎錯誤",
    );
}

#[test]
fn usage_errors_exit_one_not_the_fail_on_code() {
    // clap 預設以 2 結束，與 --fail-on 撞號（ADR-006）
    let sb = Sandbox::new("clap");
    for args in [
        &["run"][..],
        &["--no-such-flag"],
        &["run", "x", "--fail-on"],
        &[],
    ] {
        let o = sb.run(args, &[]);
        assert_eq!(o.code, 1, "{args:?} 應以 1 結束：{}", o.stderr);
    }
    for args in [&["--help"][..], &["--version"], &["run", "--help"]] {
        let o = sb.run(args, &[]);
        assert_eq!(o.code, 0, "{args:?} 應以 0 結束：{}", o.stderr);
    }
}

#[test]
fn language_source_precedence() {
    let sb = Sandbox::new("prec");
    let missing = sb.path("nope.json");

    // 只有環境變數 → 英文
    let o = sb.run(&["report", &missing], &[("CYTRACE_LANG", "en-US")]);
    assert!(
        o.stderr.starts_with("error: ") && !has_cjk(&o.stderr),
        "{}",
        o.stderr
    );

    // 旗標優先於環境變數；--lang 是全域旗標，放在子命令後也算
    let o = sb.run(
        &["report", &missing, "--lang", "zh-TW"],
        &[("CYTRACE_LANG", "en-US")],
    );
    assert!(o.stderr.starts_with("錯誤："), "{}", o.stderr);

    // 都沒有 → zh-TW；空白的環境變數視同未設
    for env in [&[][..], &[("CYTRACE_LANG", "  ")]] {
        let o = sb.run(&["report", &missing], env);
        assert!(o.stderr.starts_with("錯誤："), "{env:?}：{}", o.stderr);
    }

    // 寬鬆寫法沿用既有正規化（en、EN、en_US.UTF-8 都是英文）
    for v in ["en", "EN", "en_US.UTF-8"] {
        let o = sb.run(&["report", &missing], &[("CYTRACE_LANG", v)]);
        assert!(!has_cjk(&o.stderr), "{v}：{}", o.stderr);
    }
}

#[test]
fn unsupported_language_warns_in_both_languages_then_uses_zh_tw() {
    let sb = Sandbox::new("unsup");
    let missing = sb.path("nope.json");
    for (args, env) in [
        (vec!["--lang", "fr", "report", &missing], vec![]),
        (vec!["report", &missing], vec![("CYTRACE_LANG", "de-DE")]),
    ] {
        let o = sb.run(&args, &env);
        assert_eq!(o.code, 1);
        assert!(o.stderr.contains("不支援的語言"), "{}", o.stderr);
        assert!(o.stderr.contains("Unsupported language"), "{}", o.stderr);
        assert!(o.stderr.contains("錯誤：無法讀取"), "{}", o.stderr);
        assert_eq!(bare_key(&o.stderr), None, "{}", o.stderr);
    }
    // 旗標不支援時不往下找環境變數：明確給了 --lang 卻悄悄改用環境變數更難察覺
    let o = sb.run(
        &["--lang", "fr", "report", &missing],
        &[("CYTRACE_LANG", "en-US")],
    );
    assert!(o.stderr.contains("錯誤：無法讀取"), "{}", o.stderr);
}

#[cfg(feature = "server")]
mod serve {
    use super::*;
    use std::sync::LazyLock;

    static PHC: LazyLock<String> =
        LazyLock::new(|| cytrace_server::auth::hash_password("operator-lang-test").unwrap());

    #[test]
    fn startup_errors_are_localized() {
        let sb = Sandbox::new("serve");
        let data = sb.path("data");

        // bind 在 admin hash 之前檢查；訊息指名值的來源
        let (en, _) = both_langs(
            &sb,
            &["serve", "--bind", "not-an-addr"],
            &[],
            1,
            "--bind is not a valid listen address",
            "--bind 不是合法的監聽位址",
        );
        assert!(en.stderr.contains("not-an-addr"), "{}", en.stderr);
        both_langs(
            &sb,
            &["serve"],
            &[("CYTRACE_BIND", "x:y")],
            1,
            "CYTRACE_BIND is not a valid listen address",
            "CYTRACE_BIND 不是合法的監聽位址",
        );

        both_langs(
            &sb,
            &["serve"],
            &[],
            1,
            "CYTRACE_ADMIN_PASSWORD_HASH is not set",
            "缺少 CYTRACE_ADMIN_PASSWORD_HASH",
        );

        let hash = [("CYTRACE_ADMIN_PASSWORD_HASH", PHC.as_str())];
        both_langs(
            &sb,
            &["serve", "--tls-cert", "/x.crt"],
            &hash,
            1,
            "must be set together",
            "必須成對設定",
        );
        both_langs(
            &sb,
            &["serve"],
            &[hash[0], ("CYTRACE_MAX_QUEUED", "lots")],
            1,
            "CYTRACE_MAX_QUEUED must be a non-negative integer: lots",
            "CYTRACE_MAX_QUEUED 必須是非負整數：lots",
        );

        // 資料目錄建不了：data/jobs 被一般檔案佔住
        fs::create_dir_all(&data).unwrap();
        fs::write(sb.dir.join("data/jobs"), "").unwrap();
        both_langs(
            &sb,
            &["serve", "--bind", "127.0.0.1:0", "--data-dir", &data],
            &hash,
            1,
            "Cannot create data directory",
            "無法建立資料目錄",
        );
    }

    #[test]
    fn quarantine_notice_and_tls_error_use_operator_language() {
        // 先在 registry 開啟時隔離一筆損毀的 job，再因 TLS 檔不存在而結束——
        // 不必讓服務真的起來，就能同時看到執行期訊息與啟動錯誤
        for (lang, quarantined, tls) in [
            (
                "en-US",
                "Corrupt job.json; quarantined to",
                "Failed to load TLS certificate",
            ),
            ("zh-TW", "job.json 損毀，已隔離至", "TLS 憑證載入失敗"),
        ] {
            let sb = Sandbox::new(&format!("tls-{lang}"));
            let job = sb.dir.join("data/jobs/1-bad");
            fs::create_dir_all(&job).unwrap();
            fs::write(job.join("job.json"), "{not json").unwrap();
            let data = sb.path("data");
            let o = sb.run(
                &[
                    "--lang",
                    lang,
                    "serve",
                    "--bind",
                    "127.0.0.1:0",
                    "--data-dir",
                    &data,
                    "--tls-cert",
                    "/no/such.crt",
                    "--tls-key",
                    "/no/such.key",
                ],
                &[("CYTRACE_ADMIN_PASSWORD_HASH", PHC.as_str())],
            );
            assert_eq!(o.code, 1, "{lang}：{}", o.stderr);
            assert!(o.stderr.contains(quarantined), "{lang}：{}", o.stderr);
            assert!(o.stderr.contains(tls), "{lang}：{}", o.stderr);
            assert_eq!(bare_key(&o.stderr), None, "{lang}：{}", o.stderr);
            assert_eq!(lang == "zh-TW", has_cjk(&o.stderr), "{lang}：{}", o.stderr);
            assert!(sb.dir.join("data/jobs/1-bad.corrupt").is_dir());
        }
    }

    #[test]
    fn health_invalid_address_is_localized() {
        let sb = Sandbox::new("health");
        both_langs(
            &sb,
            &["health", "--bind", "nope"],
            &[],
            1,
            "error: Invalid address: nope",
            "錯誤：位址不合法：nope",
        );
    }
}
