//! 操作者終端訊息的語言與退出碼（T912）——以真實 binary 端到端驗證。
//!
//! 以修正前的 binary（476c150）執行本檔，16 支情境測試中 13 支轉紅（`--lang en-US` 下印出
//! 「錯誤 / error: 引擎子程序錯誤：…」、serve 啟動錯誤整句中文、clap 用法錯誤回 2）。
//! 每支在第一個不符的斷言就停下，故這不代表同一支裡的每個樣本都逐一驗過紅燈。
//! 其餘 3 支（成功的 run、health、較新 schema 的 report）的訊息在修正前就已在地化，是防回歸用。
//!
//! 斷言只針對**我方文字**：細節裡的系統訊息（`No such file or directory`）語言由 OS 決定，
//! 這裡的 CI 與開發機都是英文 locale，但不斷言其內容。
//!
//! stdout 與 stderr 都驗：listening、明文警告、shutdown、完成、報表已輸出、服務存活等在 stdout
//! （T912 複審 gates#8）。每一次執行的輸出都斷言無裸鍵、無殘留 `{{`（插值變數漏給時
//! `Catalog::t` 會原樣保留；複審 gates#7）；我方文字另斷言語言相符。T914 起 `--help` 與用法錯誤
//! 也依操作者語言，一併驗；只有刻意兩語並陳的輸出（不支援語言的警告）不驗語言。
//!
//! `hash-password` 沒有 tty 的情境以 `setsid -w` 在新 session 執行（沒有控制終端機，/dev/tty
//! 開不了，與容器未加 `-t` 相同），只在 Linux 跑。

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

/// catalog 的全部葉鍵（`cli.err.prefix`…）。
static KEYS: std::sync::LazyLock<Vec<String>> = std::sync::LazyLock::new(|| {
    fn leaves(v: &serde_json::Value, prefix: &str, out: &mut Vec<String>) {
        if let serde_json::Value::Object(m) = v {
            for (k, c) in m {
                let p = if prefix.is_empty() {
                    k.clone()
                } else {
                    format!("{prefix}.{k}")
                };
                leaves(c, &p, out);
            }
        } else {
            out.push(prefix.to_string());
        }
    }
    let raw = include_str!("../../../locales/zh-TW.json");
    let mut out = Vec::new();
    leaves(
        &serde_json::from_str(raw).expect("locale JSON"),
        "",
        &mut out,
    );
    assert!(out.len() >= 150, "只讀到 {} 個鍵", out.len());
    out
});

/// 輸出中出現鍵本身＝有鍵沒被翻譯就印出去了。兩種判定：
/// - catalog 的真實鍵名；
/// - 我方命名空間開頭的點分詞（`cli.err.prefx`）——鍵打錯時 `Catalog::t` 原樣回傳，它不在
///   catalog 裡；結尾是副檔名的（help 裡的 `cbom.cdx.json`）是檔名，不算。
///
/// 前版只用命名空間前綴猜，把 `cbom.cdx.json` 誤判成鍵。
fn bare_key(s: &str) -> Option<String> {
    let ident = |c: char| c.is_alphanumeric() || c == '_' || c == '.' || c == '-';
    let tokens = s.split(|c: char| !ident(c)).filter(|t| !t.is_empty());
    for t in tokens {
        let t = t.trim_matches('.');
        if KEYS.iter().any(|k| k == t) {
            return Some(t.to_string());
        }
        let mut segs = t.split('.');
        let ns = segs.next().unwrap_or_default();
        let rest: Vec<&str> = segs.collect();
        let file_ext = [
            "json", "html", "txt", "crt", "key", "pem", "md", "js", "css",
        ];
        if ["cli", "server", "cbom", "severity", "report", "console"].contains(&ns)
            && !rest.is_empty()
            && rest
                .iter()
                .all(|r| !r.is_empty() && r.chars().all(|c| c.is_ascii_lowercase() || c == '_'))
            && !rest.last().is_some_and(|e| file_ext.contains(e))
        {
            return Some(t.to_string());
        }
    }
    None
}

struct Sandbox {
    dir: PathBuf,
}

struct Out {
    code: i32,
    stdout: String,
    stderr: String,
}

impl Out {
    /// 兩條輸出合併：語言與裸鍵的判定對兩者一視同仁。
    fn all(&self) -> String {
        format!("{}{}", self.stdout, self.stderr)
    }
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

/// 在讀鎖下執行子程序並收集輸出。
fn exec(cmd: &mut Command) -> Out {
    let _g = spawning();
    out_of(cmd.output().expect("執行子程序"))
}

fn out_of(o: std::process::Output) -> Out {
    Out {
        code: o.status.code().expect("退出碼"),
        stdout: String::from_utf8_lossy(&o.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&o.stderr).into_owned(),
    }
}

/// 每個情境都要成立的：無裸鍵、無殘留佔位符、沒有 panic。
/// 只有刻意兩語並陳的輸出（不支援語言的警告）只驗這一層。
fn assert_no_raw(o: &Out, ctx: &str) {
    let all = o.all();
    assert_eq!(bare_key(&all), None, "裸鍵：{ctx}");
    assert!(!all.contains("{{"), "殘留佔位符：{ctx}");
    assert!(!all.contains("panicked"), "panic：{ctx}");
}

/// 我方輸出的共同不變量：[`assert_no_raw`] 加上語言相符。
fn assert_operator_text(lang: &str, o: &Out, ctx: &str) {
    assert_no_raw(o, ctx);
    let all = o.all();
    if lang == "en-US" {
        assert!(!has_cjk(&all), "en-US 不得出現中文：{ctx}");
    } else {
        // 逐行：整份輸出只要有一個中文字就過的話，夾在中文行之間的英文硬編碼抓不到
        // （第三輪複審：`Scanning {target}`、`Report written:` 改成英文硬編碼，全套仍綠）
        let english: Vec<&str> = all
            .lines()
            .filter(|l| !l.trim().is_empty() && !has_cjk(l))
            .collect();
        assert!(
            english.is_empty(),
            "zh-TW 有不含中文的行 {english:?}：{ctx}"
        );
    }
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
        let _w = writing();
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
        exec(&mut cmd)
    }
}

impl Drop for Sandbox {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.dir);
    }
}

/// 同一情境各以兩種語言跑一次：en-US 不得有 CJK、zh-TW 必須有 CJK，兩者都不得有裸鍵或
/// 殘留佔位符，且各自含預期的我方文字片段。回傳兩次的輸出供個別情境加驗（例如實際的路徑）。
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
        let ctx = format!(
            "{lang} {args:?}\nstdout:\n{}\nstderr:\n{}",
            o.stdout, o.stderr
        );
        assert_eq!(o.code, expect_code, "退出碼：{ctx}");
        assert!(o.all().contains(has), "應含「{has}」：{ctx}");
        assert_operator_text(lang, &o, &ctx);
        outs.push(o);
    }
    let zh = outs.pop().unwrap();
    let en = outs.pop().unwrap();
    (en, zh)
}

#[test]
fn self_check_detectors() {
    assert!(has_cjk("錯誤：x") && has_cjk("a（b") && !has_cjk("error: x — “y”"));
    let k = |s: &str| Some(s.to_string());
    assert_eq!(bare_key("error: cli.err.prefix"), k("cli.err.prefix"));
    assert_eq!(
        bare_key("x server.startup.tls_unpaired"),
        k("server.startup.tls_unpaired")
    );
    assert_eq!(bare_key("(cbom.err.timeout)"), k("cbom.err.timeout"));
    // 打錯的鍵不在 catalog 裡，也要抓到
    assert_eq!(bare_key("錯誤：cli.err.prefx"), k("cli.err.prefx"));
    assert_eq!(bare_key("cytrace-server: Corrupt job.json"), None);
    assert_eq!(bare_key("see job.json (cli.)"), None);
    // help 裡的檔名不是鍵
    assert_eq!(bare_key("另產 cbom.cdx.json"), None);
    assert_eq!(bare_key("/tmp/x/sbom.cdx.json"), None);
}

#[test]
fn report_read_and_parse_failures_name_the_path() {
    let sb = Sandbox::new("report");
    let missing = sb.path("nope.json");
    let (en, zh) = both_langs(
        &sb,
        &["report", &missing],
        &[],
        1,
        "error: Cannot read",
        "錯誤：無法讀取",
    );
    for o in [&en, &zh] {
        assert!(o.stderr.contains(&missing), "應指名路徑：{}", o.stderr);
    }

    fs::write(sb.dir.join("bad.json"), "{not json").unwrap();
    let bad = sb.path("bad.json");
    let (en, zh) = both_langs(
        &sb,
        &["report", &bad],
        &[],
        1,
        "is not a valid ScanResult JSON",
        "不是合法的 ScanResult JSON",
    );
    for o in [&en, &zh] {
        assert!(o.stderr.contains(&bad), "應指名路徑：{}", o.stderr);
    }
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
    {
        let _w = writing();
        fs::write(&theia, "#!/bin/sh\n").unwrap();
        fs::set_permissions(&theia, fs::Permissions::from_mode(0o644)).unwrap();
    }
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

/// 用法錯誤：退出碼 1（clap 預設的 2 與 --fail-on 撞號，ADR-006），訊息依操作者語言（T914）。
/// 每個樣本兩種語言各跑一次，並帶出使用者給的值，且提示指向該子命令的 --help。
#[test]
fn usage_errors_exit_one_in_the_operator_language() {
    let sb = Sandbox::new("clap");
    for (args, en, zh, value) in [
        (
            &["run"][..],
            "missing required arguments",
            "缺少必要的參數",
            "<TARGET>",
        ),
        (
            &["run", "x", "--no-such-flag"],
            "unknown argument",
            "不認得的參數",
            "--no-such-flag",
        ),
        (
            &["run", "x", "--fail-on"],
            "requires a value",
            "需要一個值",
            "--fail-on",
        ),
        (
            &["run", "x", "--fail-on", "zz"],
            "is not a valid value",
            "不是",
            "zz",
        ),
        (&["bogus"], "unknown subcommand", "不認得的子命令", "bogus"),
        (
            &["run", "x", "--fail-on-quantum-vulnerable"],
            "missing required arguments",
            "缺少必要的參數",
            "--cbom",
        ),
    ] {
        let (o_en, o_zh) = both_langs(&sb, args, &[], 1, en, zh);
        for o in [&o_en, &o_zh] {
            assert!(
                o.stderr.contains(value),
                "{args:?} 應帶出 {value}：{}",
                o.stderr
            );
            assert!(
                o.stdout.is_empty(),
                "{args:?} 錯誤只走 stderr：{}",
                o.stdout
            );
        }
        if args[0] == "run" {
            assert!(
                o_en.stderr.contains("`cytrace run --help`"),
                "{}",
                o_en.stderr
            );
        }
    }
}

/// `--help`：每個子命令與頂層都依操作者語言（T914；修正前 doc 註解寫死中文、clap 標題是英文）。
#[test]
fn help_follows_operator_language() {
    let sb = Sandbox::new("help");
    // 純 CLI 建置沒有 serve 系列子命令，下面的 extend 不存在
    #[cfg_attr(not(feature = "server"), allow(unused_mut))]
    let mut subs = vec![
        vec!["--help"],
        vec!["run", "--help"],
        vec!["batch", "--help"],
        vec!["scan", "--help"],
        vec!["report", "--help"],
    ];
    #[cfg(feature = "server")]
    subs.extend([
        vec!["serve", "--help"],
        vec!["hash-password", "--help"],
        vec!["health", "--help"],
    ]);
    for args in subs {
        let (en, zh) = both_langs(&sb, &args, &[], 0, "Usage: cytrace", "用法：cytrace");
        assert!(en.stdout.contains("Print help"), "{}", en.stdout);
        assert!(zh.stdout.contains("顯示說明"), "{}", zh.stdout);
        // clap 會把英文的 `[possible values: …]` 接在說明同一行後面，逐行判語言抓不到；
        // 可用值已寫進我方說明，這段必須被隱藏
        for o in [&en, &zh] {
            assert!(
                !o.stdout.contains("possible values"),
                "{args:?}：{}",
                o.stdout
            );
        }
    }
    // 完全不帶參數：整頁說明到 stderr、以 1 結束（語言只能來自 CYTRACE_LANG）
    for (lang, has) in [("en-US", "Commands:"), ("zh-TW", "命令:")] {
        let o = sb.run(&[], &[("CYTRACE_LANG", lang)]);
        let ctx = format!("{lang}\nstderr:\n{}", o.stderr);
        assert_eq!(o.code, 1, "{ctx}");
        assert!(o.stderr.contains(has) && o.stdout.is_empty(), "{ctx}");
        assert_operator_text(lang, &o, &ctx);
    }
    // 給了旗標卻沒有子命令：一行錯誤加提示（clap 此時回報缺少子命令，而非印整頁）
    both_langs(&sb, &[], &[], 1, "missing subcommand", "缺少子命令");
    // --version 不受語言影響、以 0 結束
    let o = sb.run(&["--version"], &[]);
    assert_eq!(o.code, 0, "{}", o.stderr);
    assert!(o.stdout.starts_with("cytrace "), "{}", o.stdout);
}

/// `--fail-on hgih`：T912 前任何字串都被接受、未知值落到最低的 unknown，打錯字等於
/// 「有任何弱點就以 2 結束」（複審 cli#2）。
///
/// 掃描必須真的跑得完（shim），才分得出「門檻觸發的 2」與「用法錯誤的 1」——沒有 shim 時
/// 程式會因找不到 syft 而回 1，不論值是否被驗都一樣（故障注入 R9 抓到前版這裡空轉）。
#[test]
fn fail_on_typo_is_a_usage_error_not_a_threshold() {
    let sb = Sandbox::new("failon");
    sb.shim("syft", "cyclonedx.json");
    sb.shim("grype", "grype.json");
    let target = sb.path("target");
    let report = sb.path("r.html");
    let dir = sb.path("");

    // 對照組：合法值（大小寫不拘）照常觸發——fixture 含 high 弱點
    for v in ["high", "HIGH"] {
        let o = sb.run(&["run", &target, "--fail-on", v, "-o", &report], &[]);
        assert_eq!(o.code, 2, "{v}：{}", o.stderr);
        assert_operator_text("zh-TW", &o, v);
    }
    // 空字串在 clap 眼中等同沒給值，訊息是「需要一個值」
    for (args, want) in [
        (
            vec!["run", &target, "--fail-on", "hgih", "-o", &report],
            "is not a valid value",
        ),
        (
            vec!["batch", &target, "--fail-on", "", "--out-dir", &dir],
            "requires a value",
        ),
    ] {
        let o = sb.run(&args, &[("CYTRACE_LANG", "en-US")]);
        assert_eq!(o.code, 1, "{args:?}：{}", o.stderr);
        assert!(o.stderr.contains(want), "{args:?}：{}", o.stderr);
        assert_operator_text("en-US", &o, &format!("{args:?}"));
        assert!(
            !o.all().contains("Reached --fail-on threshold"),
            "{args:?} 不得被當成門檻：{}",
            o.all()
        );
    }
}

/// 成功路徑的 stdout：盤點完成、完成（含風險等級）、報表已輸出（T912 複審 gates#8：
/// 這幾則在 stdout，前版沒有任何情境走到成功的 run）。
#[test]
fn successful_run_reports_in_operator_language() {
    let sb = Sandbox::new("ok-run");
    sb.shim("syft", "cyclonedx.json");
    sb.shim("grype", "grype.json");
    sb.shim("cbomkit-theia", "cbom.json");
    let report = sb.path("r.html");
    let (en, zh) = both_langs(
        &sb,
        &["run", &sb.path("target"), "--cbom", "-o", &report],
        &[],
        0,
        "Cryptographic asset inventory complete: 12 items",
        "密碼學資產盤點完成：12 項",
    );
    for (o, done, written) in [
        (
            &en,
            "Done: 2 vulnerabilities, overall risk Critical",
            "Report written: ",
        ),
        (&zh, "完成：2 個弱點，風險總評 極高", "報表已輸出："),
    ] {
        assert!(o.stdout.contains(done), "{}", o.stdout);
        assert!(
            o.stdout.contains(&format!("{written}{report}")),
            "{}",
            o.stdout
        );
    }
}

/// `report` 讀到較新 schema 的檔案：警告要列出兩個版本號（鍵不是字面值，插值對帳比不到——
/// 由本情境涵蓋，見 tests/i18n_call_vars.rs 的 NONLITERAL；T912 複審 newgates#3）。
#[test]
fn report_on_a_newer_schema_names_both_versions() {
    let sb = Sandbox::new("schema");
    let golden = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../cytrace-core/tests/golden/scanresult.json"
    );
    let mut v: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(golden).unwrap()).unwrap();
    v["schema_version"] = serde_json::json!(99);
    let input = sb.path("future.json");
    fs::write(&input, v.to_string()).unwrap();
    let (en, zh) = both_langs(
        &sb,
        &["report", &input, "-o", &sb.path("future.html")],
        &[],
        0,
        "schema v99; this build supports v",
        "schema v99，本版支援 v",
    );
    for o in [&en, &zh] {
        assert!(o.stdout.contains(&sb.path("future.html")), "{}", o.stdout);
    }
}

#[test]
fn language_source_precedence() {
    let sb = Sandbox::new("prec");
    let missing = sb.path("nope.json");

    let check = |o: &Out, lang: &str, prefix: &str, ctx: &str| {
        assert!(o.stderr.starts_with(prefix), "{ctx}：{}", o.stderr);
        assert!(
            o.stderr.contains(&missing),
            "{ctx} 應指名路徑：{}",
            o.stderr
        );
        assert_operator_text(lang, o, ctx);
    };

    // 只有環境變數 → 英文
    let o = sb.run(&["report", &missing], &[("CYTRACE_LANG", "en-US")]);
    check(&o, "en-US", "error: ", "env en-US");

    // 旗標優先於環境變數；--lang 是全域旗標，放在子命令後也算
    let o = sb.run(
        &["report", &missing, "--lang", "zh-TW"],
        &[("CYTRACE_LANG", "en-US")],
    );
    check(&o, "zh-TW", "錯誤：", "flag zh-TW over env en-US");

    // 都沒有 → zh-TW；空白的環境變數視同未設
    for env in [&[][..], &[("CYTRACE_LANG", "  ")]] {
        let o = sb.run(&["report", &missing], env);
        check(&o, "zh-TW", "錯誤：", &format!("{env:?}"));
    }

    // 寬鬆寫法沿用既有正規化（en、EN、en_US.UTF-8 都是英文）
    for v in ["en", "EN", "en_US.UTF-8"] {
        let o = sb.run(&["report", &missing], &[("CYTRACE_LANG", v)]);
        check(&o, "en-US", "error: ", v);
    }
}

#[test]
fn unsupported_language_warns_in_both_languages_then_uses_zh_tw() {
    let sb = Sandbox::new("unsup");
    let missing = sb.path("nope.json");
    for (args, env, raw) in [
        (vec!["--lang", "fr", "report", &missing], vec![], "fr"),
        (
            vec!["report", &missing],
            vec![("CYTRACE_LANG", "de-DE")],
            "de-DE",
        ),
    ] {
        let o = sb.run(&args, &env);
        assert_eq!(o.code, 1);
        assert!(o.stderr.contains("不支援的語言"), "{}", o.stderr);
        assert!(o.stderr.contains("Unsupported language"), "{}", o.stderr);
        assert!(o.stderr.contains("錯誤：無法讀取"), "{}", o.stderr);
        // 兩種語言的警告都要帶出使用者給的原值
        assert_eq!(o.stderr.matches(raw).count(), 2, "{}", o.stderr);
        assert_no_raw(&o, raw);
    }
    // 旗標不支援時不往下找環境變數：明確給了 --lang 卻悄悄改用環境變數更難察覺
    let o = sb.run(
        &["--lang", "fr", "report", &missing],
        &[("CYTRACE_LANG", "en-US")],
    );
    assert!(o.stderr.contains("錯誤：無法讀取"), "{}", o.stderr);
    assert_no_raw(&o, "fr over env en-US");
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
        let (en, zh) = both_langs(
            &sb,
            &["serve"],
            &[("CYTRACE_BIND", "x:y")],
            1,
            "CYTRACE_BIND is not a valid listen address",
            "CYTRACE_BIND 不是合法的監聽位址",
        );
        for o in [&en, &zh] {
            assert!(o.stderr.contains("x:y"), "{}", o.stderr);
        }

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

        // 位址已被占用：listen_failed 指名位址
        let taken = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = taken.local_addr().unwrap().to_string();
        let (en, zh) = both_langs(
            &sb,
            &[
                "serve",
                "--bind",
                &addr,
                "--data-dir",
                &sb.path("data-listen"),
            ],
            &hash,
            1,
            "Cannot serve on",
            "無法在",
        );
        for o in [&en, &zh] {
            assert!(o.stderr.contains(&addr), "應指名位址：{}", o.stderr);
        }
        drop(taken);

        // 資料目錄建不了：data/jobs 被一般檔案佔住
        fs::create_dir_all(&data).unwrap();
        fs::write(sb.dir.join("data/jobs"), "").unwrap();
        let (en, zh) = both_langs(
            &sb,
            &["serve", "--bind", "127.0.0.1:0", "--data-dir", &data],
            &hash,
            1,
            "Cannot create data directory",
            "無法建立資料目錄",
        );
        let jobs = sb.path("data/jobs");
        for o in [&en, &zh] {
            assert!(o.stderr.contains(&jobs), "應指名路徑：{}", o.stderr);
        }
    }

    /// 服務真的起來：listening、明文警告（stdout）與收到 SIGINT 後的 shutdown 訊息。
    /// 語言只由 `CYTRACE_LANG` 給——這個來源是 T912 新加的，錯誤路徑以外沒有別處驗它。
    #[test]
    fn running_server_messages_follow_operator_language() {
        use std::io::{BufRead, BufReader, Read};
        use std::process::Stdio;
        use std::sync::mpsc;
        use std::time::{Duration, Instant};

        for (env_lang, want) in [
            (
                Some("en-US"),
                [
                    "serving plaintext HTTP",
                    "listening on",
                    "Shutdown signal received",
                ],
            ),
            (None, ["以 HTTP 明文提供服務", "服務已啟動", "收到中止訊號"]),
        ] {
            let lang = env_lang.unwrap_or("zh-TW");
            let sb = Sandbox::new(&format!("up-{lang}"));
            let mut cmd = Command::new(env!("CARGO_BIN_EXE_cytrace"));
            cmd.args([
                "serve",
                "--bind",
                "127.0.0.1:0",
                "--data-dir",
                &sb.path("data"),
            ])
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("CYTRACE_ADMIN_PASSWORD_HASH", PHC.as_str())
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
            if let Some(l) = env_lang {
                cmd.env("CYTRACE_LANG", l);
            }
            let mut child = {
                let _g = spawning();
                cmd.spawn().expect("啟動 serve")
            };
            let (tx, rx) = mpsc::channel();
            let stdout = child.stdout.take().unwrap();
            let reader = std::thread::spawn(move || {
                for line in BufReader::new(stdout).lines() {
                    let Ok(line) = line else { break };
                    let _ = tx.send(line);
                }
            });
            let mut stderr = child.stderr.take().unwrap();
            let err_reader = std::thread::spawn(move || {
                let mut s = String::new();
                let _ = stderr.read_to_string(&mut s);
                s
            });

            // 等到 listening 行（實際位址確定後才印）
            let mut lines: Vec<String> = Vec::new();
            let deadline = Instant::now() + Duration::from_secs(30);
            while !lines.iter().any(|l| l.contains("127.0.0.1:")) {
                let left = deadline.saturating_duration_since(Instant::now());
                match rx.recv_timeout(left) {
                    Ok(l) => lines.push(l),
                    Err(_) => {
                        let _ = child.kill();
                        panic!("{lang}：30 秒內沒等到 listening 行：{lines:?}");
                    }
                }
            }
            let pid = child.id().to_string();
            let killed = {
                let _g = spawning();
                Command::new("kill").args(["-INT", &pid]).status().unwrap()
            };
            assert!(killed.success());
            let deadline = Instant::now() + Duration::from_secs(30);
            let status = loop {
                if let Some(st) = child.try_wait().unwrap() {
                    break st;
                }
                if Instant::now() > deadline {
                    let _ = child.kill();
                    panic!("{lang}：SIGINT 後 30 秒未結束");
                }
                std::thread::sleep(Duration::from_millis(50));
            };
            reader.join().unwrap();
            lines.extend(rx.try_iter());
            let o = Out {
                // 被訊號殺掉（handler 沒接住）時沒有退出碼——說清楚是哪一種失敗
                code: status.code().unwrap_or_else(|| {
                    use std::os::unix::process::ExitStatusExt;
                    panic!(
                        "{lang}：serve 被訊號 {:?} 終止，未優雅關閉",
                        status.signal()
                    )
                }),
                stdout: lines.join("\n"),
                stderr: err_reader.join().unwrap(),
            };
            let ctx = format!("{lang}\nstdout:\n{}\nstderr:\n{}", o.stdout, o.stderr);
            assert_eq!(o.code, 0, "{ctx}");
            for w in want {
                assert!(o.stdout.contains(w), "應含「{w}」：{ctx}");
            }
            assert_operator_text(lang, &o, &ctx);
        }
    }

    /// 沒有控制終端機（容器未加 `-t`）：rpassword 開不了 /dev/tty。
    /// `setsid -w` 讓子程序在新 session 執行——有 tty 的開發機上也不會改讀終端而卡住。
    #[cfg(target_os = "linux")]
    #[test]
    fn hash_password_without_a_terminal_is_localized() {
        for (lang, has) in [
            ("en-US", "error: Cannot read the password"),
            ("zh-TW", "錯誤：無法讀取密碼輸入"),
        ] {
            // setsid 來自 util-linux；不存在時 exec 會 panic（紅），不會靜默略過
            let o = exec(
                Command::new("setsid")
                    .arg("-w")
                    .arg(env!("CARGO_BIN_EXE_cytrace"))
                    .args(["--lang", lang, "hash-password"])
                    .env_clear()
                    .env("PATH", "/usr/bin:/bin")
                    .stdin(std::process::Stdio::null()),
            );
            let ctx = format!("{lang}\nstdout:\n{}\nstderr:\n{}", o.stdout, o.stderr);
            assert_eq!(o.code, 1, "{ctx}");
            assert!(o.stderr.contains(has), "應含「{has}」：{ctx}");
            assert_operator_text(lang, &o, &ctx);
        }
    }

    /// 環境變數不是合法 UTF-8：與我方無關的照常略過；我方的（`CYTRACE_*`、`GRYPE_DB_CACHE_DIR`）
    /// 指名報錯。T912 前 serve 用 `std::env::vars()`，任一變數壞掉就 panic（複審 cli#4）；
    /// 61719e7 改用替代字元，路徑類變數卻因此悄悄改用另一個目錄（複審 newcode#0）。
    #[test]
    fn non_utf8_environment_is_tolerated_or_named() {
        use std::ffi::OsStr;
        use std::os::unix::ffi::OsStrExt;
        let bad = OsStr::from_bytes(b"/tmp/d\xff");
        let run = |lang: &str, sub: &str, var: &str| {
            exec(
                Command::new(env!("CARGO_BIN_EXE_cytrace"))
                    .args(["--lang", lang, sub])
                    .env_clear()
                    .env("PATH", "/usr/bin:/bin")
                    .env("CYTRACE_ADMIN_PASSWORD_HASH", PHC.as_str())
                    .env("CYTRACE_BIND", "127.0.0.1:1")
                    .env(var, bad)
                    .stdin(std::process::Stdio::null()),
            )
        };
        // 無關的變數：照常走下去（health 連不上 127.0.0.1:1 → 1，訊息是「無法連線」）
        let o = run("en-US", "health", "FOO");
        assert_eq!(o.code, 1, "{}", o.stderr);
        assert!(o.stderr.contains("Cannot connect"), "{}", o.stderr);
        assert_operator_text("en-US", &o, "FOO");

        for (sub, var) in [
            ("serve", "CYTRACE_DATA_DIR"),
            ("serve", "GRYPE_DB_CACHE_DIR"),
            ("serve", "CYTRACE_BIND"),
            ("health", "CYTRACE_BIND"),
        ] {
            for (lang, has) in [
                ("en-US", "is not valid UTF-8"),
                ("zh-TW", "不是合法的 UTF-8"),
            ] {
                let o = run(lang, sub, var);
                let ctx = format!(
                    "{lang} {sub} {var}\nstdout:\n{}\nstderr:\n{}",
                    o.stdout, o.stderr
                );
                assert_eq!(o.code, 1, "{ctx}");
                assert!(o.stderr.contains(has) && o.stderr.contains(var), "{ctx}");
                assert_operator_text(lang, &o, &ctx);
            }
        }

        // 不該擋的：旗標已覆寫的變數、不經 ServerConfig::resolve 讀取的變數（第三輪複審：前版在收集環境時就報錯，
        // `--data-dir` 配上壞掉的 CYTRACE_DATA_DIR 照樣起不來）。以不存在的 TLS 檔讓服務在綁定前結束
        let sb = Sandbox::new("nonutf8-ok");
        let data = sb.path("data");
        for (var, extra) in [
            // 基本參數已帶 --data-dir：覆寫壞掉的 CYTRACE_DATA_DIR
            ("CYTRACE_DATA_DIR", &[][..]),
            ("CYTRACE_BIND", &["--bind", "127.0.0.1:0"]),
            ("CYTRACE_LANG", &[]),
            ("CYTRACE_CBOM_TIMEOUT_SECS", &[]),
            ("FOO", &[]),
        ] {
            let mut args = vec![
                "--lang",
                "en-US",
                "serve",
                "--data-dir",
                data.as_str(),
                "--tls-cert",
                "/no/such.crt",
                "--tls-key",
                "/no/such.key",
            ];
            args.extend_from_slice(extra);
            let o = exec(
                Command::new(env!("CARGO_BIN_EXE_cytrace"))
                    .args(&args)
                    .env_clear()
                    .env("PATH", "/usr/bin:/bin")
                    .env("CYTRACE_ADMIN_PASSWORD_HASH", PHC.as_str())
                    .env("CYTRACE_BIND", "127.0.0.1:0")
                    .env(var, bad)
                    .stdin(std::process::Stdio::null()),
            );
            let ctx = format!("{var} {extra:?}\nstderr:\n{}", o.stderr);
            assert_eq!(o.code, 1, "{ctx}");
            assert!(o.stderr.contains("Failed to load TLS certificate"), "{ctx}");
            assert!(!o.stderr.contains("UTF-8"), "{ctx}");
            assert_operator_text("en-US", &o, &ctx);
        }
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
            let ctx = format!("{lang}\nstdout:\n{}\nstderr:\n{}", o.stdout, o.stderr);
            assert_eq!(o.code, 1, "{ctx}");
            assert!(o.stderr.contains(quarantined), "{ctx}");
            assert!(o.stderr.contains(tls), "{ctx}");
            // 實際的值要印出來：隔離目的地與兩個 PEM 路徑
            for v in ["1-bad.corrupt", "/no/such.crt", "/no/such.key"] {
                assert!(o.stderr.contains(v), "應含「{v}」：{ctx}");
            }
            assert_operator_text(lang, &o, &ctx);
            assert!(sb.dir.join("data/jobs/1-bad.corrupt").is_dir());
        }
    }

    #[test]
    fn health_ok_is_localized() {
        let sb = Sandbox::new("health-ok");
        let live = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = live.local_addr().unwrap().to_string();
        let (en, zh) = both_langs(
            &sb,
            &["health", "--bind", &addr],
            &[],
            0,
            "Service alive: ",
            "服務存活：",
        );
        for o in [&en, &zh] {
            assert!(o.stdout.contains(&addr), "{}", o.stdout);
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
