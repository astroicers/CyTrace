//! CyTrace CLI（SDS §2）：`cytrace run|scan|report`。
//!
//! 退出碼語意（ADR-006 / SDS §5）：`0` 正常 / `2` `--fail-on` 觸發 / 其他非 0 為錯誤。
//! 參數用法錯誤也是 `1`——clap 預設的 `2` 會與 `--fail-on` 撞號（T912）。
//!
//! 終端訊息（含錯誤）一律以操作者語言輸出：`--lang` > `CYTRACE_LANG` > zh-TW（SDS §6）。

use clap::{Parser, Subcommand};
use cytrace_core::timefmt::{epoch_secs, epoch_to_iso};
use cytrace_core::{engine, failon, parse, CytraceError};
use cytrace_i18n::{Catalog, Localized};
use cytrace_types::{Meta, Severity};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

const EXIT_OK: u8 = 0;
const EXIT_FAILON: u8 = 2;
const EXIT_ERR: u8 = 1;

/// CyTrace — 地端依賴風險報表產生器。
#[derive(Parser, Debug)]
#[command(name = "cytrace", version, about)]
struct Cli {
    /// 介面語言（zh-TW | en-US；未給時讀 CYTRACE_LANG，皆無則 zh-TW）。
    #[arg(long, global = true)]
    lang: Option<String>,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// 一鍵：產 SBOM → 比對 → 出報表（含 --fail-on）。
    Run {
        /// 掃描目標（目錄/容器映像/檔案系統）。
        target: String,
        /// 達指定嚴重度即以退出碼 2 結束（critical|high|medium|low|negligible|unknown）。
        #[arg(long)]
        fail_on: Option<String>,
        /// 報表輸出路徑（預設 ./<basename>.report.html）。
        #[arg(long, short)]
        out: Option<PathBuf>,
        /// 併同盤點密碼學資產（CBOM；ADR-013）。預設關閉。
        #[arg(long)]
        cbom: bool,
        /// 有量子脆弱資產即以退出碼 2 結束；**未取得 CBOM 結果則以 1 結束**（fail-closed）。
        #[arg(long, requires = "cbom")]
        fail_on_quantum_vulnerable: bool,
    },
    /// 多目標批次掃描（FR-010）：逐一出報表；任一目標達 --fail-on 即整體退出碼 2。
    Batch {
        /// 一或多個掃描目標。
        targets: Vec<String>,
        #[arg(long)]
        fail_on: Option<String>,
        /// 報表輸出目錄（預設目前目錄）。
        #[arg(long, short)]
        out_dir: Option<PathBuf>,
        /// 併同盤點密碼學資產（CBOM；ADR-013）。預設關閉。
        #[arg(long)]
        cbom: bool,
        /// 任一目標有量子脆弱資產即退出碼 2；任一目標未取得 CBOM 結果則整批 1。
        #[arg(long, requires = "cbom")]
        fail_on_quantum_vulnerable: bool,
    },
    /// 只產 sbom.cdx.json 與 grype.json（加 --cbom 時另產 cbom.cdx.json）。
    Scan {
        target: String,
        /// 輸出目錄（預設目前目錄）。
        #[arg(long, short)]
        out_dir: Option<PathBuf>,
        /// 併同盤點密碼學資產（CBOM；ADR-013）。預設關閉。
        #[arg(long)]
        cbom: bool,
    },
    /// 由既有 ScanResult JSON 離線重現報表（稽核複核；ADR-009）。
    Report {
        /// ScanResult JSON 路徑。
        input: PathBuf,
        /// 報表輸出路徑（預設 ./<input>.report.html）。
        #[arg(long, short)]
        out: Option<PathBuf>,
    },
    /// 啟動 Web 服務模式（ADR-011）：登入控制台 + 掃描/報表 API。
    #[cfg(feature = "server")]
    Serve {
        /// 監聽位址（預設 127.0.0.1:8443；亦可用 CYTRACE_BIND）。
        #[arg(long)]
        bind: Option<String>,
        /// 資料目錄（job 與報表產物；預設 /data；亦可用 CYTRACE_DATA_DIR）。
        #[arg(long)]
        data_dir: Option<PathBuf>,
        /// TLS 憑證 PEM（與 --tls-key 成對；亦可用 CYTRACE_TLS_CERT）。
        #[arg(long)]
        tls_cert: Option<PathBuf>,
        /// TLS 金鑰 PEM（與 --tls-cert 成對；亦可用 CYTRACE_TLS_KEY）。
        #[arg(long)]
        tls_key: Option<PathBuf>,
    },
    /// 離線產生管理密碼的 argon2id PHC 字串（放入 CYTRACE_ADMIN_PASSWORD_HASH）。
    #[cfg(feature = "server")]
    HashPassword,
    /// 服務存活檢查（TCP connect；容器 HEALTHCHECK 用，distroless 無 shell）。
    #[cfg(feature = "server")]
    Health {
        /// 檢查位址（預設同 serve 解析順序：--bind > CYTRACE_BIND > 127.0.0.1:8443）。
        #[arg(long)]
        bind: Option<String>,
    },
}

fn main() -> ExitCode {
    let cli = match Cli::try_parse() {
        Ok(cli) => cli,
        Err(e) => {
            // clap 的錯誤與 help 文字是函式庫內建英文（help 在地化另見 T914）。
            // 退出碼自己決定：help／version 為 0，其餘為 1——clap 預設的 2 是 --fail-on 的語意
            let _ = e.print();
            return ExitCode::from(if e.use_stderr() { EXIT_ERR } else { EXIT_OK });
        }
    };
    let env_lang = std::env::var_os("CYTRACE_LANG").map(|v| v.to_string_lossy().into_owned());
    let (lang, unsupported) = resolve_lang(cli.lang.as_deref(), env_lang.as_deref());
    if let Some(raw) = unsupported {
        // 要的語言不支援，也就不知道操作者讀哪一種——兩種都印
        for code in ["zh-TW", "en-US"] {
            eprintln!(
                "{}",
                Catalog::load(code).t("cli.lang_unsupported", &[("value", &raw)])
            );
        }
    }
    let cat = Catalog::load(lang);
    match run(&cli, lang, &cat) {
        Ok(code) => ExitCode::from(code),
        Err(e) => {
            eprintln!(
                "{}",
                cat.t("cli.err.prefix", &[("message", &render_error(&e, &cat))])
            );
            ExitCode::from(EXIT_ERR)
        }
    }
}

/// 介面語言：`--lang` > `CYTRACE_LANG` > zh-TW，所有子命令一致（SDS §6）。
///
/// 以**優先序最高、有給值**的來源判定；它不受支援時退回 zh-TW 並回傳原值供警告——
/// 不往下一個來源找：明確給了 `--lang` 卻悄悄改用環境變數，比退回預設更難察覺。
/// 空白的環境變數視同未設（容器常以 `CYTRACE_LANG=` 清除）。
fn resolve_lang(flag: Option<&str>, env: Option<&str>) -> (&'static str, Option<String>) {
    match flag.or(env.filter(|v| !v.trim().is_empty())) {
        None => (cytrace_i18n::DEFAULT_LANG, None),
        Some(raw) => match cytrace_i18n::lang_code(raw) {
            Some(code) => (code, None),
            None => (cytrace_i18n::DEFAULT_LANG, Some(raw.to_string())),
        },
    }
}

/// 終端錯誤 → 操作者語言。認得的型別依 catalog 渲染；其餘（第三方函式庫的錯誤）原樣附上
/// ——那是函式庫或系統的診斷，不是我們的散文（定位同 API 的 `detail`）。
fn render_error(e: &anyhow::Error, cat: &Catalog) -> String {
    if let Some(l) = e.downcast_ref::<Localized>() {
        return l.render(cat);
    }
    if let Some(c) = e.downcast_ref::<CytraceError>() {
        return render_core_error(c, cat);
    }
    e.to_string()
}

/// `CytraceError` → 操作者語言：分類走 i18n 鍵（與 server 的 job 錯誤同一組），
/// 不可翻譯的細節（路徑、子程序訊息）插值。不用 `Display`——那是語系中立的診斷。
fn render_core_error(e: &CytraceError, cat: &Catalog) -> String {
    match e {
        CytraceError::Cbom { key, detail } => cat.render_cbom(key, detail.as_deref()),
        other => {
            let what = cat.t(other.i18n_key(), &[]);
            match other.untranslatable_detail().filter(|d| !d.is_empty()) {
                Some(detail) => cat.t(
                    "cli.err.with_detail",
                    &[("what", &what), ("detail", &detail)],
                ),
                None => what,
            }
        }
    }
}

/// 帶路徑的 I/O／解析失敗：系統或函式庫訊息當細節，前後文走 i18n 鍵。
fn path_err(key: &'static str, path: &Path, e: impl std::fmt::Display) -> Localized {
    Localized::new(key)
        .var("path", path.display().to_string())
        .var("detail", e.to_string())
}

fn write_file(path: &Path, contents: impl AsRef<[u8]>) -> Result<(), Localized> {
    std::fs::write(path, contents).map_err(|e| path_err("cli.err.write_failed", path, e))
}

fn run(cli: &Cli, lang: &str, cat: &Catalog) -> anyhow::Result<u8> {
    // 只有 serve 需要語系碼本身（其餘子命令用 cat）；純 CLI 建置下沒有 serve
    #[cfg(not(feature = "server"))]
    let _ = lang;
    match &cli.command {
        Command::Report { input, out } => {
            let json = std::fs::read_to_string(input)
                .map_err(|e| path_err("cli.err.read_failed", input, e))?;
            let result: cytrace_types::ScanResult = serde_json::from_str(&json)
                .map_err(|e| path_err("cli.err.parse_failed", input, e))?;
            // 檔案來自更新版 CyTrace → serde 會靜默丟棄未知欄位，必須顯性警告
            if let Some(key) = cytrace_core::schema_warning(result.schema_version) {
                eprintln!(
                    "{}",
                    cat.t(
                        key,
                        &[
                            ("found", &result.schema_version.to_string()),
                            ("supported", &cytrace_types::SCHEMA_VERSION.to_string()),
                        ]
                    )
                );
            }
            let html = cytrace_report::render(&result)?;
            let path = out.clone().unwrap_or_else(|| default_report_path(input));
            write_file(&path, html)?;
            println!(
                "{}",
                cat.t(
                    "cli.report_written",
                    &[("path", &path.display().to_string())]
                )
            );
            Ok(EXIT_OK)
        }
        Command::Scan {
            target,
            out_dir,
            cbom,
        } => {
            let dir = out_dir.clone().unwrap_or_else(|| PathBuf::from("."));
            println!("{}", cat.t("cli.scanning", &[("target", target)]));
            let sbom = engine::sbom(target)?;
            let grype = engine::vuln(&sbom)?;
            write_file(&dir.join("sbom.cdx.json"), &sbom)?;
            write_file(&dir.join("grype.json"), &grype)?;
            if *cbom {
                // 原樣落地（ADR-013 決策 5）；失敗只警示，不影響 SBOM/CVE 產物
                match engine::cbom(target) {
                    Ok(Some(out)) => write_file(&dir.join("cbom.cdx.json"), &out.json)?,
                    Ok(None) => eprintln!("{}", cat.t("cli.cbom.engine_absent", &[])),
                    Err(e) => eprintln!(
                        "{}",
                        cat.t(
                            "cli.cbom.failed",
                            &[("reason", &render_cbom_error(&e, cat))]
                        )
                    ),
                }
            }
            Ok(EXIT_OK)
        }
        Command::Run {
            target,
            fail_on,
            out,
            cbom,
            fail_on_quantum_vulnerable,
        } => run_one(
            target,
            fail_on.as_deref(),
            out.clone(),
            cat,
            CbomOpts {
                enabled: *cbom,
                fail_on_quantum: *fail_on_quantum_vulnerable,
            },
        ),
        Command::Batch {
            targets,
            fail_on,
            out_dir,
            cbom,
            fail_on_quantum_vulnerable,
        } => {
            let dir = out_dir.clone().unwrap_or_else(|| PathBuf::from("."));
            let opts = CbomOpts {
                enabled: *cbom,
                fail_on_quantum: *fail_on_quantum_vulnerable,
            };
            let mut codes = Vec::with_capacity(targets.len());
            for target in targets {
                let out = Some(dir.join(format!("{}.report.html", sanitize(target))));
                codes.push(run_one(target, fail_on.as_deref(), out, cat, opts)?);
            }
            Ok(worst_exit(codes))
        }
        #[cfg(feature = "server")]
        Command::Serve {
            bind,
            data_dir,
            tls_cert,
            tls_key,
        } => {
            let cfg = cytrace_server::config::ServerConfig::resolve(
                cytrace_server::config::CliFlags {
                    bind: bind.clone(),
                    data_dir: data_dir.clone(),
                    tls_cert: tls_cert.clone(),
                    tls_key: tls_key.clone(),
                },
                std::env::vars().collect(),
            )?;
            cytrace_server::serve(cfg, lang)?;
            Ok(EXIT_OK)
        }
        #[cfg(feature = "server")]
        Command::HashPassword => hash_password_interactive(cat),
        #[cfg(feature = "server")]
        Command::Health { bind } => {
            // health 只需 bind 解析；不要求 admin hash（可在 provision 前檢查存活）
            let bind_raw = bind
                .clone()
                .or_else(|| std::env::var("CYTRACE_BIND").ok())
                .unwrap_or_else(|| cytrace_server::config::DEFAULT_BIND.to_string());
            let target: std::net::SocketAddr = bind_raw.parse().map_err(|_| {
                Localized::new("cli.err.invalid_address").var("value", bind_raw.as_str())
            })?;
            let addr = target.to_string();
            match std::net::TcpStream::connect_timeout(&target, std::time::Duration::from_secs(3)) {
                Ok(_) => {
                    println!("{}", cat.t("cli.health.ok", &[("addr", &addr)]));
                    Ok(EXIT_OK)
                }
                Err(_) => {
                    eprintln!("{}", cat.t("cli.health.fail", &[("addr", &addr)]));
                    Ok(EXIT_ERR)
                }
            }
        }
    }
}

/// 互動式讀密碼兩次（隱藏輸入）→ 輸出 argon2id PHC 字串。
#[cfg(feature = "server")]
fn hash_password_interactive(cat: &Catalog) -> anyhow::Result<u8> {
    use cytrace_server::auth::{hash_password, MIN_PASSWORD_LEN};
    let min = MIN_PASSWORD_LEN.to_string();
    // 沒有 tty（管線、容器未加 -it）時讀不到密碼：系統訊息只說 "No such device"，補上前後文
    let password_input =
        |e: std::io::Error| Localized::new("cli.err.password_input").var("detail", e.to_string());
    let pw = rpassword::prompt_password(cat.t("cli.hashpw.prompt", &[("min", &min)]))
        .map_err(password_input)?;
    if pw.chars().count() < MIN_PASSWORD_LEN {
        eprintln!("{}", cat.t("cli.hashpw.too_short", &[("min", &min)]));
        return Ok(EXIT_ERR);
    }
    let confirm =
        rpassword::prompt_password(cat.t("cli.hashpw.confirm", &[])).map_err(password_input)?;
    if pw != confirm {
        eprintln!("{}", cat.t("cli.hashpw.mismatch", &[]));
        return Ok(EXIT_ERR);
    }
    println!("{}", cat.t("cli.hashpw.done", &[]));
    println!("{}", hash_password(&pw)?);
    Ok(EXIT_OK)
}

/// 單一目標：產 SBOM → 比對 → 解析 → 組裝 → 出報表；回傳退出碼（0 或 2）。
/// 單一目標內的雙閘門彙整（ADR-013 決策 9）。
///
/// `EXIT_ERR`（1）優先於 `EXIT_FAILON`（2）：exit 2 在本產品有明確語意——政策閘觸發、
/// 可由人裁定豁免（ADR-006）；exit 1 則是**工具沒跑成功**。量子閘門的 `NoResult`
/// 代表「根本沒掃到」，若被 `--fail-on` 的 2 蓋掉，CI 會誤讀為「有脆弱資產但掃描成功」。
fn combine_gates(failon_triggered: bool, quantum: Option<failon::QuantumGate>) -> u8 {
    let quantum_code = match quantum {
        Some(failon::QuantumGate::NoResult) => EXIT_ERR,
        Some(failon::QuantumGate::Vulnerable) => EXIT_FAILON,
        Some(failon::QuantumGate::Pass) | None => EXIT_OK,
    };
    let failon_code = if failon_triggered {
        EXIT_FAILON
    } else {
        EXIT_OK
    };
    worst_exit([quantum_code, failon_code])
}

/// 批次退出碼彙整（ADR-013 決策 9）。
///
/// 優先序：**任一目標 `EXIT_ERR` → 整批 1（優先於 2）**；否則任一 `EXIT_FAILON` → 2；否則 0。
///
/// 錯誤優先於 fail-on 的理由：`--fail-on-quantum-vulnerable` 為 fail-closed，
/// 「未取得 CBOM 結果」以 `EXIT_ERR` 表達；若被別的目標的 2 蓋掉，CI 會誤判為
/// 「有脆弱資產但掃描成功」，而實際上是**根本沒掃到**。
fn worst_exit(codes: impl IntoIterator<Item = u8>) -> u8 {
    let mut worst = EXIT_OK;
    for c in codes {
        match c {
            EXIT_ERR => return EXIT_ERR,
            EXIT_FAILON => worst = EXIT_FAILON,
            _ => {}
        }
    }
    worst
}

fn run_one(
    target: &str,
    fail_on: Option<&str>,
    out: Option<PathBuf>,
    cat: &Catalog,
    opts: CbomOpts,
) -> anyhow::Result<u8> {
    println!("{}", cat.t("cli.scanning", &[("target", target)]));
    let sbom = engine::sbom(target)?;
    let grype = engine::vuln(&sbom)?;
    let components = parse::parse_cyclonedx(&sbom)?;
    let findings = parse::parse_grype(&grype)?;
    // CBOM 失敗只影響 crypto 區段，不中止主流程（ADR-013 決策 4）
    let crypto = opts
        .enabled
        .then(|| cytrace_core::collect_cbom(&engine::RealEngine, target));
    if let Some(inv) = &crypto {
        report_cbom_status(inv, cat);
    }
    let result = cytrace_core::assemble_with_crypto(
        meta_for(
            target,
            crypto
                .as_ref()
                .map_or(&cytrace_types::CbomStatus::NotRequested, |c| &c.status),
        ),
        components,
        findings,
        crypto,
    );
    let html = cytrace_report::render(&result)?;
    let path = out.unwrap_or_else(|| PathBuf::from(format!("{}.report.html", sanitize(target))));
    write_file(&path, html)?;
    let risk = result.summary.overall_risk;
    println!(
        "{}",
        cat.t(
            "cli.done",
            &[
                ("count", &result.findings.len().to_string()),
                ("risk", cat.t(risk.i18n_key(), &[]).as_str()),
            ],
        )
    );
    println!(
        "{}",
        cat.t(
            "cli.report_written",
            &[("path", &path.display().to_string())]
        )
    );
    // 兩個閘門各自判定後再合併——不可提前 return，否則 fail-on 的 2 會遮蔽量子的 1
    let failon_triggered = fail_on.is_some_and(|threshold| {
        let th = Severity::from_grype_str(threshold);
        let hit = failon::triggered(&result.findings, th);
        if hit {
            eprintln!(
                "{}",
                cat.t("cli.fail_on_triggered", &[("threshold", threshold)])
            );
        }
        hit
    });

    let quantum = opts.fail_on_quantum.then(|| {
        let gate = failon::quantum_gate(result.crypto.as_ref());
        match gate {
            failon::QuantumGate::Pass => {}
            failon::QuantumGate::Vulnerable => {
                eprintln!("{}", cat.t("cli.quantum_gate.vulnerable", &[]))
            }
            failon::QuantumGate::NoResult => {
                eprintln!("{}", cat.t("cli.quantum_gate.no_result", &[]))
            }
        }
        gate
    });

    Ok(combine_gates(failon_triggered, quantum))
}

/// CBOM 相關旗標（ADR-013）。
#[derive(Debug, Clone, Copy, Default)]
struct CbomOpts {
    enabled: bool,
    fail_on_quantum: bool,
}

/// 把 CBOM 錯誤依語系渲染：純鍵查 catalog，不可翻譯的細節附在括號內。
///
/// 直接用 `e.to_string()` 會印出鍵本身（`cbom.err.empty_output`），
/// 使用者看不懂、且 `--lang en-US` 也不會變英文。
///
/// 非 CBOM 變體（theia 無法執行、暫存目錄建立失敗）與 run／batch 的 `collect_cbom` 一致，
/// 以通用鍵 `cbom.err.engine` 承接。T912 前這裡印 `Display`，`scan --cbom --lang en-US`
/// 實測印出「CBOM inventory failed: 引擎子程序錯誤：cbomkit-theia: …」。
fn render_cbom_error(e: &CytraceError, cat: &Catalog) -> String {
    match e {
        CytraceError::Cbom { key, detail } => render_cbom_key(key, detail.as_deref(), cat),
        other => cat.render_cbom("cbom.err.engine", other.untranslatable_detail().as_deref()),
    }
}

/// 把 CBOM 錯誤鍵渲染為使用者可讀訊息。
///
/// **細節必須以變數插值**，不可只附在括號後：locale 字串帶 `{{target}}` / `{{secs}}`，
/// 以 `t(key, &[])` 渲染會把佔位符原樣印出（第六輪複審實測：
/// 「非 tar / gzip 封存檔，拒絕當成映像：{{target}}（/path/…）」——路徑還重複一次）。
/// 轉呼 [`Catalog::render_cbom`]——渲染邏輯住在 i18n crate，與 server 共用同一份。
fn render_cbom_key(key: &str, detail: Option<&str>, cat: &Catalog) -> String {
    cat.render_cbom(key, detail)
}

/// 把 CBOM 狀態告知使用者——降級與失敗**必須可見**，不得無聲略過（ADR-013 決策 4/10）。
fn report_cbom_status(inv: &cytrace_types::CryptoInventory, cat: &Catalog) {
    use cytrace_types::CbomStatus;
    match &inv.status {
        CbomStatus::Completed => {
            println!(
                "{}",
                cat.t("cli.cbom.done", &[("count", &inv.assets.len().to_string())])
            );
            // 兩種成因的處置不同，訊息也必須分開：把引擎門檻說成「權限不足」，
            // 操作員會去 chmod 或改用 root 重跑，而數字永遠不變。
            if inv.unscanned_unreadable > 0 {
                eprintln!(
                    "{}",
                    cat.t(
                        "cli.cbom.unscanned_unreadable",
                        &[("count", &inv.unscanned_unreadable.to_string())]
                    )
                );
            }
            if inv.unscanned_undetermined > 0 {
                eprintln!(
                    "{}",
                    cat.t(
                        "cli.cbom.unscanned_undetermined",
                        &[("count", &inv.unscanned_undetermined.to_string())]
                    )
                );
            }
            if inv.unscanned_oversize > 0 {
                eprintln!(
                    "{}",
                    cat.t(
                        "cli.cbom.unscanned_oversize",
                        &[("count", &inv.unscanned_oversize.to_string())]
                    )
                );
            }
        }
        CbomStatus::EngineAbsent => eprintln!("{}", cat.t("cli.cbom.engine_absent", &[])),
        CbomStatus::Failed {
            reason_key,
            reason_detail,
        } => {
            // reason_key 是純 i18n 鍵，依語系渲染；細節以變數插值（見 render_cbom_key）
            let reason = render_cbom_key(reason_key, reason_detail.as_deref(), cat);
            eprintln!("{}", cat.t("cli.cbom.failed", &[("reason", &reason)]))
        }
        CbomStatus::NotRequested => {}
    }
}

fn meta_for(target: &str, cbom: &cytrace_types::CbomStatus) -> Meta {
    Meta {
        target: target.to_string(),
        tool_versions: engine::tool_versions(cbom),
        // 真值取自 grype db status；失敗回 "unavailable" sentinel（見 engine::db_snapshot）
        db_snapshot: engine::db_snapshot(),
        generated_at: epoch_to_iso(epoch_secs()),
        scan_identity: Some(engine::scan_identity()),
    }
}

fn default_report_path(input: &Path) -> PathBuf {
    let stem = input.file_stem().and_then(|s| s.to_str()).unwrap_or("scan");
    PathBuf::from(format!("{stem}.report.html"))
}

fn sanitize(target: &str) -> String {
    target
        .chars()
        .map(|c| if c.is_alphanumeric() { c } else { '_' })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── CBOM 錯誤渲染（第六輪複審：佔位符原樣印給使用者）──

    #[test]
    fn cbom_error_rendering_fills_placeholders() {
        // locale 字串帶 {{target}} / {{secs}}；以 t(key, &[]) 渲染會原樣印出佔位符，
        // 實測輸出「非 tar / gzip 封存檔，拒絕當成映像：{{target}}（/path/…）」——
        // 路徑還重複出現在括號裡。
        //
        // **鍵清單由 catalog 推導，不手抄**：原本這裡列了 5 個鍵，於是第八輪新增
        // `cbom.err.drain_timeout` 時它不在清單內，這支測試對新鍵零覆蓋（第九輪複審）。
        /// 不以秒數為細節的 `cbom.err.*` 鍵數（target 類 3 + 無細節類 4）。
        /// 具名是因為 `+7` 這個裸數字看不出耦合方向：新增 secs 鍵時本測試自動放行
        /// （權威比對在 `key_lists_are_derived_from_the_catalog`），新增非 secs 鍵才轉紅。
        const NON_SECS_CBOM_KEYS: usize = 7;

        let locale: serde_json::Value =
            serde_json::from_str(include_str!("../../../locales/zh-TW.json")).expect("locale");
        let keys: Vec<String> = locale["cbom"]["err"]
            .as_object()
            .expect("cbom.err 命名空間")
            .keys()
            .map(|k| format!("cbom.err.{k}"))
            .collect();
        assert_eq!(
            keys.len(),
            cytrace_i18n::SECS_KEYS.len() + NON_SECS_CBOM_KEYS,
            "catalog 的 cbom.err.* 鍵數與預期不符（抽到 {}）——抽取失效或鍵集合已變；\n\
             鍵集合的權威比對在 cytrace-i18n 的 key_lists_are_derived_from_the_catalog",
            keys.len()
        );

        for lang in ["zh-TW", "en-US"] {
            let cat = Catalog::load(lang);
            for key in &keys {
                // leak 提到每鍵一次（原本在最內層迴圈，一次 run 洩漏 36 次）
                let static_key: &'static str = Box::leak(key.clone().into_boxed_str());
                // 依規則給該鍵一個合適的細節；兩種 detail 形態都要走過
                let detail = if cytrace_i18n::var_for_cbom_key(key) == "secs" {
                    "600"
                } else {
                    "/tmp/x.bin"
                };
                for d in [Some(detail.to_string()), None] {
                    let e = cytrace_core::CytraceError::Cbom {
                        key: static_key,
                        detail: d.clone(),
                    };
                    let out = render_cbom_error(&e, &cat);
                    assert!(!out.contains("{{"), "{lang} {key} 渲染後殘留佔位符：{out}");
                    assert!(
                        !out.trim().starts_with("cbom.err."),
                        "{lang} {key} 渲染出裸鍵：{out}"
                    );
                    if let Some(d) = &d {
                        assert!(out.contains(d.as_str()), "{lang} {key} 須含細節 {d}：{out}");
                        assert_eq!(
                            out.matches(d.as_str()).count(),
                            1,
                            "{lang} {key} 的細節不得重複出現：{out}"
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn cbom_error_rendering_is_language_aware() {
        let en = Catalog::load("en-US");
        let e = cytrace_core::CytraceError::Cbom {
            key: "cbom.err.empty_output",
            detail: None,
        };
        let out = render_cbom_error(&e, &en);
        // 只查 CJK：英文訊息本身含破折號與彎引號等非 ASCII 標點，那是正常的
        assert!(
            !out.chars().any(|c| matches!(c as u32,
                0x3000..=0x303F | 0x4E00..=0x9FFF | 0xFF00..=0xFFEF)),
            "en-US 不得出現中日韓文字（中文散文洩漏）：{out}"
        );
    }

    // ── T912：語言來源與終端錯誤渲染 ──

    #[test]
    fn resolve_lang_precedence_and_fallback() {
        assert_eq!(resolve_lang(None, None), ("zh-TW", None));
        assert_eq!(resolve_lang(None, Some("en-US")), ("en-US", None));
        assert_eq!(resolve_lang(Some("zh-TW"), Some("en-US")), ("zh-TW", None));
        assert_eq!(resolve_lang(None, Some(" ")), ("zh-TW", None));
        assert_eq!(resolve_lang(Some("en_US.UTF-8"), None), ("en-US", None));
        // 不支援：退回 zh-TW 並回傳原值；旗標不支援時不往下找環境變數
        assert_eq!(
            resolve_lang(Some("fr"), Some("en-US")),
            ("zh-TW", Some("fr".to_string()))
        );
        assert_eq!(
            resolve_lang(None, Some("de")),
            ("zh-TW", Some("de".to_string()))
        );
    }

    fn cjk(s: &str) -> bool {
        s.chars()
            .any(|c| matches!(c as u32, 0x3000..=0x303F | 0x4E00..=0x9FFF | 0xFF00..=0xFFEF))
    }

    #[test]
    fn core_errors_render_in_the_operator_language() {
        let samples = [
            CytraceError::Engine("syft: not found".into()),
            CytraceError::Parse("grype: expected value".into()),
            CytraceError::Io(std::io::Error::other("disk full")),
            CytraceError::Config("x".into()),
            CytraceError::DbMissing("/db".into()),
            CytraceError::Engine(String::new()),
        ];
        for lang in ["zh-TW", "en-US"] {
            let cat = Catalog::load(lang);
            for e in &samples {
                let out = render_core_error(e, &cat);
                let detail = e.untranslatable_detail().unwrap_or_default();
                assert!(out.contains(&detail), "{lang} {e:?}：{out}");
                assert!(!out.contains(e.i18n_key()), "{lang} 裸鍵：{out}");
                assert!(
                    !out.ends_with(": ") && !out.ends_with('：'),
                    "{lang} 空細節：{out}"
                );
                assert_eq!(lang == "zh-TW", cjk(&out), "{lang} 語言不符：{out}");
            }
        }
        // anyhow 包裝後同樣認得（main 的出口）
        let en = Catalog::load("en-US");
        let wrapped = anyhow::Error::from(CytraceError::Engine("syft: boom".into()));
        assert_eq!(
            render_error(&wrapped, &en),
            "Engine subprocess error: syft: boom"
        );
        let wrapped =
            anyhow::Error::from(Localized::new("cli.err.invalid_address").var("value", "x"));
        assert!(render_error(&wrapped, &en).starts_with("Invalid address: x"));
    }

    #[test]
    fn scan_cbom_fallback_never_prints_the_display() {
        // T912 前 `other => other.to_string()`：--lang en-US 實測印出中文前綴
        let en = Catalog::load("en-US");
        for e in [
            CytraceError::Engine("cbomkit-theia: Permission denied (os error 13)".into()),
            CytraceError::Io(std::io::Error::other("tmp")),
        ] {
            let out = render_cbom_error(&e, &en);
            assert!(out.starts_with("Engine error"), "{out}");
            assert!(!cjk(&out) && !out.contains("engine: "), "{out}");
        }
    }

    // ── 單一目標內的雙閘門彙整（複審 finding：fail_on 先行 return 會遮蔽量子 exit 1）──

    #[test]
    fn quantum_no_result_outranks_failon_within_one_target() {
        // exit 2 = 政策閘（可豁免）；exit 1 = 工具沒跑成功。
        // 兩者同時成立時必須回 1，否則 CI 會把「根本沒掃到」讀成「有脆弱資產但掃描成功」。
        assert_eq!(
            combine_gates(true, Some(failon::QuantumGate::NoResult)),
            EXIT_ERR
        );
    }

    #[test]
    fn failon_alone_is_exit_failon() {
        assert_eq!(combine_gates(true, None), EXIT_FAILON);
        assert_eq!(
            combine_gates(true, Some(failon::QuantumGate::Pass)),
            EXIT_FAILON
        );
    }

    #[test]
    fn quantum_vulnerable_alone_is_exit_failon() {
        assert_eq!(
            combine_gates(false, Some(failon::QuantumGate::Vulnerable)),
            EXIT_FAILON
        );
    }

    #[test]
    fn quantum_no_result_alone_is_exit_err() {
        assert_eq!(
            combine_gates(false, Some(failon::QuantumGate::NoResult)),
            EXIT_ERR
        );
    }

    #[test]
    fn no_gate_triggered_is_ok() {
        assert_eq!(combine_gates(false, None), EXIT_OK);
        assert_eq!(
            combine_gates(false, Some(failon::QuantumGate::Pass)),
            EXIT_OK
        );
    }

    // ── T905：batch 退出碼彙整（ADR-013 決策 9）──

    #[test]
    fn batch_exit_prefers_error_over_failon() {
        // 錯誤（含 fail-closed 的閘門未取得結果）優先於 fail-on：
        // 「沒掃到」絕不能因為別的目標只回 2 就被蓋掉
        assert_eq!(worst_exit([EXIT_OK, EXIT_FAILON, EXIT_ERR]), EXIT_ERR);
        assert_eq!(worst_exit([EXIT_ERR, EXIT_FAILON]), EXIT_ERR);
    }

    #[test]
    fn batch_exit_reports_failon_when_no_error() {
        assert_eq!(worst_exit([EXIT_OK, EXIT_FAILON, EXIT_OK]), EXIT_FAILON);
    }

    #[test]
    fn batch_exit_is_ok_when_all_ok() {
        assert_eq!(worst_exit([EXIT_OK, EXIT_OK]), EXIT_OK);
        assert_eq!(worst_exit([]), EXIT_OK);
    }

    #[test]
    fn parses_report_subcommand() {
        let cli = Cli::try_parse_from(["cytrace", "report", "scan.json"]).unwrap();
        assert!(matches!(cli.command, Command::Report { .. }));
        // 沒給就是沒給——預設值由 resolve_lang 決定，才分得出「沒給」與「給了 zh-TW」
        assert_eq!(cli.lang, None);
    }

    #[test]
    fn parses_run_with_fail_on_and_lang() {
        let cli = Cli::try_parse_from([
            "cytrace",
            "--lang",
            "en-US",
            "run",
            "dir:/srv",
            "--fail-on",
            "high",
        ])
        .unwrap();
        match cli.command {
            Command::Run {
                target, fail_on, ..
            } => {
                assert_eq!(target, "dir:/srv");
                assert_eq!(fail_on.as_deref(), Some("high"));
            }
            _ => panic!("expected run"),
        }
        assert_eq!(cli.lang.as_deref(), Some("en-US"));
    }

    #[test]
    fn default_report_path_uses_stem() {
        assert_eq!(
            default_report_path(Path::new("a/b/scan.json")),
            PathBuf::from("scan.report.html")
        );
    }

    #[test]
    fn parses_batch_multiple_targets() {
        let cli =
            Cli::try_parse_from(["cytrace", "batch", "dir:/a", "dir:/b", "--fail-on", "high"])
                .unwrap();
        match cli.command {
            Command::Batch {
                targets, fail_on, ..
            } => {
                assert_eq!(targets, vec!["dir:/a", "dir:/b"]);
                assert_eq!(fail_on.as_deref(), Some("high"));
            }
            _ => panic!("expected batch"),
        }
    }
}
