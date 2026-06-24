//! CyTrace CLI（SDS §2）：`cytrace run|scan|report`。
//!
//! 退出碼語意（ADR-006 / SDS §5）：`0` 正常 / `2` `--fail-on` 觸發 / 其他非 0 為錯誤。

mod engine;
mod i18n;

use clap::{Parser, Subcommand};
use cytrace_core::{assemble, failon, parse};
use cytrace_types::{DbSnapshot, Meta, Severity, ToolVersions};
use i18n::Catalog;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::{SystemTime, UNIX_EPOCH};

const EXIT_OK: u8 = 0;
const EXIT_FAILON: u8 = 2;
const EXIT_ERR: u8 = 1;

/// CyTrace — 地端依賴風險報表產生器。
#[derive(Parser, Debug)]
#[command(name = "cytrace", version, about)]
struct Cli {
    /// 介面語言（zh-TW | en-US）。
    #[arg(long, global = true, default_value = "zh-TW")]
    lang: String,
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
    },
    /// 只產 sbom.cdx.json 與 grype.json。
    Scan {
        target: String,
        /// 輸出目錄（預設目前目錄）。
        #[arg(long, short)]
        out_dir: Option<PathBuf>,
    },
    /// 由既有 ScanResult JSON 離線重現報表（稽核複核；ADR-009）。
    Report {
        /// ScanResult JSON 路徑。
        input: PathBuf,
        /// 報表輸出路徑（預設 ./<input>.report.html）。
        #[arg(long, short)]
        out: Option<PathBuf>,
    },
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let cat = Catalog::load(&cli.lang);
    match run(&cli, &cat) {
        Ok(code) => ExitCode::from(code),
        Err(e) => {
            eprintln!("錯誤 / error: {e}");
            ExitCode::from(EXIT_ERR)
        }
    }
}

fn run(cli: &Cli, cat: &Catalog) -> anyhow::Result<u8> {
    match &cli.command {
        Command::Report { input, out } => {
            let json = std::fs::read_to_string(input)?;
            let result: cytrace_types::ScanResult = serde_json::from_str(&json)?;
            let html = cytrace_report::render(&result)?;
            let path = out.clone().unwrap_or_else(|| default_report_path(input));
            std::fs::write(&path, html)?;
            println!(
                "{}",
                cat.t(
                    "cli.report_written",
                    &[("path", &path.display().to_string())]
                )
            );
            Ok(EXIT_OK)
        }
        Command::Scan { target, out_dir } => {
            let dir = out_dir.clone().unwrap_or_else(|| PathBuf::from("."));
            println!("{}", cat.t("cli.scanning", &[("target", target)]));
            let sbom = engine::sbom(target)?;
            let grype = engine::vuln(&sbom)?;
            std::fs::write(dir.join("sbom.cdx.json"), &sbom)?;
            std::fs::write(dir.join("grype.json"), &grype)?;
            Ok(EXIT_OK)
        }
        Command::Run {
            target,
            fail_on,
            out,
        } => run_one(target, fail_on.as_deref(), out.clone(), cat),
        Command::Batch {
            targets,
            fail_on,
            out_dir,
        } => {
            let dir = out_dir.clone().unwrap_or_else(|| PathBuf::from("."));
            let mut worst = EXIT_OK;
            for target in targets {
                let out = Some(dir.join(format!("{}.report.html", sanitize(target))));
                if run_one(target, fail_on.as_deref(), out, cat)? == EXIT_FAILON {
                    worst = EXIT_FAILON;
                }
            }
            Ok(worst)
        }
    }
}

/// 單一目標：產 SBOM → 比對 → 解析 → 組裝 → 出報表；回傳退出碼（0 或 2）。
fn run_one(
    target: &str,
    fail_on: Option<&str>,
    out: Option<PathBuf>,
    cat: &Catalog,
) -> anyhow::Result<u8> {
    println!("{}", cat.t("cli.scanning", &[("target", target)]));
    let sbom = engine::sbom(target)?;
    let grype = engine::vuln(&sbom)?;
    let components = parse::parse_cyclonedx(&sbom)?;
    let findings = parse::parse_grype(&grype)?;
    let result = assemble(meta_for(target), components, findings);
    let html = cytrace_report::render(&result)?;
    let path = out.unwrap_or_else(|| PathBuf::from(format!("{}.report.html", sanitize(target))));
    std::fs::write(&path, html)?;
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
    if let Some(threshold) = fail_on {
        let th = Severity::from_grype_str(threshold);
        if failon::triggered(&result.findings, th) {
            eprintln!(
                "{}",
                cat.t("cli.fail_on_triggered", &[("threshold", threshold)])
            );
            return Ok(EXIT_FAILON);
        }
    }
    Ok(EXIT_OK)
}

fn meta_for(target: &str) -> Meta {
    Meta {
        target: target.to_string(),
        tool_versions: ToolVersions {
            syft: "pinned".into(),
            grype: "pinned".into(),
        },
        db_snapshot: DbSnapshot {
            version: "snapshot".into(),
            built: "unknown".into(),
        },
        generated_at: epoch_to_iso(epoch_secs()),
    }
}

fn epoch_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Unix epoch 秒 → ISO-8601 UTC 字串（純函式、零依賴；civil-from-days 演算法）。
fn epoch_to_iso(secs: u64) -> String {
    let days = (secs / 86_400) as i64;
    let rem = secs % 86_400;
    let (h, mi, s) = (rem / 3600, (rem % 3600) / 60, rem % 60);
    // Howard Hinnant 的 civil_from_days（自 1970-01-01 起的天數）
    let z = days + 719_468;
    let era = (if z >= 0 { z } else { z - 146_096 }) / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!("{y:04}-{m:02}-{d:02}T{h:02}:{mi:02}:{s:02}Z")
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

    #[test]
    fn parses_report_subcommand() {
        let cli = Cli::try_parse_from(["cytrace", "report", "scan.json"]).unwrap();
        assert!(matches!(cli.command, Command::Report { .. }));
        assert_eq!(cli.lang, "zh-TW");
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
        assert_eq!(cli.lang, "en-US");
    }

    #[test]
    fn default_report_path_uses_stem() {
        assert_eq!(
            default_report_path(Path::new("a/b/scan.json")),
            PathBuf::from("scan.report.html")
        );
    }

    #[test]
    fn epoch_to_iso_formats_utc() {
        assert_eq!(epoch_to_iso(0), "1970-01-01T00:00:00Z");
        assert_eq!(epoch_to_iso(1_609_459_200), "2021-01-01T00:00:00Z");
        assert_eq!(epoch_to_iso(1_782_295_451), "2026-06-24T10:04:11Z");
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
