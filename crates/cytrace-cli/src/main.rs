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
        } => {
            println!("{}", cat.t("cli.scanning", &[("target", target)]));
            let sbom = engine::sbom(target)?;
            let grype = engine::vuln(&sbom)?;
            let components = parse::parse_cyclonedx(&sbom)?;
            let findings = parse::parse_grype(&grype)?;
            let result = assemble(meta_for(target), components, findings);
            let html = cytrace_report::render(&result)?;
            let path = out
                .clone()
                .unwrap_or_else(|| PathBuf::from(format!("{}.report.html", sanitize(target))));
            std::fs::write(&path, html)?;
            let risk = result.summary.overall_risk;
            println!(
                "{}",
                cat.t(
                    "cli.done",
                    &[
                        ("count", &result.findings.len().to_string()),
                        ("risk", cat.t(risk.i18n_key(), &[]).as_str())
                    ]
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
    }
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
        generated_at: epoch_secs().to_string(),
    }
}

fn epoch_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
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
}
