//! clap 的 `--help` 與參數用法錯誤在地化（T914）。
//!
//! clap 4 的內建字串（Usage、Options、Print help、各種解析錯誤）無法直接翻譯，且解析錯誤發生在
//! 「讀出 `--lang`」之前。做法：
//! - 呼叫端先從 argv 與 `CYTRACE_LANG` 預掃語言（[`prescan_lang`]），載入 catalog；
//! - [`localize`] 以 builder 把說明文字、區段標題、`--help`／`--version` 的說明換成 catalog 的值；
//! - 解析失敗時，[`render_usage_error`] 依 `ErrorKind` 與錯誤附帶的 context 組出我方訊息。
//!
//! 說明文字的鍵由子命令名與參數 id 推導（`cli.help.cmd.<子命令>`、`cli.help.arg.<子命令>.<參數>`），
//! 所以「每個參數都有兩語說明」可以逐一測試（見 main.rs 的
//! `every_subcommand_and_arg_has_localized_help`）。

use clap::error::{ContextKind, ErrorKind};
use clap::{Arg, ArgAction, Command};
use cytrace_i18n::Catalog;
use std::ffi::OsString;

/// 子命令名 → 鍵片段（`hash-password` → `hash_password`；鍵只用小寫與底線）。
fn seg(name: &str) -> String {
    name.replace('-', "_")
}

pub fn command_key(name: &str) -> String {
    format!("cli.help.cmd.{}", seg(name))
}

pub fn arg_key(sub: &str, id: &str) -> String {
    format!("cli.help.arg.{}.{}", seg(sub), id)
}

/// 從 argv 找 `--lang <值>` 或 `--lang=<值>`（全域旗標，可在任何位置）。`--` 之後不再找。
pub fn prescan_lang(args: &[OsString]) -> Option<String> {
    let mut it = args.iter().skip(1).map(|a| a.to_string_lossy());
    while let Some(a) = it.next() {
        if a == "--" {
            return None;
        }
        if a == "--lang" {
            return it.next().map(|v| v.into_owned());
        }
        if let Some(v) = a.strip_prefix("--lang=") {
            return Some(v.to_string());
        }
    }
    None
}

/// argv 裡出現的第一個子命令名（用法提示要指向該子命令的 `--help`）。
pub fn subcommand_in(args: &[OsString], cmd: &Command) -> Option<String> {
    let names: Vec<&str> = cmd.get_subcommands().map(|s| s.get_name()).collect();
    args.iter()
        .skip(1)
        .map(|a| a.to_string_lossy())
        .find(|a| names.contains(&a.as_ref()))
        .map(|a| a.into_owned())
}

/// 把 catalog 的說明文字注入 clap 命令。
pub fn localize(cmd: Command, cat: &Catalog) -> Command {
    let template = format!(
        "{{about-with-newline}}\n{}{{usage}}\n\n{{all-args}}{{after-help}}",
        cat.t("cli.help.usage", &[])
    );
    let options = cat.t("cli.help.heading.options", &[]);
    let arguments = cat.t("cli.help.heading.arguments", &[]);

    // 內建的 --help／--version 改由我們自己加：建置後再 mut_arg 內建旗標會錯位
    //（實測 `--help` 印出版本、`-V` 被當成 `--lang`）。help 設為 global，子命令一併沿用
    let mut cmd = cmd
        .about(cat.t("cli.help.about", &[]))
        .help_template(template.clone())
        .subcommand_help_heading(cat.t("cli.help.heading.commands", &[]))
        .disable_help_subcommand(true)
        .disable_help_flag(true)
        .disable_version_flag(true)
        .arg(
            Arg::new("help")
                .short('h')
                .long("help")
                .action(ArgAction::Help)
                .global(true)
                .help(cat.t("cli.help.arg.help", &[]))
                .help_heading(options.clone()),
        )
        .arg(
            Arg::new("version")
                .short('V')
                .long("version")
                .action(ArgAction::Version)
                .help(cat.t("cli.help.arg.version", &[]))
                .help_heading(options.clone()),
        )
        .mut_arg("lang", |a| {
            a.help(cat.t("cli.help.arg.lang", &[]))
                .help_heading(options.clone())
        });

    let subs: Vec<String> = cmd
        .get_subcommands()
        .map(|s| s.get_name().to_string())
        .collect();
    for name in subs {
        cmd = cmd.mut_subcommand(&name, |sc| {
            let ids: Vec<String> = sc.get_arguments().map(|a| a.get_id().to_string()).collect();
            let k = command_key(&name);
            let mut sc = sc.about(cat.t(&k, &[])).help_template(template.clone());
            for id in ids {
                let k = arg_key(&name, &id);
                let help = cat.t(&k, &[]);
                sc = sc.mut_arg(&id, |a| {
                    let heading = if a.is_positional() {
                        arguments.clone()
                    } else {
                        options.clone()
                    };
                    let a = a.help(help).help_heading(heading);
                    // 可用值已寫在說明裡；clap 會另外印英文的 `[possible values: …]`。
                    // 只能設在帶值的參數上（clap 的除錯斷言：旗標設了會 panic）
                    if a.get_action().takes_values() {
                        a.hide_possible_values(true)
                    } else {
                        a
                    }
                });
            }
            sc
        });
    }
    cmd
}

/// 用法錯誤 → 操作者語言的一行訊息（不含前綴）。認得的 `ErrorKind` 用我方的鍵；
/// 其餘以 `cli.usage.other` 附上 clap 的原文（英文）——那是函式庫的診斷，與第三方錯誤同一處置。
pub fn render_usage_error(e: &clap::Error, cat: &Catalog) -> String {
    let ctx = |k: ContextKind| e.get(k).map(|v| v.to_string()).unwrap_or_default();
    let arg = ctx(ContextKind::InvalidArg);
    match e.kind() {
        ErrorKind::InvalidValue if !arg.is_empty() => {
            let value = ctx(ContextKind::InvalidValue);
            let valid = ctx(ContextKind::ValidValue);
            if value.is_empty() {
                cat.t("cli.usage.value_required", &[("arg", &arg)])
            } else if valid.is_empty() {
                cat.t(
                    "cli.usage.invalid_value_plain",
                    &[("arg", &arg), ("value", &value)],
                )
            } else {
                cat.t(
                    "cli.usage.invalid_value",
                    &[("arg", &arg), ("value", &value), ("valid", &valid)],
                )
            }
        }
        ErrorKind::UnknownArgument if !arg.is_empty() => {
            cat.t("cli.usage.unknown_argument", &[("arg", &arg)])
        }
        ErrorKind::InvalidSubcommand => cat.t(
            "cli.usage.unknown_subcommand",
            &[("value", &ctx(ContextKind::InvalidSubcommand))],
        ),
        ErrorKind::MissingRequiredArgument if !arg.is_empty() => {
            cat.t("cli.usage.missing_required", &[("args", &arg)])
        }
        ErrorKind::MissingSubcommand => cat.t("cli.usage.missing_subcommand", &[]),
        ErrorKind::ArgumentConflict if !arg.is_empty() => cat.t(
            "cli.usage.conflict",
            &[("arg", &arg), ("other", &ctx(ContextKind::PriorArg))],
        ),
        _ => {
            let raw = e.to_string();
            let first = raw.lines().next().unwrap_or_default();
            let detail = first.strip_prefix("error: ").unwrap_or(first).to_string();
            cat.t("cli.usage.other", &[("detail", &detail)])
        }
    }
}
