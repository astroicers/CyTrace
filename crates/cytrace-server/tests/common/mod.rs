//! i18n 機械閘共用：生產碼的掃描範圍。
//!
//! 範圍由 `cargo metadata` 推導——每個 workspace 成員的 lib／bin target 所在目錄（含子目錄）。
//! 原本寫死 `crates/*/src`，把某個 crate 的 lib 路徑改到 src 之外、或新 crate 放在 crates/
//! 之外，就會被靜默略過（T912 複審 gates#10 實測：types 改放 lib-src/ 後加入中文常數，棘輪仍綠）。
//!
//! **刻意不在範圍內**：`build.rs` 與它 `include!` 的檔案（如 cytrace-core 的
//! `theia_version_rule.rs`）——只在建置期執行，訊息給開發者看，不會到操作者手上。

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

/// 一個生產碼檔案：（workspace 相對路徑，絕對路徑）。
pub struct Source {
    pub rel: String,
    pub path: PathBuf,
}

/// 生產碼來源。`packages` 是有被掃到 .rs 的成員名（反空轉用）。
pub struct Sources {
    pub files: Vec<Source>,
    pub packages: BTreeSet<String>,
    pub members: BTreeSet<String>,
}

const PRODUCTION_KINDS: &[&str] = &[
    "lib",
    "rlib",
    "dylib",
    "cdylib",
    "staticlib",
    "proc-macro",
    "bin",
];

pub fn production_sources() -> Sources {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    let out = std::process::Command::new(env!("CARGO"))
        .args([
            "metadata",
            "--no-deps",
            "--format-version",
            "1",
            "--offline",
        ])
        .current_dir(manifest)
        .output()
        .expect("執行 cargo metadata");
    assert!(
        out.status.success(),
        "cargo metadata 失敗：{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let meta: serde_json::Value = serde_json::from_slice(&out.stdout).expect("cargo metadata JSON");
    let root = PathBuf::from(meta["workspace_root"].as_str().expect("workspace_root"));

    let members: BTreeSet<String> = meta["workspace_members"]
        .as_array()
        .expect("workspace_members")
        .iter()
        .filter_map(|m| m.as_str().map(str::to_string))
        .collect();

    let mut seen = BTreeSet::new();
    let mut files = Vec::new();
    let mut packages = BTreeSet::new();
    let mut member_names = BTreeSet::new();
    for p in meta["packages"].as_array().expect("packages") {
        let id = p["id"].as_str().unwrap_or_default();
        if !members.contains(id) {
            continue;
        }
        let name = p["name"].as_str().expect("package name").to_string();
        member_names.insert(name.clone());
        for t in p["targets"].as_array().expect("targets") {
            let is_production = t["kind"]
                .as_array()
                .expect("target kind")
                .iter()
                .any(|k| PRODUCTION_KINDS.contains(&k.as_str().unwrap_or_default()));
            if !is_production {
                continue;
            }
            let src = PathBuf::from(t["src_path"].as_str().expect("src_path"));
            let dir = src.parent().expect("target 目錄");
            let mut found = Vec::new();
            walk(dir, &mut found);
            for f in found {
                if seen.insert(f.clone()) {
                    let rel = f
                        .strip_prefix(&root)
                        .unwrap_or(&f)
                        .to_string_lossy()
                        .replace('\\', "/");
                    packages.insert(name.clone());
                    files.push(Source { rel, path: f });
                }
            }
        }
    }
    files.sort_by(|a, b| a.rel.cmp(&b.rel));
    Sources {
        files,
        packages,
        members: member_names,
    }
}

fn walk(dir: &Path, files: &mut Vec<PathBuf>) {
    for e in std::fs::read_dir(dir).expect("讀 target 目錄") {
        let p = e.expect("目錄項").path();
        if p.is_dir() {
            walk(&p, files);
        } else if p.extension().and_then(|x| x.to_str()) == Some("rs") {
            files.push(p);
        }
    }
}

/// 反空轉：每個 workspace 成員都要有檔案被掃到，總數不得低於 `min_files`。
pub fn assert_scope_not_vacuous(s: &Sources, min_files: usize) {
    let missing: Vec<_> = s.members.difference(&s.packages).collect();
    assert!(
        missing.is_empty(),
        "以下 workspace 成員沒有任何生產碼被掃到——掃描範圍可能已失效：{missing:?}"
    );
    assert!(
        s.members.len() >= 6,
        "只看到 {} 個 workspace 成員——cargo metadata 解析可能已失效",
        s.members.len()
    );
    assert!(
        s.files.len() >= min_files,
        "只找到 {} 個 .rs——掃描可能已失效",
        s.files.len()
    );
}

/// `#[cfg(test)]`（兩支閘都跳過或都計入時共用同一個判定）。
#[allow(dead_code)]
pub fn is_cfg_test(attrs: &[syn::Attribute]) -> bool {
    attrs.iter().any(|a| {
        a.path().is_ident("cfg")
            && a.meta
                .require_list()
                .is_ok_and(|l| l.tokens.to_string().trim() == "test")
    })
}
