//! i18n 棘輪：server 非測試程式碼的中文字面值只減不增（NFR-06 / T909 / T912）。
//!
//! T909 把流進 **API 回應**的中文散文全數改走 i18n 鍵（經 53 個代理分類 + 反證確認範圍）。
//! 剩下的都印在**操作員終端**（serve 啟動錯誤、job 落盤警告），屬 T912，列於 [`T912_BACKLOG`]。
//!
//! 本測試是雙向的：
//! - 出現清單外的新中文字面值 → 紅（T909 修掉的不得回來；新增的必須走 i18n 鍵或進清單並說明）
//! - 清單內的項目已不存在 → 紅（T912 修掉一個就得從清單移除——否則清單變陳舊，
//!   日後有人照同樣字串加回來也不會被抓）
//!
//! 鍵為（檔案, 字面值片段），不用行號——行號一改就漂。

use std::path::Path;

/// T912 待辦：已知印在操作員終端、尚未 i18n 的字面值片段。**只能刪，不該加**。
const T912_BACKLOG: &[(&str, &str)] = &[
    ("config.rs", "CYTRACE_BIND 不是合法位址"),
    ("config.rs", "缺少 CYTRACE_ADMIN_PASSWORD_HASH"),
    ("config.rs", "CYTRACE_ADMIN_PASSWORD_HASH 不是合法 PHC 字串"),
    ("config.rs", "CYTRACE_SESSION_TTL_HOURS 不是整數"),
    ("config.rs", "TLS 憑證與金鑰必須成對設定"),
    ("config.rs", "{key} 不是整數"),
    ("config.rs", "CYTRACE_MAX_EXTRACT_MB 不是整數"),
    ("jobs/registry.rs", "無法建立資料目錄"),
    ("jobs/registry.rs", "損毀的 job 記錄"),
    ("jobs/registry.rs", "job.json 落盤失敗"),
    ("targets.rs", "格式應為 name=/abs/path："),
    ("targets.rs", "格式應為 name=/abs/path（絕對路徑）"),
    ("tls.rs", "TLS 憑證載入失敗"),
];

fn is_cjk(c: char) -> bool {
    matches!(c as u32, 0x4E00..=0x9FFF)
}

/// 抽出一行裡所有含 CJK 的雙引號字面值。
fn cjk_literals(line: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut rest = line;
    while let Some(start) = rest.find('"') {
        let after = &rest[start + 1..];
        let Some(end) = after.find('"') else { break };
        let lit = &after[..end];
        if lit.chars().any(is_cjk) {
            out.push(lit.to_string());
        }
        rest = &after[end + 1..];
    }
    out
}

fn walk(dir: &Path, files: &mut Vec<std::path::PathBuf>) {
    for e in std::fs::read_dir(dir).expect("讀 src") {
        let p = e.unwrap().path();
        if p.is_dir() {
            walk(&p, files);
        } else if p.extension().and_then(|x| x.to_str()) == Some("rs") {
            files.push(p);
        }
    }
}

#[test]
fn server_cjk_literals_only_shrink() {
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut files = Vec::new();
    walk(&src, &mut files);
    assert!(
        files.len() >= 15,
        "只找到 {} 個 .rs——掃描可能已失效",
        files.len()
    );

    let mut found: Vec<(String, String)> = Vec::new();
    for f in &files {
        let rel = f
            .strip_prefix(&src)
            .unwrap()
            .to_string_lossy()
            .replace('\\', "/");
        let text = std::fs::read_to_string(f).unwrap();
        for line in text.lines() {
            // 測試模組以後不計（測試斷言訊息非使用者可見）
            if line.trim_start().starts_with("#[cfg(test)]") {
                break;
            }
            if line.trim_start().starts_with("//") {
                continue;
            }
            for lit in cjk_literals(line) {
                found.push((rel.clone(), lit));
            }
        }
    }

    // 方向 1：清單外的新中文字面值
    let unexpected: Vec<_> = found
        .iter()
        .filter(|(file, lit)| {
            !T912_BACKLOG
                .iter()
                .any(|(bf, frag)| file == bf && lit.contains(frag))
        })
        .collect();
    assert!(
        unexpected.is_empty(),
        "server 出現清單外的中文字面值（使用者可見字串須走 i18n 鍵；若確屬操作員終端，\
         加進 T912_BACKLOG 並在 commit 說明）：\n{}",
        unexpected
            .iter()
            .map(|(f, l)| format!("  {f}: \"{l}\""))
            .collect::<Vec<_>>()
            .join("\n")
    );

    // 方向 2：清單內已消失的項目（T912 修掉後須從清單移除）
    let stale: Vec<_> = T912_BACKLOG
        .iter()
        .filter(|(bf, frag)| !found.iter().any(|(f, l)| f == bf && l.contains(frag)))
        .collect();
    assert!(
        stale.is_empty(),
        "T912_BACKLOG 有項目已不存在於程式碼——請從清單移除（清單陳舊會讓同樣字串加回來時不被抓）：\n{:?}",
        stale
    );

    // 反空轉：清單非空時必須真的看到中文字面值，否則抽取邏輯可能失效
    assert!(
        !found.is_empty() || T912_BACKLOG.is_empty(),
        "一個中文字面值都沒抽到，但 T912_BACKLOG 非空——抽取可能失效"
    );
}
