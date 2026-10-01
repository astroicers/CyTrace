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

/// T912 待辦：已知印在操作員終端、尚未 i18n 的字面值片段與**出現次數**。**只能減，不該加**。
///
/// 計次數而非只看片段是否存在：只看存在的話，一筆清單能豁免任意多個同片段字面值——
/// 複製既有錯誤訊息（例如再貼一處「job.json 落盤失敗」送進 API）正是新散文最常見的來源
/// （T909 對抗式複審 v14：反證票 1/3、未達確認門檻；但複製一行即可繞過是實測可重現的，故仍修）。
const T912_BACKLOG: &[(&str, &str, usize)] = &[
    ("config.rs", "CYTRACE_BIND 不是合法位址", 1),
    ("config.rs", "缺少 CYTRACE_ADMIN_PASSWORD_HASH", 1),
    (
        "config.rs",
        "CYTRACE_ADMIN_PASSWORD_HASH 不是合法 PHC 字串",
        1,
    ),
    ("config.rs", "CYTRACE_SESSION_TTL_HOURS 不是整數", 1),
    ("config.rs", "TLS 憑證與金鑰必須成對設定", 1),
    ("config.rs", "{key} 不是整數", 1),
    ("config.rs", "CYTRACE_MAX_EXTRACT_MB 不是整數", 1),
    // 只含全形冒號、無漢字——初版 is_cjk 只認 U+4E00–9FFF，這條看不到
    ("config.rs", "CYTRACE_SCAN_ROOTS：", 1),
    ("jobs/registry.rs", "無法建立資料目錄", 1),
    ("jobs/registry.rs", "損毀的 job 記錄", 1),
    ("jobs/registry.rs", "job.json 落盤失敗", 2),
    ("targets.rs", "格式應為 name=/abs/path：", 1),
    ("targets.rs", "格式應為 name=/abs/path（絕對路徑）", 1),
    ("tls.rs", "TLS 憑證載入失敗", 1),
];

/// 與 tests/jobs.rs 的 `has_cjk` 同範圍：漢字 + CJK 標點 + 全形字元。
/// 初版只認漢字，只含全形標點的字面值（`"CYTRACE_SCAN_ROOTS：{e}"`）完全看不到。
fn is_cjk(c: char) -> bool {
    matches!(c as u32, 0x4E00..=0x9FFF | 0x3000..=0x303F | 0xFF00..=0xFFEF)
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

    // 每筆清單項目的實際出現次數
    let count_of = |bf: &str, frag: &str| {
        found
            .iter()
            .filter(|(f, l)| f == bf && l.contains(frag))
            .count()
    };

    // 方向 1：清單外的新中文字面值
    let unexpected: Vec<_> = found
        .iter()
        .filter(|(file, lit)| {
            !T912_BACKLOG
                .iter()
                .any(|(bf, frag, _)| file == bf && lit.contains(frag))
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

    // 方向 2：次數必須精確相符——多了是複製了既有散文，少了是 T912 修掉後沒更新清單
    let drift: Vec<_> = T912_BACKLOG
        .iter()
        .filter_map(|(bf, frag, want)| {
            let got = count_of(bf, frag);
            (got != *want).then(|| format!("  {bf} 「{frag}」：清單記 {want} 處，實際 {got} 處"))
        })
        .collect();
    assert!(
        drift.is_empty(),
        "T912_BACKLOG 與程式碼次數不符（多了＝複製了既有中文散文；少了＝修掉後請更新清單）：\n{}",
        drift.join("\n")
    );

    // 反空轉：清單非空時必須真的看到中文字面值，否則抽取邏輯可能失效
    assert!(
        !found.is_empty() || T912_BACKLOG.is_empty(),
        "一個中文字面值都沒抽到，但 T912_BACKLOG 非空——抽取可能失效"
    );
}
