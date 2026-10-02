// `scripts/versions.env` 的 THEIA_VERSION 取值規則——build.rs 與 tests/theia_version.rs 以 `include!`
// 共用這一份。shell（scripts/check-theia-version.sh）與 PowerShell（scripts/package.ps1）實作同一條
// 規則；shell 端由 tests/theia_version.rs 以同一組位元組樣本機械對帳，PowerShell 端是對照實作，
// 只在 windows-package CI job 以真實 versions.env 執行過、沒有對樣本表對帳。
//
// 規則：
// 1. 檔案必須是 UTF-8，且不含 NUL 位元組。
// 2. 以 `\n` 切行，每行去掉**一個**行尾 `\r`（Windows checkout 的 CRLF）——與 shell 的
//    `sed 's/\r$//'` 同義；`lines()` 不行：它對沒有換行的最後一行不去 `\r`。
// 3. 註解行（行首 ASCII 空白後接 `#`）不算。
// 4. 其餘行中**只准有一行**以 ASCII 詞邊界提到 `THEIA_VERSION`，且那一行必須逐字是
//    `THEIA_VERSION=<數字(.數字)+>`（不縮排、不 export、等號兩側無空白、無引號或行內註解）。
//
// 為什麼不只數「`THEIA_VERSION=` 開頭的行」：`export THEIA_VERSION=…`、`THEIA_VERSION+=…` 這類
// 再賦值不在計數內，shell 載入後卻會改值，NOTICE 與報表因此靜默分歧（T909 第三輪複審 build#1）。
// 為什麼只認 ASCII：shell 端以 `LC_ALL=C` 執行，[[:space:]] 與詞字元都只含 ASCII——否則判定會隨
// 呼叫者的 locale 改變（第四輪複審 build#1）。
//
// 刻意不收預發布版號（`1.2.0-rc1`）：穩定優先，只釘正式版。真要釘預發布版時三處須一起放寬，
// tests/theia_version.rs 的樣本表會先紅。

/// 依上述規則取出版本；不符時回傳說明。
pub fn theia_version_from_bytes(bytes: &[u8]) -> Result<String, String> {
    let text = std::str::from_utf8(bytes).map_err(|e| format!("不是 UTF-8：{e}"))?;
    if bytes.contains(&0) {
        // shell 端的變數裝不下 NUL（指令替換會默默丟掉），兩端讀到的字會不同
        return Err("含 NUL 位元組".into());
    }
    const KEY: &str = "THEIA_VERSION";
    let word = |c: u8| c.is_ascii_alphanumeric() || c == b'_';
    let mentions_key = |line: &str| {
        let b = line.as_bytes();
        line.match_indices(KEY).any(|(i, _)| {
            (i == 0 || !word(b[i - 1])) && b.get(i + KEY.len()).is_none_or(|&c| !word(c))
        })
    };
    let is_comment = |line: &str| {
        line.trim_start_matches([' ', '\t', '\x0b', '\x0c', '\r'])
            .starts_with('#')
    };
    let hits: Vec<&str> = text
        .split('\n')
        .map(|l| l.strip_suffix('\r').unwrap_or(l))
        .filter(|l| !is_comment(l))
        .filter(|l| mentions_key(l))
        .collect();
    let [line] = hits.as_slice() else {
        return Err(format!(
            "註解以外應恰有一行提到 {KEY}，實際 {} 行：{hits:?}",
            hits.len()
        ));
    };
    let Some(v) = line.strip_prefix("THEIA_VERSION=") else {
        return Err(format!(
            "{KEY} 那一行必須逐字是 `THEIA_VERSION=<版本>`（不縮排、不 export、等號旁無空白）：{line:?}"
        ));
    };
    let well_formed = v.split('.').count() >= 2
        && v
            .split('.')
            .all(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()));
    if !well_formed {
        return Err(format!(
            "THEIA_VERSION={v:?} 不是 數字(.數字)+（引號、行內註解、空白會讓 shell 讀出不同值）"
        ));
    }
    Ok(v.to_string())
}
