// `scripts/versions.env` 的 THEIA_VERSION 取值規則——build.rs 與 tests/theia_version.rs 以 `include!`
// 共用這一份。shell（scripts/check-theia-version.sh）與 PowerShell（scripts/package.ps1）實作同一條
// 規則；shell 端由 tests/theia_version.rs 以同一組樣本機械對帳，PowerShell 端為對照實作。
//
// 規則：註解行以外，**只准有一行**提到 `THEIA_VERSION` 這個名字，且那一行必須逐字是
// `THEIA_VERSION=<數字(.數字)+>`（不縮排、不 export、等號兩側無空白、無引號或行內註解）。
// 只數「`THEIA_VERSION=` 開頭的行」不夠：`export THEIA_VERSION=…`、`THEIA_VERSION+=…` 這類再賦值
// 不在計數內，shell 載入後卻會改值，NOTICE（shell 讀）與報表（本規則讀）因此靜默分歧
// （T909 第三輪複審 build#1／claims#5）。行尾的 `\r` 由 `lines()` 去除（Windows checkout 為 CRLF）。
//
// 刻意不收預發布版號（`1.2.0-rc1`）：穩定優先，只釘正式版。真要釘預發布版時三處須一起放寬，
// tests/theia_version.rs 的樣本表會先紅。

/// 依上述規則取出版本；不符時回傳說明。
pub fn theia_version_from(text: &str) -> Result<String, String> {
    const KEY: &str = "THEIA_VERSION";
    let mentions_key = |line: &str| {
        let b = line.as_bytes();
        line.match_indices(KEY).any(|(i, _)| {
            let word = |c: u8| c.is_ascii_alphanumeric() || c == b'_';
            let before = i == 0 || !word(b[i - 1]);
            let after = b.get(i + KEY.len()).is_none_or(|&c| !word(c));
            before && after
        })
    };
    let hits: Vec<&str> = text
        .lines()
        .filter(|l| !l.trim_start().starts_with('#'))
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
