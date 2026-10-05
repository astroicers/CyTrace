//! 掛載目錄白名單與路徑解析（ADR-011 §6；path traversal / symlink 逃逸防護）。
//!
//! 驗證順序：**先語彙檢查**（拒 `..`/絕對路徑/Prefix，不給 FS 任何機會）→
//! `canonicalize` → 前綴驗證（擋 symlink 逃逸）。失敗一律對外 403（不洩漏檔案系統結構）。

use cytrace_i18n::Localized;
use std::path::{Component, Path, PathBuf};

/// 解析失敗原因（對外一律 403；原因碼與請求的 root、path 附在回應的 `detail`。
/// 伺服器端不另記稽核 log——ADR-011 修訂節，T916）。
#[derive(Debug, PartialEq, Eq)]
pub enum TargetError {
    UnknownRoot,
    LexicalViolation,
    Escape,
    NotFound,
}

impl TargetError {
    pub fn as_str(&self) -> &'static str {
        match self {
            TargetError::UnknownRoot => "unknown_root",
            TargetError::LexicalViolation => "lexical_violation",
            TargetError::Escape => "escape",
            TargetError::NotFound => "not_found",
        }
    }
}

/// 解析 `CYTRACE_SCAN_ROOTS`（`name=/abs/path` 逗號清單）。錯誤為啟動訊息（`server.startup.*`）。
pub fn parse_roots(raw: &str) -> Result<Vec<(String, PathBuf)>, Localized> {
    let mut roots = Vec::new();
    for item in raw.split(',').filter(|s| !s.trim().is_empty()) {
        let (name, path) = item
            .split_once('=')
            .ok_or_else(|| Localized::new("server.startup.scan_roots_format").var("item", item))?;
        let (name, path) = (name.trim(), Path::new(path.trim()));
        if name.is_empty() {
            return Err(Localized::new("server.startup.scan_roots_format").var("item", item));
        }
        if !path.is_absolute() {
            return Err(Localized::new("server.startup.scan_roots_not_absolute").var("item", item));
        }
        roots.push((name.to_string(), path.to_path_buf()));
    }
    Ok(roots)
}

/// 解析掃描目標：`root` 白名單名 + `rel` 相對路徑（空字串 = root 本身）。
pub fn resolve(
    roots: &[(String, PathBuf)],
    root_name: &str,
    rel: &str,
) -> Result<PathBuf, TargetError> {
    let root = roots
        .iter()
        .find(|(n, _)| n == root_name)
        .map(|(_, p)| p)
        .ok_or(TargetError::UnknownRoot)?;

    // 1) 語彙檢查（canonicalize 之前，不觸 FS）
    let rel_path = Path::new(rel);
    for comp in rel_path.components() {
        match comp {
            Component::Normal(_) | Component::CurDir => {}
            _ => return Err(TargetError::LexicalViolation), // ParentDir / RootDir / Prefix
        }
    }

    // 2) canonicalize root 與 joined（symlink 全展開）
    let canon_root = root.canonicalize().map_err(|_| TargetError::UnknownRoot)?;
    let joined = canon_root.join(rel_path);
    let canon = joined.canonicalize().map_err(|_| TargetError::NotFound)?;

    // 3) 前綴驗證：展開後必須仍在 root 內（擋 symlink 逃逸）
    if !canon.starts_with(&canon_root) {
        return Err(TargetError::Escape);
    }
    Ok(canon)
}

#[cfg(test)]
mod tests {
    use super::*;

    static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

    fn setup() -> (PathBuf, Vec<(String, PathBuf)>) {
        let base = std::env::temp_dir().join(format!(
            "cytrace-targets-{}-{}",
            std::process::id(),
            SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&base);
        let inside = base.join("root/sub");
        std::fs::create_dir_all(&inside).unwrap();
        std::fs::write(inside.join("app.bin"), b"x").unwrap();
        let outside = base.join("secret");
        std::fs::create_dir_all(&outside).unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink(&outside, base.join("root/link-out")).unwrap();
        let roots = vec![("targets".to_string(), base.join("root"))];
        (base, roots)
    }

    #[test]
    fn valid_paths_resolve() {
        let (_base, roots) = setup();
        assert!(resolve(&roots, "targets", "sub").is_ok());
        assert!(resolve(&roots, "targets", "sub/app.bin").is_ok());
        assert!(resolve(&roots, "targets", "").is_ok()); // root 本身
        assert!(resolve(&roots, "targets", "./sub").is_ok());
    }

    #[test]
    fn lexical_violations_rejected_before_fs() {
        let (_base, roots) = setup();
        assert_eq!(
            resolve(&roots, "targets", "../secret").unwrap_err(),
            TargetError::LexicalViolation
        );
        assert_eq!(
            resolve(&roots, "targets", "sub/../../secret").unwrap_err(),
            TargetError::LexicalViolation
        );
        assert_eq!(
            resolve(&roots, "targets", "/etc/passwd").unwrap_err(),
            TargetError::LexicalViolation
        );
    }

    #[cfg(unix)]
    #[test]
    fn symlink_escape_blocked() {
        let (_base, roots) = setup();
        assert_eq!(
            resolve(&roots, "targets", "link-out").unwrap_err(),
            TargetError::Escape
        );
    }

    #[test]
    fn unknown_root_and_missing_path() {
        let (_base, roots) = setup();
        assert_eq!(
            resolve(&roots, "nope", "x").unwrap_err(),
            TargetError::UnknownRoot
        );
        assert_eq!(
            resolve(&roots, "targets", "no/such").unwrap_err(),
            TargetError::NotFound
        );
    }

    #[test]
    fn parse_roots_validates_format() {
        let roots = parse_roots("targets=/scan-targets, extra=/mnt/x").unwrap();
        assert_eq!(roots.len(), 2);
        assert_eq!(roots[0].0, "targets");
        assert!(parse_roots("bad-entry").is_err());
        assert!(parse_roots("name=relative/path").is_err());
        assert!(parse_roots("").unwrap().is_empty());
    }
}
