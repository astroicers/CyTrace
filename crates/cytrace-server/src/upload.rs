//! multipart 上傳串流落盤 + 壓縮包安全解壓（ADR-011 §6）。
//!
//! **絕不整包進 RAM**：逐 chunk 寫檔並累計 bytes（超 body limit 即中止）。
//! 解壓在呼叫端的 `spawn_blocking` 語境（掃描管線前置）。

use crate::archive::{self, UploadKind};
use std::path::{Path, PathBuf};

/// 清理上傳檔名（去路徑、去危險字元）——只留 basename 的安全字元。
pub fn sanitize_filename(name: &str) -> String {
    let base = Path::new(name)
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("upload");
    let cleaned: String = base
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_') {
                c
            } else {
                '_'
            }
        })
        .collect();
    let trimmed = cleaned.trim_matches('.');
    if trimmed.is_empty() {
        "upload".to_string()
    } else {
        trimmed.to_string()
    }
}

/// 落盤後的上傳，決定掃描目標。
pub struct PreparedUpload {
    /// syft 掃描目標（`dir:<extracted>` 或單檔路徑）。
    pub scan_target: String,
    /// 原始檔名（job.target 描述用）。
    pub original_name: String,
}

/// 依 magic bytes 決定：壓縮包 → 安全解壓到 `extracted/`；單檔 → 直接掃該檔。
pub fn prepare(
    saved: &Path,
    original_name: &str,
    input_dir: &Path,
    max_extract_bytes: u64,
) -> Result<PreparedUpload, archive::ArchiveError> {
    let kind =
        archive::detect_kind(saved).map_err(|e| archive::ArchiveError::Malformed(e.to_string()))?;
    match kind {
        UploadKind::PlainFile => Ok(PreparedUpload {
            scan_target: saved.display().to_string(),
            original_name: original_name.to_string(),
        }),
        UploadKind::Zip | UploadKind::Tar | UploadKind::TarGz => {
            let extracted = input_dir.join("extracted");
            std::fs::create_dir_all(&extracted)
                .map_err(|e| archive::ArchiveError::Malformed(e.to_string()))?;
            archive::extract(saved, kind, &extracted, max_extract_bytes)?;
            Ok(PreparedUpload {
                scan_target: format!("dir:{}", extracted.display()),
                original_name: original_name.to_string(),
            })
        }
    }
}

/// 上傳原檔的落點：`<input_dir>/original/<sanitized>`。
pub fn original_path(input_dir: &Path, filename: &str) -> PathBuf {
    input_dir.join("original").join(sanitize_filename(filename))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitize_strips_path_and_unsafe_chars() {
        assert_eq!(sanitize_filename("../../etc/passwd"), "passwd");
        assert_eq!(sanitize_filename("my app (1).zip"), "my_app__1_.zip");
        assert_eq!(sanitize_filename("/abs/x.tar.gz"), "x.tar.gz");
        assert_eq!(sanitize_filename("..."), "upload");
        assert_eq!(sanitize_filename(""), "upload");
    }

    #[test]
    fn plain_file_scans_directly() {
        let dir = std::env::temp_dir().join(format!("cytrace-up-{}", std::process::id()));
        std::fs::create_dir_all(dir.join("original")).unwrap();
        let f = dir.join("original/app.bin");
        std::fs::write(&f, b"plain bytes").unwrap();
        let prep = prepare(&f, "app.bin", &dir, 1024).unwrap();
        assert_eq!(prep.scan_target, f.display().to_string());
    }
}
