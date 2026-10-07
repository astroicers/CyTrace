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
            let files = archive::extract(saved, kind, &extracted, max_extract_bytes)?;
            Ok(PreparedUpload {
                scan_target: image_aware_target(
                    saved,
                    kind,
                    &extracted,
                    input_dir,
                    tar_stream_budget(max_extract_bytes, files),
                )?,
                original_name: original_name.to_string(),
            })
        }
    }
}

/// 依解開後的內容決定 Syft 的目標形態（#49）。
///
/// 映像 tar 解開後若以 `dir:` 掃描，Syft 不會打開內層的 layer tar，**靜默得到 0 個元件**（alpine 實測）：
/// - tar／tar.gz 的 docker-save（含 Docker 25 起同時寫出 OCI layout 者）→ `docker-archive:<tar>`。
///   Syft 1.45.1 的 `oci-dir` 解析不了 Docker 匯出的巢狀 index，docker-archive 才掃得到。
///   gzip 壓縮的映像 Syft 讀不了，先解壓成 `<input>/image.tar`。
///   多映像（`docker save a b`）Syft 以 `cannot process multiple docker manifests` 失敗——
///   仍交給 docker-archive，讓 job 明確失敗，不落到 `dir:` 靜默得到 0。
/// - 只有 OCI layout（例如 skopeo 匯出）→ `oci-dir:<extracted>`。
/// - 其餘 → `dir:<extracted>`。
///
/// 已知限制（ADR-011 修訂）：zip 包的映像不轉成 docker-archive——舊式落到 `dir:`（得 0 個元件），
/// Docker 25 起的匯出落到 `oci-dir:`（Syft 報錯）；映像放在子目錄裡同樣落到 `dir:`。
fn image_aware_target(
    saved: &Path,
    kind: UploadKind,
    extracted: &Path,
    input_dir: &Path,
    tar_stream_budget: u64,
) -> Result<String, archive::ArchiveError> {
    if is_docker_save(extracted) {
        match kind {
            UploadKind::Tar => return Ok(format!("docker-archive:{}", saved.display())),
            UploadKind::TarGz => {
                let image = input_dir.join("image.tar");
                gunzip_to(saved, &image, tar_stream_budget)?;
                return Ok(format!("docker-archive:{}", image.display()));
            }
            UploadKind::Zip | UploadKind::PlainFile => {}
        }
    }
    if cytrace_core::engine::is_oci_layout(extracted) {
        return Ok(format!("oci-dir:{}", extracted.display()));
    }
    Ok(format!("dir:{}", extracted.display()))
}

/// docker save 的舊式清單：根目錄 `manifest.json` 是非空陣列，且每個元素都有 `Layers` 陣列。
/// 前端專案常見的 PWA `manifest.json` 是物件，不會被誤判。
fn is_docker_save(dir: &Path) -> bool {
    let Ok(text) = std::fs::read_to_string(dir.join("manifest.json")) else {
        return false;
    };
    let Ok(serde_json::Value::Array(items)) = serde_json::from_str(&text) else {
        return false;
    };
    !items.is_empty()
        && items
            .iter()
            .all(|i| i.get("Layers").is_some_and(|l| l.is_array()))
}

/// 解壓後 tar 串流的容許量：內容上限加上檔頭餘量。
///
/// 串流比內容多出每個 entry 的 512 位元組檔頭、補齊到 512 倍數的尾端、PAX／GNU 長檔名的延伸檔頭，
/// 以及結尾零區塊與 10 KiB 記錄邊界的補齊。以每個檔案 4 KiB、外加 16 個的量涵蓋——docker save 的輸出中，
/// 目錄與連結的數量不多於檔案。只用內容上限的話，內容剛好在上限內的合法映像會在解壓這一步被拒收。
/// 內容本身已由 `archive::extract` 檢查；這裡擋的是 tar 結尾之後的填充（`extract` 讀到結尾即停，看不到）。
fn tar_stream_budget(max_content: u64, files: usize) -> u64 {
    max_content.saturating_add(4096 * (files as u64 + 16))
}

/// 把 gzip 檔解壓到 `dest`，總量受 `max` 約束（超過即拒收，不留半套檔案）。
fn gunzip_to(src: &Path, dest: &Path, max: u64) -> Result<(), archive::ArchiveError> {
    use std::io::Read;
    let malformed = |e: std::io::Error| archive::ArchiveError::Malformed(e.to_string());
    let reader = flate2::read::GzDecoder::new(std::fs::File::open(src).map_err(malformed)?);
    let mut out = std::fs::File::create(dest).map_err(malformed)?;
    let copied = std::io::copy(&mut reader.take(max + 1), &mut out).map_err(malformed)?;
    if copied > max {
        drop(out);
        let _ = std::fs::remove_file(dest);
        return Err(archive::ArchiveError::TooLarge(format!(
            "extracted_bytes>{max}"
        )));
    }
    Ok(())
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

    /// 測試用的 job input 目錄，測試結束時整個移除。
    struct TempInput(PathBuf);
    impl Drop for TempInput {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    impl std::ops::Deref for TempInput {
        type Target = Path;
        fn deref(&self) -> &Path {
            &self.0
        }
    }

    fn temp_input(tag: &str) -> TempInput {
        let d = std::env::temp_dir().join(format!("cytrace-up-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(d.join("original")).unwrap();
        TempInput(d)
    }

    fn tar_bytes(entries: &[(&str, &[u8])]) -> Vec<u8> {
        let mut buf = Vec::new();
        {
            let mut b = tar::Builder::new(&mut buf);
            for (n, data) in entries {
                let mut h = tar::Header::new_gnu();
                h.set_size(data.len() as u64);
                h.set_mode(0o644);
                h.set_cksum();
                b.append_data(&mut h, n, *data).unwrap();
            }
            b.finish().unwrap();
        }
        buf
    }

    fn gzip(data: &[u8]) -> Vec<u8> {
        use std::io::Write;
        let mut enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        enc.write_all(data).unwrap();
        enc.finish().unwrap()
    }

    /// 在 `<input>/original/<name>` 寫一個 tar（可選 gzip），回傳原檔路徑。
    fn write_tar(input: &Path, name: &str, entries: &[(&str, &[u8])], gz: bool) -> PathBuf {
        let path = input.join("original").join(name);
        let buf = tar_bytes(entries);
        std::fs::write(&path, if gz { gzip(&buf) } else { buf }).unwrap();
        path
    }

    /// 在 `<input>/original/<name>` 寫一個 zip，回傳原檔路徑。
    fn write_zip(input: &Path, name: &str, entries: &[(&str, &[u8])]) -> PathBuf {
        use std::io::Write;
        let path = input.join("original").join(name);
        let mut z = zip::ZipWriter::new(std::fs::File::create(&path).unwrap());
        for (n, data) in entries {
            z.start_file(*n, zip::write::SimpleFileOptions::default())
                .unwrap();
            z.write_all(data).unwrap();
        }
        z.finish().unwrap();
        path
    }

    /// `docker save` 的舊式清單：JSON 陣列，每個映像都有 `Layers`。
    const DOCKER_MANIFEST: &[u8] =
        br#"[{"Config":"blobs/sha256/c","RepoTags":["x:1"],"Layers":["blobs/sha256/l"]}]"#;
    const OCI_LAYOUT: &[u8] = br#"{"imageLayoutVersion":"1.0.0"}"#;

    /// Docker 25 起的 `docker save` 同時寫出 OCI layout 與舊式 manifest.json（Docker 28 實測）。
    /// Syft 1.45.1 的 oci-dir 解析不了它的巢狀 index，docker-archive 才掃得到（#49 實測）。
    #[test]
    fn docker_save_tar_is_scanned_as_docker_archive_of_the_original() {
        let input = temp_input("dsave");
        let saved = write_tar(
            &input,
            "img.tar",
            &[
                ("manifest.json", DOCKER_MANIFEST),
                ("oci-layout", OCI_LAYOUT),
                ("index.json", b"{}"),
                ("blobs/sha256/c", b"{}"),
                ("blobs/sha256/l", b"layer"),
            ],
            false,
        );
        let prep = prepare(&saved, "img.tar", &input, 1 << 20).unwrap();
        assert_eq!(
            prep.scan_target,
            format!("docker-archive:{}", saved.display())
        );
    }

    /// Syft 讀不了 gzip 壓縮的映像 tar（docker-archive 失敗、不加前綴則靜默得到 0 個元件，#49 實測）：
    /// 先解壓成 `<input>/image.tar` 再交給 docker-archive。
    #[test]
    fn gzipped_docker_save_is_decompressed_then_scanned_as_docker_archive() {
        let input = temp_input("dsavegz");
        let saved = write_tar(
            &input,
            "img.tar.gz",
            &[
                ("manifest.json", DOCKER_MANIFEST),
                ("blobs/sha256/l", b"layer"),
            ],
            true,
        );
        let prep = prepare(&saved, "img.tar.gz", &input, 1 << 20).unwrap();
        let image = input.join("image.tar");
        assert_eq!(
            prep.scan_target,
            format!("docker-archive:{}", image.display())
        );
        // 解壓後是未壓縮的 tar，內容即原映像
        let mut a = tar::Archive::new(std::fs::File::open(&image).unwrap());
        let names: Vec<String> = a
            .entries()
            .unwrap()
            .map(|e| e.unwrap().path().unwrap().display().to_string())
            .collect();
        assert!(names.contains(&"manifest.json".to_string()), "{names:?}");
    }

    #[test]
    fn oci_layout_without_docker_manifest_is_scanned_as_oci_dir() {
        let input = temp_input("oci");
        let saved = write_tar(
            &input,
            "img.tar",
            &[
                ("oci-layout", OCI_LAYOUT),
                ("index.json", b"{}"),
                ("blobs/sha256/x", b"blob"),
            ],
            false,
        );
        let prep = prepare(&saved, "img.tar", &input, 1 << 20).unwrap();
        assert_eq!(
            prep.scan_target,
            format!("oci-dir:{}", input.join("extracted").display())
        );
    }

    #[test]
    fn ordinary_source_tar_stays_dir() {
        let input = temp_input("src");
        let saved = write_tar(
            &input,
            "src.tar",
            &[("app/requirements.txt", b"requests==2.19.0\n")],
            false,
        );
        let prep = prepare(&saved, "src.tar", &input, 1 << 20).unwrap();
        assert_eq!(
            prep.scan_target,
            format!("dir:{}", input.join("extracted").display())
        );
    }

    /// 前端專案常見的 PWA `manifest.json` 是 JSON 物件，不是映像：不得誤判。
    #[test]
    fn pwa_manifest_json_object_is_not_mistaken_for_an_image() {
        let input = temp_input("pwa");
        let saved = write_tar(
            &input,
            "web.tar",
            &[
                ("manifest.json", br#"{"name":"app","icons":[]}"#),
                ("index.html", b"<html>"),
            ],
            false,
        );
        let prep = prepare(&saved, "web.tar", &input, 1 << 20).unwrap();
        assert_eq!(
            prep.scan_target,
            format!("dir:{}", input.join("extracted").display())
        );
    }

    /// manifest.json 是陣列但元素沒有 `Layers` → 不是 docker-save。
    #[test]
    fn manifest_array_without_layers_is_not_an_image() {
        let input = temp_input("noLayers");
        let saved = write_tar(
            &input,
            "x.tar",
            &[("manifest.json", br#"[{"name":"x"}]"#)],
            false,
        );
        let prep = prepare(&saved, "x.tar", &input, 1 << 20).unwrap();
        assert_eq!(
            prep.scan_target,
            format!("dir:{}", input.join("extracted").display())
        );
    }

    /// 內容剛好等於解壓上限的 gzip 映像：tar 串流多出的檔頭不得讓它在解壓成 image.tar 時被拒收。
    #[test]
    fn gzipped_image_with_content_at_the_limit_is_accepted() {
        let input = temp_input("dsavegz-limit");
        let layer = vec![7u8; 10_000];
        let entries: &[(&str, &[u8])] = &[
            ("manifest.json", DOCKER_MANIFEST),
            ("blobs/sha256/l", &layer),
        ];
        let content: u64 = entries.iter().map(|(_, d)| d.len() as u64).sum();
        let saved = write_tar(&input, "img.tar.gz", entries, true);
        let prep = prepare(&saved, "img.tar.gz", &input, content).unwrap();
        assert_eq!(
            prep.scan_target,
            format!("docker-archive:{}", input.join("image.tar").display())
        );
    }

    /// tar 結尾之後的填充 `extract` 看不到（讀到結尾即停），解壓成 image.tar 時才擋得住：
    /// 超量即拒收，且不留半套檔案。
    #[test]
    fn gzipped_image_with_trailing_padding_beyond_budget_is_rejected() {
        let input = temp_input("dsavegz-pad");
        let mut stream = tar_bytes(&[
            ("manifest.json", DOCKER_MANIFEST),
            ("blobs/sha256/l", b"layer"),
        ]);
        stream.extend(std::iter::repeat_n(0u8, 2 << 20));
        let saved = input.join("original/img.tar.gz");
        std::fs::write(&saved, gzip(&stream)).unwrap();
        let err = prepare(&saved, "img.tar.gz", &input, 1 << 20)
            .err()
            .unwrap();
        assert!(
            matches!(&err, archive::ArchiveError::TooLarge(d) if d.starts_with("extracted_bytes>")),
            "{err:?}"
        );
        assert!(
            !input.join("image.tar").exists(),
            "超量時不得留下半套 image.tar"
        );
    }

    /// `docker save a b` 的多映像清單仍判為 docker-save：Syft 會以 multiple manifests 明確失敗，
    /// 而不是落到 `dir:` 靜默得到 0（#49 實測）。
    #[test]
    fn multi_image_docker_save_is_still_docker_archive() {
        let input = temp_input("dsave-multi");
        let manifest = br#"[{"Config":"a","Layers":["l1"]},{"Config":"b","Layers":["l2"]}]"#;
        let saved = write_tar(&input, "two.tar", &[("manifest.json", manifest)], false);
        let prep = prepare(&saved, "two.tar", &input, 1 << 20).unwrap();
        assert_eq!(
            prep.scan_target,
            format!("docker-archive:{}", saved.display())
        );
    }

    #[test]
    fn empty_manifest_array_is_not_an_image() {
        let input = temp_input("emptyArr");
        let saved = write_tar(&input, "x.tar", &[("manifest.json", b"[]")], false);
        let prep = prepare(&saved, "x.tar", &input, 1 << 20).unwrap();
        assert_eq!(
            prep.scan_target,
            format!("dir:{}", input.join("extracted").display())
        );
    }

    /// 已知限制（ADR-011 修訂）：zip 包的映像不轉成 docker-archive。舊式落到 `dir:`，
    /// Docker 25 起的匯出因帶 OCI layout 落到 `oci-dir:`。改動此行為時連同 ADR 一起改。
    #[test]
    fn zipped_image_is_not_turned_into_docker_archive() {
        let old = temp_input("zip-old");
        let saved = write_zip(&old, "img.zip", &[("manifest.json", DOCKER_MANIFEST)]);
        let prep = prepare(&saved, "img.zip", &old, 1 << 20).unwrap();
        assert_eq!(
            prep.scan_target,
            format!("dir:{}", old.join("extracted").display())
        );

        let new = temp_input("zip-new");
        let saved = write_zip(
            &new,
            "img.zip",
            &[
                ("manifest.json", DOCKER_MANIFEST),
                ("oci-layout", OCI_LAYOUT),
                ("index.json", b"{}"),
                ("blobs/sha256/l", b"layer"),
            ],
        );
        let prep = prepare(&saved, "img.zip", &new, 1 << 20).unwrap();
        assert_eq!(
            prep.scan_target,
            format!("oci-dir:{}", new.join("extracted").display())
        );
    }

    #[test]
    fn plain_file_scans_directly() {
        let dir = temp_input("plain");
        let f = dir.join("original/app.bin");
        std::fs::write(&f, b"plain bytes").unwrap();
        let prep = prepare(&f, "app.bin", &dir, 1024).unwrap();
        assert_eq!(prep.scan_target, f.display().to_string());
    }
}
