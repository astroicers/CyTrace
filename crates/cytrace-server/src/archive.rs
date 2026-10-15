//! 壓縮包安全解壓（ADR-011 §6）。在 `spawn_blocking` 內同步執行（job 管線的前置步驟）。
//!
//! 三道防護：
//! 1. **zip-slip / 路徑穿越**：zip 用 `enclosed_name()`；tar 逐 component 檢查——
//!    出現 `..`/絕對路徑/Prefix **整包拒收**（上傳者惡意即整件失敗，不是跳過）
//! 2. **連結類 entry**：symlink/hardlink 一律跳過不解（掃描不需要，且是逃逸主要向量）
//! 3. **zip-bomb**：entry 數上限 + 總解壓量上限——**只信實際解出的 bytes**
//!    （`Read::take` 限量），不信 header 宣告的 uncompressed size

use std::fs::File;
use std::io::{BufReader, Read};
use std::path::{Component, Path, PathBuf};

/// entry 數上限（固定；超過此數的正常交付目標不存在）。
pub const MAX_ENTRIES: usize = 100_000;

/// 解壓失敗分類（i18n 鍵 `server.err.*`）。
///
/// 解壓在 upload handler 內同步執行，失敗時 job 尚未 insert——故經 **ApiError** 直接回給
/// 請求者，不經 runner / JobError（舊註解寫「→ JobError」與實況不符，T909 分類時查出）。
/// `detail` 只放鍵值形式的診斷資料（`entries=N`、`extracted_bytes>N`），說明句走 [`Self::i18n_key`]。
#[derive(Debug, PartialEq, Eq)]
pub enum ArchiveError {
    /// 路徑穿越 / 絕對路徑 / Prefix——整包拒收。
    PathViolation(String),
    /// 超過 entry 數或總解壓量上限。
    TooLarge(String),
    /// 讀取/解壓 I/O 或格式錯誤。
    Malformed(String),
    /// 認得但不支援的壓縮格式（RAR、7z、xz、bzip2、zstd；#77），內容為格式名。
    Unsupported(String),
}

impl ArchiveError {
    pub fn i18n_key(&self) -> &'static str {
        match self {
            ArchiveError::PathViolation(_) => "server.err.forbidden_path",
            ArchiveError::TooLarge(_) => "server.err.extract_too_large",
            ArchiveError::Malformed(_) | ArchiveError::Unsupported(_) => {
                "server.err.unsupported_archive"
            }
        }
    }
    pub fn kind(&self) -> &'static str {
        match self {
            ArchiveError::PathViolation(_) => "forbidden_path",
            ArchiveError::TooLarge(_) => "extract_too_large",
            ArchiveError::Malformed(_) | ArchiveError::Unsupported(_) => "unsupported_archive",
        }
    }
    pub fn detail(&self) -> &str {
        match self {
            ArchiveError::PathViolation(s)
            | ArchiveError::TooLarge(s)
            | ArchiveError::Malformed(s)
            | ArchiveError::Unsupported(s) => s,
        }
    }
}

/// 上傳格式（magic bytes 辨識，副檔名只做參考不信任）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UploadKind {
    Zip,
    TarGz,
    Tar,
    /// 非壓縮包：直接以該檔為掃描目標。
    PlainFile,
    /// 認得但不支援的壓縮格式（#77）：上傳時拒收。原本落到 PlainFile 交給 Syft，由 Syft 自行解壓後掃描——
    /// 繞過本模組的條目數與總量上限：釘選版實測 458 KB 的 tar.xz 解出 3 GiB 到 `TMPDIR`（解壓炸彈）。
    /// 內容為格式名（rar、7z、xz、bzip2、zstd）。
    Unsupported(&'static str),
}

/// 認得但不支援的壓縮格式的檔頭（#77），涵蓋 Syft 1.45.1 內建 mholt/archives v0.1.5 能自行解壓、且有固定檔頭者。
/// RAR5、7z 取自真實檔案；xz 由 xz 實際壓縮產生；zstd、lz4、lzip、minlz、snappy、s2 由 Syft 所依賴的同版本
/// 函式庫實際壓縮產生；RAR4 與 RAR5 前 6 bytes 相同。bzip2 另見 [`is_bzip2`]。沒有可靠檔頭的 brotli、zlib
/// 由 `upload::unsupported_by_name` 依副檔名拒收。
const UNSUPPORTED_MAGIC: &[(&str, &[u8])] = &[
    ("rar", b"Rar!\x1a\x07"),
    ("7z", b"7z\xbc\xaf\x27\x1c"),
    ("xz", b"\xfd7zXZ\x00"),
    ("zstd", b"\x28\xb5\x2f\xfd"),
    ("lz4", b"\x04\x22\x4d\x18"),
    ("lzip", b"LZIP"),
    ("minlz", b"\xff\x06\x00\x00MinLz"),
    ("snappy", b"\xff\x06\x00\x00sNaPpY"),
    ("s2", b"\xff\x06\x00\x00S2sTwO"),
];

/// bzip2：`BZh` + 區塊大小 `1`–`9`，其後必須是區塊標頭（π 的 BCD）或空串流的結尾標記（√π）。
/// 只比 `BZh` 會把以「BZh」開頭的文字檔誤判成壓縮檔而拒收。
fn is_bzip2(head: &[u8]) -> bool {
    head.len() >= 10
        && &head[0..3] == b"BZh"
        && (b'1'..=b'9').contains(&head[3])
        && (head[4..10] == [0x31, 0x41, 0x59, 0x26, 0x53, 0x59]
            || head[4..10] == [0x17, 0x72, 0x45, 0x38, 0x50, 0x90])
}

/// 讀檔頭辨識格式：zip=`PK\x03\x04`、gzip=`\x1f\x8b`、tar=offset 257 `ustar`。
pub fn detect_kind(path: &Path) -> std::io::Result<UploadKind> {
    let mut f = File::open(path)?;
    let mut head = [0u8; 262];
    let n = f.read(&mut head)?;
    if n >= 4 && head[0..4] == [0x50, 0x4b, 0x03, 0x04] {
        return Ok(UploadKind::Zip);
    }
    if n >= 2 && head[0..2] == [0x1f, 0x8b] {
        return Ok(UploadKind::TarGz); // gzip：以 tar.gz 處理（純 .gz 單檔極罕見，不支援）
    }
    if n >= 262 && &head[257..262] == b"ustar" {
        return Ok(UploadKind::Tar);
    }
    let head = &head[..n];
    if let Some((name, _)) = UNSUPPORTED_MAGIC.iter().find(|(_, m)| head.starts_with(m)) {
        return Ok(UploadKind::Unsupported(name));
    }
    if is_bzip2(head) {
        return Ok(UploadKind::Unsupported("bzip2"));
    }
    Ok(UploadKind::PlainFile)
}

/// 路徑語彙檢查（與 targets.rs 同準則）：只允許 Normal/CurDir component。
fn lexical_ok(p: &Path) -> bool {
    p.components()
        .all(|c| matches!(c, Component::Normal(_) | Component::CurDir))
}

/// 解壓進 `dest`（必須已存在且為空目錄）。回傳解出的 entry 數。
pub fn extract(
    archive: &Path,
    kind: UploadKind,
    dest: &Path,
    max_total_bytes: u64,
) -> Result<usize, ArchiveError> {
    match kind {
        UploadKind::Zip => extract_zip(archive, dest, max_total_bytes),
        UploadKind::Tar => {
            let f = File::open(archive).map_err(|e| ArchiveError::Malformed(e.to_string()))?;
            extract_tar(BufReader::new(f), dest, max_total_bytes)
        }
        UploadKind::TarGz => {
            let f = File::open(archive).map_err(|e| ArchiveError::Malformed(e.to_string()))?;
            extract_tar(
                flate2::bufread::GzDecoder::new(BufReader::new(f)),
                dest,
                max_total_bytes,
            )
        }
        UploadKind::PlainFile => Err(ArchiveError::Malformed("not an archive".into())),
        UploadKind::Unsupported(name) => Err(ArchiveError::Unsupported(name.into())),
    }
}

fn extract_zip(archive: &Path, dest: &Path, max_total: u64) -> Result<usize, ArchiveError> {
    let f = File::open(archive).map_err(|e| ArchiveError::Malformed(e.to_string()))?;
    let mut z = zip::ZipArchive::new(BufReader::new(f))
        .map_err(|e| ArchiveError::Malformed(e.to_string()))?;
    if z.len() > MAX_ENTRIES {
        return Err(ArchiveError::TooLarge(format!("entries={}", z.len())));
    }
    let mut written: u64 = 0;
    let mut count = 0usize;
    for i in 0..z.len() {
        let mut entry = z
            .by_index(i)
            .map_err(|e| ArchiveError::Malformed(e.to_string()))?;
        // 連結類跳過（unix 權限位判斷 symlink）
        if entry.unix_mode().map(|m| m & 0o170000 == 0o120000) == Some(true) {
            continue;
        }
        // zip-slip：enclosed_name 拒 ../ 與絕對路徑；None = 惡意 → 整包拒收
        let rel = entry
            .enclosed_name()
            .ok_or_else(|| ArchiveError::PathViolation(entry.name().to_string()))?;
        if !lexical_ok(&rel) {
            return Err(ArchiveError::PathViolation(entry.name().to_string()));
        }
        let out = dest.join(rel);
        if entry.is_dir() {
            std::fs::create_dir_all(&out).map_err(|e| ArchiveError::Malformed(e.to_string()))?;
            continue;
        }
        if let Some(parent) = out.parent() {
            std::fs::create_dir_all(parent).map_err(|e| ArchiveError::Malformed(e.to_string()))?;
        }
        written += copy_limited(&mut entry, &out, max_total - written)?;
        count += 1;
    }
    Ok(count)
}

fn extract_tar<R: Read>(reader: R, dest: &Path, max_total: u64) -> Result<usize, ArchiveError> {
    let mut ar = tar::Archive::new(reader);
    let mut written: u64 = 0;
    let mut count = 0usize;
    let entries = ar
        .entries()
        .map_err(|e| ArchiveError::Malformed(e.to_string()))?;
    for entry in entries {
        let mut entry = entry.map_err(|e| ArchiveError::Malformed(e.to_string()))?;
        if count >= MAX_ENTRIES {
            return Err(ArchiveError::TooLarge(format!("entries>{MAX_ENTRIES}")));
        }
        let etype = entry.header().entry_type();
        // 連結類一律跳過
        if etype.is_symlink() || etype.is_hard_link() {
            continue;
        }
        let rel: PathBuf = entry
            .path()
            .map_err(|e| ArchiveError::Malformed(e.to_string()))?
            .into_owned();
        // 整包拒收：../、絕對路徑、Prefix
        if !lexical_ok(&rel) {
            return Err(ArchiveError::PathViolation(rel.display().to_string()));
        }
        let out = dest.join(&rel);
        if etype.is_dir() {
            std::fs::create_dir_all(&out).map_err(|e| ArchiveError::Malformed(e.to_string()))?;
            continue;
        }
        if !etype.is_file() {
            continue; // device/fifo 等特殊類型：跳過
        }
        if let Some(parent) = out.parent() {
            std::fs::create_dir_all(parent).map_err(|e| ArchiveError::Malformed(e.to_string()))?;
        }
        written += copy_limited(&mut entry, &out, max_total - written)?;
        count += 1;
    }
    Ok(count)
}

/// 限量複製：實際寫出 bytes 計數（不信 header）；超限即中止。
fn copy_limited<R: Read>(src: &mut R, out: &Path, budget: u64) -> Result<u64, ArchiveError> {
    let mut dst = File::create(out).map_err(|e| ArchiveError::Malformed(e.to_string()))?;
    // 多取 1 byte 偵測「剛好超限」
    let mut limited = src.take(budget + 1);
    let n = std::io::copy(&mut limited, &mut dst)
        .map_err(|e| ArchiveError::Malformed(e.to_string()))?;
    if n > budget {
        let _ = std::fs::remove_file(out);
        // 鍵值形式的診斷資料（與 entries=N 等兄弟站點同慣例）；說明句走 i18n 鍵
        return Err(ArchiveError::TooLarge(format!("extracted_bytes>{budget}")));
    }
    Ok(n)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    /// `api::jobs` 以 `with_message(ae.i18n_key(), &[])` 渲染——鍵不是字面值，插值對帳
    /// 比不到，在此逐變體驗不需變數（T912 複審 newgates#3）。
    #[test]
    fn every_archive_error_message_renders_without_variables() {
        for e in [
            ArchiveError::PathViolation(String::new()),
            ArchiveError::TooLarge(String::new()),
            ArchiveError::Malformed(String::new()),
            ArchiveError::Unsupported(String::new()),
        ] {
            for lang in ["zh-TW", "en-US"] {
                let m = cytrace_i18n::Catalog::load(lang).t(e.i18n_key(), &[]);
                assert_ne!(m, e.i18n_key(), "{lang} 查不到");
                assert!(!m.contains("{{"), "{lang} {}：{m}", e.i18n_key());
            }
        }
    }

    /// #77：已知但不支援的壓縮格式要被認出來，上傳時拒收；原本一律落到 PlainFile，由 Syft 自行解壓、
    /// 沒有總量上限。檔頭取自實際檔案：RAR5、7z 取自真實壓縮檔，xz、bzip2 由 xz／bzip2 實際壓縮產生；
    /// RAR4 依 RAR 規格（與 RAR5 前 6 bytes 相同），zstd 依 RFC 8878。
    #[test]
    fn known_unsupported_archives_are_detected() {
        let cases: &[(&str, &[u8])] = &[
            ("rar", b"Rar!\x1a\x07\x01\x00rest"),
            ("rar", b"Rar!\x1a\x07\x00rest"),
            ("7z", b"7z\xbc\xaf\x27\x1c\x00\x04rest"),
            ("xz", b"\xfd7zXZ\x00\x00\x04\xe6\xd6"),
            ("bzip2", b"BZh91AY&SYrest"),
            ("bzip2", b"BZh9\x17\x72\x45\x38\x50\x90rest"),
            ("zstd", b"\x28\xb5\x2f\xfdrest"),
            // 以下取自 Syft 1.45.1 所依賴的同版本函式庫實際壓縮產生的檔案（#77 第三輪）
            ("lz4", b"\x04\x22\x4d\x18\x64\x70\xb9\xda"),
            ("lzip", b"LZIP\x01\x17\x00\x3b"),
            ("minlz", b"\xff\x06\x00\x00MinLz\x0b"),
            ("snappy", b"\xff\x06\x00\x00sNaPpY"),
            ("s2", b"\xff\x06\x00\x00S2sTwO"),
        ];
        for (name, head) in cases {
            let p = tmp().join("upload.bin");
            std::fs::write(&p, head).unwrap();
            assert_eq!(
                detect_kind(&p).unwrap(),
                UploadKind::Unsupported(name),
                "{name}：{head:?}"
            );
        }
        // 反例：單一執行檔、開頭剛好是 BZh 的文字檔仍是 PlainFile；zip 照舊
        for head in [
            &b"\x7fELF\x02\x01\x01\x00rest"[..],
            b"BZh9 is not bzip2 text",
            b"Rar! plain",
        ] {
            let p = tmp().join("upload.bin");
            std::fs::write(&p, head).unwrap();
            assert_eq!(detect_kind(&p).unwrap(), UploadKind::PlainFile, "{head:?}");
        }
        assert_eq!(
            detect_kind(&make_zip(&[("a", b"x")])).unwrap(),
            UploadKind::Zip
        );
    }

    static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

    fn tmp() -> PathBuf {
        let d = std::env::temp_dir().join(format!(
            "cytrace-archive-{}-{}",
            std::process::id(),
            SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn make_zip(entries: &[(&str, &[u8])]) -> PathBuf {
        let dir = tmp();
        let path = dir.join("t.zip");
        let mut w = zip::ZipWriter::new(File::create(&path).unwrap());
        let opt = zip::write::SimpleFileOptions::default();
        for (name, data) in entries {
            w.start_file(*name, opt).unwrap();
            w.write_all(data).unwrap();
        }
        w.finish().unwrap();
        path
    }

    fn make_tar(entries: &[(&str, &[u8])], with_symlink: bool) -> PathBuf {
        let dir = tmp();
        let path = dir.join("t.tar");
        let mut b = tar::Builder::new(File::create(&path).unwrap());
        for (name, data) in entries {
            let mut h = tar::Header::new_gnu();
            h.set_size(data.len() as u64);
            h.set_mode(0o644);
            h.set_cksum();
            b.append_data(&mut h, name, *data).unwrap();
        }
        if with_symlink {
            let mut h = tar::Header::new_gnu();
            h.set_entry_type(tar::EntryType::Symlink);
            h.set_size(0);
            h.set_cksum();
            b.append_link(&mut h, "evil-link", "/etc/passwd").unwrap();
        }
        b.finish().unwrap();
        path
    }

    #[test]
    fn detect_by_magic_bytes() {
        let zip = make_zip(&[("a.txt", b"hi")]);
        assert_eq!(detect_kind(&zip).unwrap(), UploadKind::Zip);
        let tar = make_tar(&[("a.txt", b"hi")], false);
        assert_eq!(detect_kind(&tar).unwrap(), UploadKind::Tar);
        let plain = tmp().join("x.bin");
        std::fs::write(&plain, b"just bytes").unwrap();
        assert_eq!(detect_kind(&plain).unwrap(), UploadKind::PlainFile);
    }

    #[test]
    fn zip_normal_extracts() {
        let zip = make_zip(&[("dir/a.txt", b"hello"), ("b.txt", b"world")]);
        let dest = tmp();
        let n = extract(&zip, UploadKind::Zip, &dest, 1024 * 1024).unwrap();
        assert_eq!(n, 2);
        assert_eq!(std::fs::read(dest.join("dir/a.txt")).unwrap(), b"hello");
    }

    #[test]
    fn zip_slip_rejected_whole_archive() {
        let zip = make_zip(&[("ok.txt", b"x"), ("../evil.txt", b"pwn")]);
        let dest = tmp();
        let err = extract(&zip, UploadKind::Zip, &dest, 1024 * 1024).unwrap_err();
        assert!(matches!(err, ArchiveError::PathViolation(_)));
        assert!(!dest.join("../evil.txt").exists());
    }

    /// 以 raw header bytes 造惡意 `../` 路徑（tar builder 自身會拒 `..`，須繞過）。
    fn make_evil_tar() -> PathBuf {
        let dir = tmp();
        let path = dir.join("evil.tar");
        let mut b = tar::Builder::new(File::create(&path).unwrap());
        let mut h = tar::Header::new_gnu();
        h.set_size(3);
        h.set_mode(0o644);
        h.set_entry_type(tar::EntryType::Regular);
        {
            let name = b"../evil";
            let bytes = h.as_mut_bytes();
            bytes[..name.len()].copy_from_slice(name);
        }
        h.set_cksum();
        b.append(&h, &b"pwn"[..]).unwrap();
        b.finish().unwrap();
        path
    }

    #[test]
    fn tar_traversal_rejected_and_symlink_skipped() {
        // ../ traversal → 整包拒收
        let tar = make_evil_tar();
        let err = extract(&tar, UploadKind::Tar, &tmp(), 1024 * 1024).unwrap_err();
        assert!(
            matches!(err, ArchiveError::PathViolation(_)),
            "應為 PathViolation，實得 {err:?}"
        );

        // symlink entry → 跳過，其餘正常
        let tar = make_tar(&[("good.txt", b"ok")], true);
        let dest = tmp();
        let n = extract(&tar, UploadKind::Tar, &dest, 1024 * 1024).unwrap();
        assert_eq!(n, 1);
        assert!(dest.join("good.txt").exists());
        assert!(!dest.join("evil-link").exists());
    }

    #[test]
    fn total_size_budget_enforced_on_actual_bytes() {
        let big = vec![0u8; 4096];
        let zip = make_zip(&[("a", &big), ("b", &big)]);
        let err = extract(&zip, UploadKind::Zip, &tmp(), 6000).unwrap_err();
        assert!(matches!(err, ArchiveError::TooLarge(_)));
    }

    #[test]
    fn targz_roundtrip() {
        // tar → gzip
        let tar = make_tar(&[("x/y.txt", b"z")], false);
        let gz_path = tmp().join("t.tar.gz");
        let mut enc = flate2::write::GzEncoder::new(
            File::create(&gz_path).unwrap(),
            flate2::Compression::fast(),
        );
        std::io::copy(&mut File::open(&tar).unwrap(), &mut enc).unwrap();
        enc.finish().unwrap();

        assert_eq!(detect_kind(&gz_path).unwrap(), UploadKind::TarGz);
        let dest = tmp();
        extract(&gz_path, UploadKind::TarGz, &dest, 1024 * 1024).unwrap();
        assert!(dest.join("x/y.txt").exists());
    }
}
