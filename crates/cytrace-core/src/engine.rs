//! Syft / Grype 子程序編排（SDS §3 / ADR-002/003）。
//!
//! 引擎為釘選版 Go binary，以子程序呼叫。Grype 強制離線：`GRYPE_DB_AUTO_UPDATE=false`、
//! `GRYPE_DB_VALIDATE_AGE=false`（否則舊快照會被年齡驗證中止，ADR-003）。
//!
//! 注意：本模組需安裝包內的引擎執行檔；無引擎時回 [`CytraceError::Engine`]，
//! 由 CLI 對映為非 2 的錯誤退出碼（與 fail-on 的 2 區隔）。
//!
//! [`ScanEngine`] trait 是 CLI 與 server（ADR-011）共用的測試縫：
//! 整合測試可注入 fake 實作，完全不需要 syft/grype binary（air-gapped CI 可跑）。

use crate::error::{CytraceError, Result};
use std::process::Command;

/// 掃描引擎抽象（測試縫）：真實實作為 [`RealEngine`]（子程序呼叫釘選版 syft/grype）。
pub trait ScanEngine: Send + Sync {
    /// 對目標產生 CycloneDX JSON SBOM。
    fn sbom(&self, target: &str) -> Result<String>;
    /// 對 SBOM（CycloneDX JSON）比對 CVE，回傳 grype JSON。
    fn vuln(&self, sbom_cyclonedx_json: &str) -> Result<String>;

    /// 對目標產生 CycloneDX CBOM（ADR-013）。
    ///
    /// **降級語意**（決策 4）：引擎 binary 不存在 → `Ok(None)`（不影響 SBOM/CVE 主流程）；
    /// 其餘失敗（子程序非零、輸出空白或非 JSON）→ `Err`，由呼叫端記為
    /// [`cytrace_types::CbomStatus::Failed`]，同樣不中止主流程。
    ///
    /// 預設實作回 `Ok(None)`，使既有 fake 引擎無須改動（測試縫相容）。
    fn cbom(&self, _target: &str) -> Result<Option<CbomOutput>> {
        Ok(None)
    }
}

/// 以子程序呼叫釘選版 syft/grype 的真實引擎。
pub struct RealEngine;

impl ScanEngine for RealEngine {
    fn sbom(&self, target: &str) -> Result<String> {
        sbom(target)
    }
    fn vuln(&self, sbom_cyclonedx_json: &str) -> Result<String> {
        vuln(sbom_cyclonedx_json)
    }
    fn cbom(&self, target: &str) -> Result<Option<CbomOutput>> {
        cbom(target)
    }
}

/// 以 Syft 對目標產生 CycloneDX JSON SBOM。
pub fn sbom(target: &str) -> Result<String> {
    let out = Command::new("syft")
        .args(["scan", target, "-o", "cyclonedx-json", "-q"])
        .output()
        .map_err(|e| CytraceError::Engine(format!("syft: {e}")))?;
    check(out, "syft")
}

/// 以 Grype 對 SBOM（CycloneDX JSON）比對 CVE，回傳 grype JSON。離線設定已內建。
///
/// 注意：grype 的 `sbom:-`（stdin）在部分版本不穩，故將 SBOM 寫入暫存檔以 `sbom:<path>` 餵入，
/// 亦避免 stdin/stdout pipe 滿載 deadlock。暫存檔用後即刪。
pub fn vuln(sbom_cyclonedx_json: &str) -> Result<String> {
    let tmp = sbom_temp_path();
    std::fs::write(&tmp, sbom_cyclonedx_json)?;
    let out = Command::new("grype")
        .arg(format!("sbom:{}", tmp.display()))
        .args(["-o", "json", "-q"])
        .env("GRYPE_DB_AUTO_UPDATE", "false")
        .env("GRYPE_DB_VALIDATE_AGE", "false")
        .output();
    let _ = std::fs::remove_file(&tmp);
    let out = out.map_err(|e| CytraceError::Engine(format!("grype: {e}")))?;
    check(out, "grype")
}

/// 由引擎的 `--version` 輸出取出版本號（`syft 1.51.1` → `1.51.1`）。
pub fn parse_version_output(out: &str) -> Option<String> {
    let first = out.lines().next()?.trim();
    let v = first.split_whitespace().nth(1)?;
    // 版本號須以數字起頭，避免把 help 文字誤認為版本
    v.chars().next().filter(char::is_ascii_digit)?;
    Some(v.to_string())
}

fn query_version(bin: &str) -> Option<String> {
    let out = Command::new(bin).arg("--version").output().ok()?;
    parse_version_output(&String::from_utf8_lossy(&out.stdout))
}

/// 掃描當下的**真實**引擎版本（NFR-03 可稽核）。
///
/// 以執行期查詢取代編譯期常數：交付包若被換過引擎，報表須反映實際跑的那一個。
/// 查不到（引擎缺席）→ `unknown`，不謊稱版本。
///
/// theia 的判準是 **CBOM 是否真的跑完**（`CbomStatus::Completed`），不是「有沒有下 `--cbom`」：
/// 引擎缺席或執行失敗卻蓋上版本號，等於在要併入交件的報表上做不實陳述。
/// theia 1.1.2 無 `--version`，故取建置期由 `versions.env` 帶入的釘選值。
pub fn tool_versions(cbom: &cytrace_types::CbomStatus) -> cytrace_types::ToolVersions {
    cytrace_types::ToolVersions {
        syft: query_version("syft").unwrap_or_else(|| "unknown".into()),
        grype: query_version("grype").unwrap_or_else(|| "unknown".into()),
        theia: matches!(cbom, cytrace_types::CbomStatus::Completed)
            .then(|| option_env!("CYTRACE_THEIA_VERSION").map(str::to_string))
            .flatten(),
    }
}

/// 離開作用域即刪除的暫存目錄。
///
/// theia 的 HOME 需在**所有**離開路徑上清理——手動 `remove_dir_all` 只會蓋到成功路徑，
/// 引擎缺席或 spawn 失敗的 early return 會各洩一個空目錄；在 server 上這是每次呼叫累積、無上界。
struct TempDir(std::path::PathBuf);

impl TempDir {
    fn new(prefix: &str) -> std::io::Result<Self> {
        let p = unique_temp_path(prefix);
        std::fs::create_dir_all(&p)?;
        Ok(Self(p))
    }
    fn path(&self) -> &std::path::Path {
        &self.0
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0); // 清理失敗不影響掃描結果
    }
}

/// 供 [`vuln`] 使用的暫存 SBOM 路徑（**每次呼叫唯一**）。
///
/// server 的 job 跑在同一行程（`spawn_blocking`，預設併發 2）。若是每行程一個固定路徑，
/// 兩個 job 會互寫互刪——最糟的情形是 A 的元件配到 B 的 CVE，
/// 而 grype 退出碼 0、輸出合法 JSON，`check()` 完全攔不到，報表安靜地描述錯的目標。
pub fn sbom_temp_path() -> std::path::PathBuf {
    unique_temp_path("cytrace-sbom").with_extension("cdx.json")
}

/// 行程內唯一的暫存路徑（`<prefix>-<pid>-<seq>`）。
///
/// 只用 pid 的話，**同一行程內的併發呼叫會共用同一個目錄**——server 預設可並發兩個 job，
/// 複審實測共用 theia HOME 會讓 26/80 的 job 失敗。序號使兩者互不相干。
fn unique_temp_path(prefix: &str) -> std::path::PathBuf {
    use std::sync::atomic::{AtomicU64, Ordering};
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let n = SEQ.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!("{prefix}-{}-{n}", std::process::id()))
}

/// 執行掃描的身分（ADR-013 決策 10）。
///
/// `dir` 模式的偵測完整度取決於權限，故報表須標示當時是誰在跑。
/// 以「建立暫存檔後讀其 owner」取得 effective uid——零額外相依。
pub fn scan_identity() -> String {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let probe = unique_temp_path("cytrace-uid-probe");
        let uid = std::fs::write(&probe, b"")
            .ok()
            .and_then(|_| std::fs::metadata(&probe).ok())
            .map(|m| m.uid());
        let _ = std::fs::remove_file(&probe);
        match uid {
            Some(u) => format!("uid={u}"),
            None => "uid=unknown".into(),
        }
    }
    #[cfg(not(unix))]
    {
        // Windows 無 uid 概念；以使用者名稱標示（ADR-010 雙平台）
        std::env::var("USERNAME")
            .map(|u| format!("user={u}"))
            .unwrap_or_else(|_| "user=unknown".into())
    }
}

// ─── CBOM（cbomkit-theia；ADR-013）─────────────────────────────────

/// 一次 CBOM 掃描的產物（ADR-013）。
///
/// `skipped` 與 `json` **一起回傳**：早期版本以行程內全域狀態傳遞 skipped，
/// 在 server 併發（預設兩個 job 共用同一 engine）下會跨 job 互相覆寫——
/// 實測 15/80 的 job 把「真的有檔案被略過」回報成 0，fail-closed 保護靜默消失。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CbomOutput {
    /// theia 的原始 CycloneDX JSON（原樣落地用）。
    pub json: String,
    /// 引擎因自身大小門檻略過的**檔案數**（去重後）。
    pub skipped: u64,
    /// 引擎自承偵測到的資產數（`Found N ...`）——供呼叫端與實際產出對帳。
    pub admitted: u64,
}

/// theia 的輸入形態。**只接受本地路徑**——registry 參照一律在此層拒絕（決策 2）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CbomTarget {
    /// 檔案系統目錄 → `theia dir <path>`
    Dir(std::path::PathBuf),
    /// docker-save tar / OCI layout（目錄或 tar）→ `theia image <path>`
    Image(std::path::PathBuf),
}

impl CbomTarget {
    /// theia 子命令名稱。
    pub fn subcommand(&self) -> &'static str {
        match self {
            CbomTarget::Dir(_) => "dir",
            CbomTarget::Image(_) => "image",
        }
    }
    /// 傳給 theia 的路徑。
    pub fn path(&self) -> &std::path::Path {
        match self {
            CbomTarget::Dir(p) | CbomTarget::Image(p) => p,
        }
    }
}

/// CyTrace 目標字串 → theia 輸入形態（ADR-013 決策 2）。
///
/// **必須實際開檔成功才轉譯**，不可僅做存在性判定：存在但不可讀的 tar 會讓 theia
/// 判定「本地取得失敗」而**回退嘗試 docker daemon / podman / containerd / registry**
/// （T901b 實測，stderr 可見 `index.docker.io`），在有網路的環境即違反零外連（NFR-01）。
///
/// 無法在本地判定的形態（裸映像名等）一律拒絕，**不猜測**。
pub fn cbom_target(target: &str) -> Result<CbomTarget> {
    // syft 風格前綴：取冒號後的路徑部分
    let raw = ["dir:", "docker-archive:", "oci-archive:", "oci-dir:"]
        .iter()
        .find_map(|p| target.strip_prefix(*p))
        .unwrap_or(target);

    // **一律正規化為絕對路徑**（決定性防線，NFR-01）：
    // theia 解析輸入失敗後會把字串當成**映像參照**回退到 docker daemon / podman /
    // containerd / registry。實測 8 bytes 的 gzip 殘檔命名為 `nginx` → 它載入本機真正的
    // nginx 映像並輸出 10,807 個元件，當成使用者目標寫進報表（報表造假）；
    // 截斷的 tar 則會 `GET https://index.docker.io/...`（外連）。
    // 改成絕對路徑後 theia 直接 `could not parse reference`，兩條回退全部關閉。
    let path = std::fs::canonicalize(raw).map_err(|_| {
        CytraceError::Config(format!(
            "cbom.err.target_not_local（目標非本地可讀路徑，拒絕交給引擎）：{target}"
        ))
    })?;
    let path = path.as_path();
    let meta = std::fs::metadata(path).map_err(|_| {
        CytraceError::Config(format!(
            "cbom.err.target_not_local（目標非本地可讀路徑，拒絕交給引擎）：{target}"
        ))
    })?;

    if meta.is_dir() {
        // 可讀性前檢：列目錄失敗即拒絕
        std::fs::read_dir(path).map_err(|_| {
            CytraceError::Config(format!(
                "cbom.err.target_unreadable（目錄不可讀）：{target}"
            ))
        })?;
        // OCI layout 目錄：標記檔須**實質有效**才走 image 模式。
        // 只判 `exists()` 的話，一個空的 oci-layout 檔就能讓任意目錄被當成映像。
        if is_oci_layout(path) {
            return Ok(CbomTarget::Image(path.to_path_buf()));
        }
        return Ok(CbomTarget::Dir(path.to_path_buf()));
    }

    // 可讀性前檢：實際開檔
    let mut f = std::fs::File::open(path).map_err(|_| {
        CytraceError::Config(format!(
            "cbom.err.target_unreadable（檔案不可讀）：{target}"
        ))
    })?;

    // 格式驗證：**不可僅憑「讀得到」就當成映像**。
    // theia 的 image 子命令會把無法解析的路徑當成**映像參照**：實測以純文字檔命名為
    // `nginx` 時，它成功載入本機真正的 nginx 映像並輸出 10,807 項資產——那會把別的
    // 映像的盤點結果寫進使用者的報表（報表造假）；daemon 不可用時則回退打 registry（NFR-01）。
    if !is_archive(&mut f) {
        return Err(CytraceError::Config(format!(
            "cbom.err.target_not_archive（非 tar / gzip 封存檔，拒絕當成映像）：{target}"
        )));
    }
    Ok(CbomTarget::Image(path.to_path_buf()))
}

/// OCI image layout 目錄的實質驗證（非僅檔名存在）。
///
/// 依 OCI Image Layout 規格要求三者齊備：`oci-layout` 為含 `imageLayoutVersion` 的
/// 合法 JSON、`index.json` 存在、`blobs/` 目錄存在。
fn is_oci_layout(dir: &std::path::Path) -> bool {
    let Ok(text) = std::fs::read_to_string(dir.join("oci-layout")) else {
        return false;
    };
    let valid_marker = serde_json::from_str::<serde_json::Value>(&text)
        .ok()
        .and_then(|v| v.get("imageLayoutVersion").cloned())
        .is_some();
    valid_marker && dir.join("index.json").exists() && dir.join("blobs").is_dir()
}

/// 以 magic bytes 辨識 tar / gzip（與 server 的 `archive::detect_kind` 同一組判準）。
///
/// gzip=`\x1f\x8b`；tar=offset 257 的 `ustar`。副檔名不予採信。
fn is_archive(f: &mut std::fs::File) -> bool {
    use std::io::Read;
    let mut head = [0u8; 262];
    let Ok(n) = f.read(&mut head) else {
        return false;
    };
    (n >= 2 && head[0..2] == [0x1f, 0x8b]) || (n >= 262 && &head[257..262] == b"ustar")
}

/// 以 cbomkit-theia 對目標產生 CycloneDX CBOM（ADR-013）。
///
/// 硬性條件（決策 10，皆為 T901b 實測所得）：
/// - 目標先經 [`cbom_target`] 轉譯與**可讀性前檢**，不可讀即拒絕、不 spawn；
/// - 以**專用可寫 `HOME`** 啟動，否則 theia 會把警告印進 stdout 汙染 JSON；
/// - stdout 須通過 [`ensure_cbom_json`]，空白或非 JSON 一律視為失敗。
///
/// 回傳 `Ok(None)` 僅代表**引擎不存在**（降級）；其餘失敗回 `Err`。
/// CBOM 子程序的逾時上限（秒）。可經 `CYTRACE_CBOM_TIMEOUT_SECS` 覆寫。
///
/// 無逾時的後果（實測）：目標樹含一個 FIFO 即永久阻塞——CLI 無聲掛住、
/// server 的 permit 永不釋放且 Running job 不可取消，預設併發 2 時兩個卡住
/// 就讓掃描服務停擺到重啟。真實 root filesystem 本身就含 FIFO，屬普通輸入。
const CBOM_TIMEOUT_SECS_DEFAULT: u64 = 600;

fn cbom_timeout() -> std::time::Duration {
    let secs = std::env::var("CYTRACE_CBOM_TIMEOUT_SECS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .filter(|n| *n > 0)
        .unwrap_or(CBOM_TIMEOUT_SECS_DEFAULT);
    std::time::Duration::from_secs(secs)
}

pub fn cbom(target: &str) -> Result<Option<CbomOutput>> {
    cbom_with_timeout(target, cbom_timeout())
}

/// 同 [`cbom`]，但可指定逾時（供測試注入短逾時，不必操作行程環境變數）。
pub fn cbom_with_timeout(target: &str, timeout: std::time::Duration) -> Result<Option<CbomOutput>> {
    let t = cbom_target(target)?;

    // theia 需要可寫 HOME 才不會把警告印到 stdout（T901b 實測）
    // 每次呼叫一個獨立 HOME：併發 job 共用會互相干擾（複審實測 26/80 失敗）。
    // 以 guard 承接，確保引擎缺席 / spawn 失敗等 early return 也會清理。
    let home = TempDir::new("cytrace-theia-home")?;

    // 環境隔離：清空繼承環境後只加回必要項，避免 DOCKER_HOST 等變數把子程序指向非預期的
    // daemon。**注意**：這不是零外連的防線——daemon 走預設 unix socket、registry 也不吃
    // 環境變數。真正關閉回退鏈的是 cbom_target 的絕對路徑正規化。
    let mut child = match Command::new("cbomkit-theia")
        .arg(t.subcommand())
        .arg(t.path())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .env_clear()
        .env("HOME", home.path())
        .env("TMPDIR", std::env::temp_dir())
        // PATH 必須沿用繼承值：離線交付包的 wrapper 正是靠 PATH 指向包內 bin/，
        // 寫死路徑會讓交付版找不到引擎（實測：theia 在 ~/.local/bin 時被誤判為缺席）
        .env(
            "PATH",
            std::env::var_os("PATH").unwrap_or_else(|| "/usr/local/bin:/usr/bin:/bin".into()),
        )
        .spawn()
    {
        Ok(c) => c,
        // 引擎不存在 → 降級（決策 4）；其餘 I/O 錯誤仍為失敗
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(CytraceError::Engine(format!("cbomkit-theia: {e}"))),
    };

    // 逾時輪詢：逾時即 kill，歸為 Failed（fail-closed，不中止主流程）
    let deadline = std::time::Instant::now() + timeout;
    loop {
        match child.try_wait() {
            Ok(Some(_)) => break,
            Ok(None) => {
                if std::time::Instant::now() >= deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(CytraceError::Engine(format!(
                        "cbom.err.timeout（引擎逾時 {} 秒，已終止；目標可能含具名管線或特殊檔案）",
                        timeout.as_secs()
                    )));
                }
                std::thread::sleep(std::time::Duration::from_millis(50));
            }
            Err(e) => return Err(CytraceError::Engine(format!("cbomkit-theia: {e}"))),
        }
    }
    let out = child
        .wait_with_output()
        .map_err(|e| CytraceError::Engine(format!("cbomkit-theia: {e}")))?;

    // stderr 含「因大小門檻略過」的警告，須在丟棄前清點（見 skipped_file_count）
    let stderr_text = String::from_utf8_lossy(&out.stderr).into_owned();
    let skipped = skipped_file_count(&stderr_text);
    // 引擎自承偵測到的數量（尚未扣除 stdout 實際產出，由呼叫端對帳）
    let admitted = undetermined_count(&stderr_text, 0);

    let stdout = check(out, "cbomkit-theia")?;
    ensure_cbom_json(&stdout)?;
    Ok(Some(CbomOutput {
        json: stdout,
        skipped,
        admitted,
    }))
}

/// 清點 theia 因**自身大小門檻**而略過的檔案數（ADR-013 決策 10）。
///
/// 複審實測：theia 1.1.2 對超過 1 MiB 的檔案直接略過，只在 **stderr** 印
/// `Skipping large file: <name> (exceeds limit of 1048576 bytes)`，**exit 仍為 0**。
/// 不清點的話 `unscanned_count` 會是 0，量子閘門就會對「其實沒掃完」的目標回報通過。
/// 受影響的恰是最要緊的目標：串接的 CA 憑證鏈 bundle、大型 PEM 匯出。
///
/// 該門檻在 1.1.2 無旗標可調，故只能在 CyTrace 側清點並顯性標示。
pub fn skipped_file_count(stderr: &str) -> u64 {
    // theia 的**每個 plugin** 對同一個檔案各印一行 → 直接數行數會是檔案數的數倍。
    // 取訊息中的檔名去重，才符合「被略過的檔案數」語意。
    let mut files = std::collections::BTreeSet::new();
    for (i, line) in stderr.lines().enumerate() {
        let Some(rest) = line.split("Skipping large file:").nth(1) else {
            continue;
        };
        // 去重只為修正「每 plugin 各印一行」的膨脹；**解析不出檔名時寧可多算也不能少算**，
        // 否則檔名以分隔字串開頭（可由上游或上傳者控制）就能把整行吃掉，
        // 使 oversize 歸零、閘門與報表警示同時失效——fail-open。
        let name = rest
            .rsplit_once(" (exceeds limit of ")
            .map(|(head, _)| head)
            .unwrap_or(rest)
            .trim()
            .trim_end_matches('"')
            .trim();
        if name.is_empty() {
            // 認不得就以行序當唯一鍵：計數只會偏高，不會偏低
            files.insert(format!("<unnamed-{i}>"));
        } else {
            files.insert(name.to_string());
        }
    }
    files.len() as u64
}

/// 清點「引擎自承偵測到、但未出現在 stdout 的資產數」（ADR-013 決策 10）。
///
/// theia 對它偵測到卻無法建模的資產只在 **stderr** 留痕
/// （`Found N private key(s) in <path>`），stdout 零元件、exit 0。
/// 實測：OpenSSH 格式私鑰走這條路；同一把金鑰改存 PKCS#8 PEM 則會產生資產——
/// **換個檔案格式，閘門答案就從「有脆弱」變成「通過」**。
/// 原則與 oversize 相同：引擎講得出口的漏檢一律要出現在計數裡，寧可多算。
///
/// `modelled` 傳入 stdout 實際產出的資產數，用以扣除已如實回報的部分。
pub fn undetermined_count(stderr: &str, modelled: u64) -> u64 {
    let mut admitted = 0u64;
    for line in stderr.lines() {
        let Some(rest) = line.split("Found ").nth(1) else {
            continue;
        };
        if !rest.contains("private key") && !rest.contains("certificate") {
            continue;
        }
        // 取 "Found " 之後的第一個整數
        let n: u64 = rest
            .split_whitespace()
            .next()
            .and_then(|t| t.parse().ok())
            .unwrap_or(1); // 認不得數字也算一項：寧可多算
        admitted = admitted.saturating_add(n);
    }
    admitted.saturating_sub(modelled)
}

/// 驗證 theia stdout 為合法 JSON（ADR-013 決策 10）。
///
/// `HOME` 不可寫時 theia 會把警告印到 **stdout** 汙染輸出；輸入不可讀時則 **stdout 空白且 exit 0**。
/// 兩種情形都**不得**被當成「掃到 0 項」——一律視為失敗。
pub fn ensure_cbom_json(stdout: &str) -> Result<&str> {
    if stdout.trim().is_empty() {
        return Err(CytraceError::Parse(
            "cbom.err.empty_output（引擎輸出空白，非「零資產」）".into(),
        ));
    }
    let v: serde_json::Value = serde_json::from_str(stdout).map_err(|e| {
        CytraceError::Parse(format!("cbom.err.stdout_not_json（輸出非合法 JSON）：{e}"))
    })?;
    // 光是「合法 JSON」不夠：`{}` 也會通過，然後被當成「掃到 0 項」——又是一個 fail-open。
    // 必須確認這確實是一份 CycloneDX BOM。
    let is_cyclonedx = v.get("bomFormat").and_then(|b| b.as_str()) == Some("CycloneDX")
        && v.get("specVersion").is_some();
    if !is_cyclonedx {
        return Err(CytraceError::Parse(
            "cbom.err.not_cyclonedx（輸出不是 CycloneDX BOM）".into(),
        ));
    }
    Ok(stdout)
}

fn check(out: std::process::Output, name: &str) -> Result<String> {
    if out.status.success() {
        Ok(String::from_utf8_lossy(&out.stdout).into_owned())
    } else {
        Err(CytraceError::Engine(format!(
            "{name} 失敗（exit {:?}）：{}",
            out.status.code(),
            String::from_utf8_lossy(&out.stderr).trim()
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// fake 引擎可經 `dyn ScanEngine` 注入——驗證測試縫成立（server 整合測試依賴此性質）。
    struct FakeEngine;

    impl ScanEngine for FakeEngine {
        fn sbom(&self, _target: &str) -> Result<String> {
            Ok("{}".into())
        }
        fn vuln(&self, _sbom: &str) -> Result<String> {
            Ok("{\"matches\":[]}".into())
        }
    }

    #[test]
    fn fake_engine_usable_through_trait_object() {
        let engine: &dyn ScanEngine = &FakeEngine;
        assert_eq!(engine.sbom("dir:/x").unwrap(), "{}");
        assert_eq!(engine.vuln("{}").unwrap(), "{\"matches\":[]}");
    }

    // ── T905：CBOM 目標轉譯與可讀性前檢（ADR-013 決策 2/10）──

    use std::fs;
    use std::path::PathBuf;

    fn tmpdir(tag: &str) -> PathBuf {
        let d =
            std::env::temp_dir().join(format!("cytrace-cbom-test-{}-{tag}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(&d).expect("建立暫存目錄");
        d
    }

    #[test]
    fn existing_directory_maps_to_dir_mode() {
        let d = tmpdir("dir");
        let t = cbom_target(d.to_str().unwrap()).expect("目錄須可轉譯");
        assert!(matches!(t, CbomTarget::Dir(_)));
        // syft 風格前綴亦須支援
        let t2 = cbom_target(&format!("dir:{}", d.display())).expect("dir: 前綴");
        assert!(matches!(t2, CbomTarget::Dir(_)));
    }

    /// 產生一個最小但合法的 uncompressed tar（單一 manifest.json 條目）。
    fn write_minimal_tar(path: &std::path::Path) {
        let mut buf = vec![0u8; 512];
        let name = b"manifest.json";
        buf[..name.len()].copy_from_slice(name);
        buf[100..108].copy_from_slice(b"0000644\0"); // mode
        buf[108..116].copy_from_slice(b"0000000\0"); // uid
        buf[116..124].copy_from_slice(b"0000000\0"); // gid
        buf[124..136].copy_from_slice(b"00000000002\0"); // size = 2
        buf[136..148].copy_from_slice(b"00000000000\0"); // mtime
        buf[148..156].copy_from_slice(b"        "); // checksum 佔位
        buf[156] = b'0'; // typeflag = 一般檔
        buf[257..263].copy_from_slice(b"ustar\0");
        buf[263..265].copy_from_slice(b"00");
        let sum: u32 = buf[..512].iter().map(|b| *b as u32).sum();
        let chk = format!("{sum:06o}\0 ");
        buf[148..156].copy_from_slice(chk.as_bytes());
        buf.extend_from_slice(b"[]"); // 內容
        buf.extend_from_slice(&vec![0u8; 510]); // 補滿 block
        buf.extend_from_slice(&vec![0u8; 1024]); // 結尾雙空 block
        fs::write(path, &buf).unwrap();
    }

    #[test]
    fn valid_tar_maps_to_image_mode() {
        let d = tmpdir("tar");
        let tar = d.join("image.tar");
        write_minimal_tar(&tar);
        assert!(matches!(
            cbom_target(tar.to_str().unwrap()).expect("合法 tar"),
            CbomTarget::Image(_)
        ));
        assert!(matches!(
            cbom_target(&format!("docker-archive:{}", tar.display())).expect("前綴"),
            CbomTarget::Image(_)
        ));
    }

    #[test]
    fn gzip_archive_maps_to_image_mode() {
        let d = tmpdir("targz");
        let tgz = d.join("image.tar.gz");
        // gzip magic + 任意內容（內層無法在不解壓的情況下驗證，故僅憑 magic）
        fs::write(&tgz, [0x1f, 0x8b, 0x08, 0x00, 0, 0, 0, 0]).unwrap();
        assert!(matches!(
            cbom_target(tgz.to_str().unwrap()).expect("gzip"),
            CbomTarget::Image(_)
        ));
    }

    #[test]
    fn target_path_is_always_absolute() {
        // 決定性防線：theia 解析失敗後會把**字串當成映像參照**回退到 docker daemon / registry。
        // 實測 8 bytes 的 gzip 殘檔命名為 `nginx` → 載入本機真正的 nginx 映像、輸出 10,807 個元件；
        // 改成絕對路徑後 theia 直接 `could not parse reference`，兩條回退全部關閉。
        let d = tmpdir("abs");
        let f = d.join("nginx");
        fs::write(&f, [0x1f, 0x8b, 0x08, 0x00, 0, 0, 0, 0]).unwrap();

        let prev = std::env::current_dir().unwrap();
        std::env::set_current_dir(&d).unwrap();
        let got = cbom_target("nginx");
        std::env::set_current_dir(prev).unwrap();

        let t = got.expect("gzip 殘檔仍視為封存檔（格式層），但路徑須絕對化");
        assert!(
            t.path().is_absolute(),
            "交給 theia 的路徑必須是絕對路徑，否則會被當成映像名：{:?}",
            t.path()
        );
    }

    #[test]
    fn directory_target_is_also_absolute() {
        let d = tmpdir("absdir");
        let prev = std::env::current_dir().unwrap();
        std::env::set_current_dir(d.parent().unwrap()).unwrap();
        let name = d.file_name().unwrap().to_str().unwrap().to_string();
        let got = cbom_target(&name);
        std::env::set_current_dir(prev).unwrap();
        assert!(got.expect("目錄").path().is_absolute());
    }

    #[test]
    fn oci_layout_marker_must_be_valid_before_image_mode() {
        // 空的 oci-layout 檔原本就能讓目錄走 image 模式（連 magic bytes 都不跑）
        let d = tmpdir("fakeoci");
        fs::write(d.join("oci-layout"), b"").unwrap();
        let t = cbom_target(d.to_str().unwrap()).expect("目錄可掃");
        assert!(
            matches!(t, CbomTarget::Dir(_)),
            "無效的 oci-layout 標記不得讓目錄被當成映像"
        );
    }

    #[test]
    fn valid_oci_layout_directory_is_image_mode() {
        let d = tmpdir("realoci");
        fs::write(d.join("oci-layout"), br#"{"imageLayoutVersion":"1.0.0"}"#).unwrap();
        fs::write(d.join("index.json"), b"{}").unwrap();
        fs::create_dir_all(d.join("blobs")).unwrap();
        assert!(matches!(
            cbom_target(d.to_str().unwrap()).expect("合法 OCI layout"),
            CbomTarget::Image(_)
        ));
    }

    #[test]
    fn non_archive_file_is_rejected_instead_of_guessed_as_image() {
        // 複審實測：任何「可讀」檔案都被當成 image 交給 theia 時，
        // theia 會把檔名當成映像參照——曾載入本機真正的 nginx 映像並輸出 10,807 項資產，
        // 當成使用者目標的盤點結果寫進報表（報表造假），daemon 不可用時則回退打 registry（NFR-01）。
        // 故非封存檔一律拒絕，不猜測。
        let d = tmpdir("notarchive");
        for (name, bytes) in [
            ("nginx", &b"just some text"[..]),
            ("firmware.bin", &[0u8, 1, 2, 3][..]),
            ("image.tar", &b"not really a tar"[..]),
        ] {
            let f = d.join(name);
            fs::write(&f, bytes).unwrap();
            assert!(
                cbom_target(f.to_str().unwrap()).is_err(),
                "非封存檔 {name} 必須被拒絕，不得交給 theia"
            );
        }
    }

    #[test]
    fn bare_name_is_rejected_even_if_a_file_with_that_name_exists_in_cwd() {
        // 原測試只因 CWD 恰好沒有同名檔而通過——語意須由「檔案不存在」改為「非封存格式」
        for bare in ["nginx:latest", "ghcr.io/foo/bar:1.0", "alpine"] {
            assert!(cbom_target(bare).is_err(), "裸映像名 {bare} 必須被拒絕");
        }
    }

    #[test]
    fn oci_layout_directory_maps_to_image_mode() {
        let d = tmpdir("oci");
        fs::write(d.join("oci-layout"), br#"{"imageLayoutVersion":"1.0.0"}"#).unwrap();
        fs::write(d.join("index.json"), b"{}").unwrap();
        fs::create_dir_all(d.join("blobs")).unwrap();
        assert!(matches!(
            cbom_target(d.to_str().unwrap()).expect("OCI layout"),
            CbomTarget::Image(_)
        ));
    }

    #[test]
    fn nonexistent_path_is_rejected() {
        assert!(cbom_target("/nonexistent/cytrace/xyz.tar").is_err());
    }

    #[test]
    #[cfg(unix)]
    fn unreadable_input_is_rejected_before_spawning_engine() {
        // ADR-013 新發現二：輸入不可讀時 theia 會回退嘗試 registry（隱含外連），
        // 且 stdout 空白仍 exit 0。故必須「實際開檔成功」才轉譯。
        use std::os::unix::fs::PermissionsExt;
        let d = tmpdir("unreadable");
        let tar = d.join("secret.tar");
        fs::write(&tar, b"x").unwrap();
        fs::set_permissions(&tar, fs::Permissions::from_mode(0o000)).unwrap();
        let result = cbom_target(tar.to_str().unwrap());
        // root 會無視權限位元，該情境下跳過斷言
        if fs::File::open(&tar).is_err() {
            assert!(result.is_err(), "不可讀的 tar 必須在 spawn 前被拒絕");
        }
    }

    // ── stdout 純淨度（ADR-013 決策 10）──

    #[test]
    fn polluted_stdout_is_rejected_as_failure() {
        // HOME 不可寫時 theia 會把警告印到 stdout，JSON 解析失敗但 exit 0
        let polluted = "could not create application folder '/nonexistent/.cbomkit-theia'\n{\"bomFormat\":\"CycloneDX\"}";
        assert!(ensure_cbom_json(polluted).is_err());
    }

    #[test]
    fn empty_stdout_is_rejected_not_treated_as_zero_assets() {
        // 輸入不可讀時 stdout 空白 + exit 0——絕不可映射為「掃到 0 項」
        assert!(ensure_cbom_json("").is_err());
        assert!(ensure_cbom_json("   \n").is_err());
    }

    #[test]
    fn valid_cbom_json_passes_through() {
        let good = r#"{"bomFormat":"CycloneDX","specVersion":"1.6","components":[]}"#;
        assert_eq!(ensure_cbom_json(good).expect("合法 JSON"), good);
    }
}
