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
            .then(|| env!("CYTRACE_THEIA_VERSION").to_string()),
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

/// 漏洞 DB 快照的版本與建置時間（NFR-03 / ADR-003 稽核欄位）。
///
/// 事實源是 `grype db status -o json` 的 `schemaVersion` 與 `built`。
/// **這個欄位曾經是假的**：CLI 與 server 都硬編碼 `"snapshot"` / `"unknown"`，
/// 而 SOP §5 與 ADR-003 宣稱「報表顯示 DB 快照版本／日期供時效稽核」——
/// 宣稱存在的稽核控制實質不存在（release 準備複審 major #18）。
///
/// fail-closed：任何一步失敗（grype 缺席、非零退出、JSON 壞、欄位缺）一律回
/// `"unavailable"` sentinel——**不得**假裝有值；前端把 sentinel 譯為可讀訊息。
/// 掃描主流程不因此失敗：DB 缺失的硬性攔截在 vuln 比對那層，此處只負責稽核標示。
pub fn db_snapshot() -> cytrace_types::DbSnapshot {
    // **不以退出碼過濾**：DB 逾預設時效（5 天——air-gapped 場域的常態）時
    // `grype db status` exit 1 但 stdout 仍含完整 JSON。初版 `.filter(success)`
    // 讓時效稽核欄位**恰在 DB 一舊就整欄消失**——NFR-03 要稽核的正是 DB 多舊
    // （release-prep 複審 major #0/#3，反證者實測確認）。時效判斷是稽核者的事，
    // 我們負責如實轉錄；另補 VALIDATE_AGE=false 使函式不依賴 wrapper 的環境繼承。
    parse_db_status(
        Command::new("grype")
            .args(["db", "status", "-o", "json"])
            .env("GRYPE_CHECK_FOR_APP_UPDATE", "false")
            .env("GRYPE_DB_AUTO_UPDATE", "false")
            .env("GRYPE_DB_VALIDATE_AGE", "false")
            .output()
            .ok()
            .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
            .as_deref(),
    )
}

/// 解析 `grype db status -o json`。抽成純函式以便餵真實樣本測試——
/// 憑證計數那課的教訓：凡依賴引擎輸出格式，就要有一份實地抓取的樣本進測試。
pub fn parse_db_status(stdout: Option<&str>) -> cytrace_types::DbSnapshot {
    const UNAVAILABLE: &str = "unavailable";
    let fallback = || cytrace_types::DbSnapshot {
        version: UNAVAILABLE.into(),
        built: UNAVAILABLE.into(),
    };
    let Some(raw) = stdout else { return fallback() };
    let Ok(v) = serde_json::from_str::<serde_json::Value>(raw) else {
        return fallback();
    };
    let field = |k: &str| {
        v.get(k)
            .and_then(|x| x.as_str())
            .filter(|s| !s.trim().is_empty())
            .map(str::to_string)
    };
    match (field("schemaVersion"), field("built")) {
        (Some(version), Some(built)) => cytrace_types::DbSnapshot { version, built },
        _ => fallback(),
    }
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
    /// 引擎自承偵測到的**私鑰**數（`Found N private key(s) ...`）。
    pub admitted_keys: u64,
    /// 引擎自承偵測到的**憑證**數。
    pub admitted_certs: u64,
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
    let path = std::fs::canonicalize(raw).map_err(|_| CytraceError::Cbom {
        key: "cbom.err.target_not_local",
        detail: Some(target.to_string()),
    })?;
    let path = path.as_path();
    let meta = std::fs::metadata(path).map_err(|_| CytraceError::Cbom {
        key: "cbom.err.target_not_local",
        detail: Some(target.to_string()),
    })?;

    if meta.is_dir() {
        // 可讀性前檢：列目錄失敗即拒絕
        std::fs::read_dir(path).map_err(|_| CytraceError::Cbom {
            key: "cbom.err.target_unreadable",
            detail: Some(target.to_string()),
        })?;
        // OCI layout 目錄：標記檔須**實質有效**才走 image 模式。
        // 只判 `exists()` 的話，一個空的 oci-layout 檔就能讓任意目錄被當成映像。
        if is_oci_layout(path) {
            return Ok(CbomTarget::Image(path.to_path_buf()));
        }
        return Ok(CbomTarget::Dir(path.to_path_buf()));
    }

    // 可讀性前檢：實際開檔
    let mut f = std::fs::File::open(path).map_err(|_| CytraceError::Cbom {
        key: "cbom.err.target_unreadable",
        detail: Some(target.to_string()),
    })?;

    // 格式驗證：**不可僅憑「讀得到」就當成映像**。
    // theia 的 image 子命令會把無法解析的路徑當成**映像參照**：實測以純文字檔命名為
    // `nginx` 時，它成功載入本機真正的 nginx 映像並輸出 10,807 項資產——那會把別的
    // 映像的盤點結果寫進使用者的報表（報表造假）；daemon 不可用時則回退打 registry（NFR-01）。
    if !is_archive(&mut f) {
        return Err(CytraceError::Cbom {
            key: "cbom.err.target_not_archive",
            detail: Some(target.to_string()),
        });
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

/// 逾時的上限（24 小時）。**上界與下界同樣必要**：`Instant::now() + timeout` 在結果
/// 無法表示時依定義 **panic**，故 `u64::MAX` 秒這種值不是「很大的逾時」而是崩潰
/// ——server 模式下是 job thread 直接炸掉，不是設計中的降級（第七輪複審 finding）。
const CBOM_TIMEOUT_SECS_MAX: u64 = 86_400;

/// 解析逾時設定值。**刻意不提供「無逾時」**：`0`、負值、非數字一律回退預設；
/// 超過 [`CBOM_TIMEOUT_SECS_MAX`] 者同樣回退。
///
/// 「0 = 無限制」是常見慣例，這裡明確不採用——無逾時正是上述 FIFO 永久阻塞的成因，
/// 給得出這個值就等於給得出讓 server 停擺的開關。回退而非報錯，是因為本變數僅供
/// 測試與除錯（未列於 CLI help 與交付文件），打錯字不該讓整趟掃描失敗。
fn parse_timeout_secs(raw: Option<&str>) -> u64 {
    raw.and_then(|v| v.trim().parse::<u64>().ok())
        .filter(|n| (1..=CBOM_TIMEOUT_SECS_MAX).contains(n))
        .unwrap_or(CBOM_TIMEOUT_SECS_DEFAULT)
}

fn cbom_timeout() -> std::time::Duration {
    let raw = std::env::var("CYTRACE_CBOM_TIMEOUT_SECS").ok();
    std::time::Duration::from_secs(parse_timeout_secs(raw.as_deref()))
}

pub fn cbom(target: &str) -> Result<Option<CbomOutput>> {
    cbom_with_timeout(target, cbom_timeout())
}

/// 同 [`cbom`]，但可指定逾時（供測試注入短逾時，不必操作行程環境變數）。
pub fn cbom_with_timeout(target: &str, timeout: std::time::Duration) -> Result<Option<CbomOutput>> {
    cbom_with_timeouts(target, timeout, DRAIN_GRACE_DEFAULT)
}

/// 子程序結束後等管線 EOF 的寬限。正常情況下 buffer 已就緒，此值只在異常時生效。
///
/// 上界的依據：子程序已結束（或已被 kill），寫端唯一可能還開著的情形是有孫程序
/// 繼承了它；5 秒足以涵蓋正常的 EOF 傳遞，又不會讓呼叫端實質卡住。
const DRAIN_GRACE_DEFAULT: std::time::Duration = std::time::Duration::from_secs(5);

/// 抽乾一條 reader channel。**抽不到就是失敗，不得當成「空的」。**
///
/// `recv_timeout` 的 `Err` 若被 `unwrap_or_default()` 吞掉，「stderr 真的是空的」與
/// 「抽不到 stderr」會塌成同一個空 `Vec`，於是 `skipped` 與 `admitted_*` 全部歸零
/// ——「有 1 MiB 以上的 CA bundle 被略過」變成「沒有」、「偵測到卻未建模」恆為 0，
/// 量子閘門對沒掃完的目標回報 `Pass`。那是核心不變量「沒掃到 ≠ 通過」的反面
/// （第八輪複審 finding D）。
///
/// `Disconnected` 同樣算失敗：reader thread 若在 send 之前 panic，我們一樣沒有輸出。
fn drain_or_fail(
    rx: &std::sync::mpsc::Receiver<Vec<u8>>,
    grace: std::time::Duration,
) -> Result<Vec<u8>> {
    rx.recv_timeout(grace).map_err(|_| CytraceError::Cbom {
        key: "cbom.err.drain_timeout",
        detail: Some(grace.as_secs().to_string()),
    })
}

/// 同 [`cbom_with_timeout`]，但另可指定**抽乾寬限**。
///
/// 保持私有：抽乾的 fail-closed 語意由 [`drain_or_fail`] 的四支單元測試直接覆蓋
/// （以永不送值的 channel 觸發），不需要從這裡注入——實測注入 0ms 寬限根本觸發不到，
/// 因為 `recv_timeout` 對已就緒的 channel 立即返回。原本的 doc 聲稱「開放注入只為
/// 讓該路徑可被測試觸發」，而零測試經由它，那句話不成立（第九輪複審）。
/// 穩定優先鐵則下不留無人使用的公開面。
fn cbom_with_timeouts(
    target: &str,
    timeout: std::time::Duration,
    drain_grace: std::time::Duration,
) -> Result<Option<CbomOutput>> {
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

    // **必須併發抽乾 stdout/stderr**：Linux 預設管線容量僅 64 KiB，
    // 子程序寫滿即阻塞在 write()、永不結束，於是逾時輪詢會誤判為「卡住」並殺掉它。
    // 實測（第五輪複審）：60 組憑證的目標輸出 285 KB，theia 單獨跑 5 秒完成，
    // 但改用「輪詢 try_wait 且不讀管線」後卡滿逾時——那是第四輪逾時修補引入的迴歸。
    // 舊實作 `.output()` 內部以 read2 併發抽乾兩條管線，正是防死鎖的機制。
    //
    // 抽乾用 channel 而非 `JoinHandle::join`，因為 **join 沒有上限**：`kill()` 只殺直接
    // 子程序，若有孫程序繼承了管線寫端，`read_to_end` 不會返回、join 就不會返回
    // ——那是把第四輪那個「FIFO 永久掛死」從輪詢處搬到 join 處而已，逾時形同失效
    // （第七輪複審 finding）。改以 `recv_timeout` 給寬限：拿不到就放棄那份 buffer。
    // 阻塞呼叫端（server 的 permit 永不釋放、job 不可取消）遠比洩漏一條讀取執行緒嚴重，
    // 而該執行緒最終會隨孫程序結束而收尾。
    // 實測（2026-09-27）：theia v1.1.2 為靜態 Go binary，dir 模式不 spawn 子程序，
    // 故此路徑目前不可達；此處是防上游行為改變，不是修一個當下的缺陷。
    let (tx_out, rx_out) = std::sync::mpsc::channel::<Vec<u8>>();
    let (tx_err, rx_err) = std::sync::mpsc::channel::<Vec<u8>>();
    let mut stdout_pipe = child.stdout.take();
    let mut stderr_pipe = child.stderr.take();
    std::thread::spawn(move || {
        let mut buf = Vec::new();
        if let Some(p) = stdout_pipe.as_mut() {
            use std::io::Read;
            let _ = p.read_to_end(&mut buf);
        }
        let _ = tx_out.send(buf);
    });
    std::thread::spawn(move || {
        let mut buf = Vec::new();
        if let Some(p) = stderr_pipe.as_mut() {
            use std::io::Read;
            let _ = p.read_to_end(&mut buf);
        }
        let _ = tx_err.send(buf);
    });

    let drain = |rx: &std::sync::mpsc::Receiver<Vec<u8>>| drain_or_fail(rx, drain_grace);

    // 逾時輪詢：逾時即 kill，歸為 Failed（fail-closed，不中止主流程）
    //
    // **每一條 early-return 都必須先收屍**：kill + wait 讓子程序離開，管線關閉後兩條
    // reader 才會結束、才 join 得動。漏掉任一步在 server 長駐情境即為洩漏——theia
    // 變成孤兒繼續吃 CPU/IO，兩條 thread 抱著管線活到它自然結束為止。
    // 逾時與 try_wait 失敗兩條路徑共用同一套清理，避免只修一邊（第六輪複審 finding I：
    // Err 分支原本直接 return，既不 kill 也不 join）。
    let deadline = std::time::Instant::now() + timeout;
    let mut reap = Some(child);
    macro_rules! reap_and_fail {
        ($err:expr) => {{
            if let Some(mut c) = reap.take() {
                let _ = c.kill();
                let _ = c.wait();
                // kill 後管線關閉，兩條 reader 會自行結束並送出 buffer；
                // 送不出來（孫程序持有寫端）時由寬限逾時放行，不阻塞呼叫端
                let _ = drain(&rx_out);
                let _ = drain(&rx_err);
            }
            return Err($err);
        }};
    }
    let status = loop {
        let Some(child) = reap.as_mut() else {
            unreachable!("reap 只在 early return 時取走");
        };
        match child.try_wait() {
            Ok(Some(st)) => break st,
            Ok(None) => {
                if std::time::Instant::now() >= deadline {
                    reap_and_fail!(CytraceError::Cbom {
                        key: "cbom.err.timeout",
                        detail: Some(timeout.as_secs().to_string()),
                    });
                }
                std::thread::sleep(std::time::Duration::from_millis(50));
            }
            // try_wait 失敗（例如 SIGCHLD 被他處收割）→ 同樣要收屍再回報
            Err(e) => reap_and_fail!(CytraceError::Engine(format!("cbomkit-theia: {e}"))),
        }
    };
    // `try_wait` 回 `Ok(Some(_))` 時已經收割過，這次 `wait` 會立即返回；
    // 顯式寫出來是為了讓「不留 zombie」由程式碼本身表明，而非靠讀者推論。
    let mut child = reap.take().expect("正常結束路徑上 reap 必然還在");
    let _ = child.wait();

    // **抽不到就是失敗，不得當成「空的」**：`recv_timeout` 的 `Err(Timeout)` 若被
    // `unwrap_or_default()` 吞掉，「stderr 真的是空的」與「抽不到 stderr」會塌成同一個
    // 空 Vec，於是 `skipped` 與 `admitted_*` 全部歸零——「有 1 MiB 以上的 CA bundle
    // 被略過」變成「沒有」、「偵測到卻未建模」恆為 0，量子閘門對沒掃完的目標回報 Pass。
    // 那是本專案核心不變量「沒掃到 ≠ 通過」的反面，也正是這整段改動要防的情境
    // （第八輪複審 finding D：stdout 側有 `ensure_cbom_json` 攔著，stderr 側原本沒有）。
    let stdout_buf = drain(&rx_out)?;
    let stderr_buf = drain(&rx_err)?;
    let out = std::process::Output {
        status,
        stdout: stdout_buf,
        stderr: stderr_buf,
    };

    // stderr 含「因大小門檻略過」的警告，須在丟棄前清點（見 skipped_file_count）
    let stderr_text = String::from_utf8_lossy(&out.stderr).into_owned();
    let skipped = skipped_file_count(&stderr_text);
    // 引擎自承偵測到的數量，**分類別**記錄（由呼叫端與同類別的實際產出對帳）
    let (admitted_keys, admitted_certs) = admitted_counts(&stderr_text);

    let stdout = check(out, "cbomkit-theia")?;
    ensure_cbom_json(&stdout)?;
    Ok(Some(CbomOutput {
        json: stdout,
        skipped,
        admitted_keys,
        admitted_certs,
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

/// 從 stderr 取出引擎**自承偵測到**的私鑰數與憑證數（ADR-013 決策 10）。
///
/// **必須分類別**：theia 自承「找到 N 把私鑰」，若拿它去扣「憑證 + 私鑰」或「全部資產」
/// 的數量，混合資產目標會被抵銷成 0——實測目錄含 RSA 憑證與 OpenSSH host key 時
/// 自承 2 把私鑰，而建模輸出有 1 憑證 + 1 私鑰，兩種錯誤量綱都會算出 0，
/// 於是閘門回 `Pass`，那把 OpenSSH 金鑰確實沒被建模。
///
/// theia 對它偵測到卻無法建模的資產只在 **stderr** 留痕，stdout 零元件、exit 0。
/// 實測：OpenSSH 格式私鑰走這條路；同一把金鑰改存 PKCS#8 PEM 則會產生資產——
/// **換個檔案格式，閘門答案就從「有脆弱」變成「通過」**。
/// 原則與 oversize 相同：引擎講得出口的漏檢一律要出現在計數裡，寧可多算。
///
/// **兩類的訊息格式不同**（v1.1.2 實測，2026-09-27）：
///
/// ```text
/// msg="Found 1 private key(s) in s.key"
/// msg="Certificate searching done" numberOfDetectedCertificates=1
/// ```
///
/// 憑證**從不**印 `Found N certificate(s)`。原實作只認 `Found ` 前綴，於是 certs 恆為 0，
/// `undetermined_count` 對憑證恆回 0——「偵測到 5 張、只建模 3 張」會算出缺口 0、
/// 閘門回 `Pass`，正是 fail-open（第六輪複審的證據缺口，實測後確認為缺陷）。
pub fn admitted_counts(stderr: &str) -> (u64, u64) {
    let mut keys = 0u64;
    let mut certs = 0u64;
    for line in stderr.lines() {
        // 私鑰：`Found N private key(s) in <path>`
        if let Some(rest) = line.split("Found ").nth(1) {
            let n: u64 = rest
                .split_whitespace()
                .next()
                .and_then(|t| t.parse().ok())
                .unwrap_or(1); // 認不得數字也算一項：寧可多算
            if rest.contains("private key") {
                keys = keys.saturating_add(n);
            }
            // 刻意**不**在此接 `Found N certificate(s)`：theia 不印該格式，而留著它會製造
            // 一條唯一的重複計數路徑——若上游哪天同時印兩種（`msg="Found 3 certificate(s)"
            // numberOfDetectedCertificates=3`），憑證數會變成 6，於是「自承 6 建模 3」
            // 憑空生出 3 項未確定、閘門回 NoResult 假警報（第七輪複審 finding）。
            // 憑證一律只認下方的結構化欄位；欄位改名由 real_engine 案例 13 當場抓到。
        }
        // 憑證：logrus 結構化欄位 `numberOfDetectedCertificates=N`
        if let Some(rest) = line.split("numberOfDetectedCertificates=").nth(1) {
            let n: u64 = rest
                .split_whitespace()
                .next()
                .and_then(|t| t.trim_matches('"').parse().ok())
                .unwrap_or(1); // 認不得數字也算一項：寧可多算
            certs = certs.saturating_add(n);
        }
    }
    (keys, certs)
}

/// 單一類別的未確定數：引擎自承數扣除實際建模數。
pub fn undetermined_count(admitted: u64, modelled: u64) -> u64 {
    admitted.saturating_sub(modelled)
}

/// 驗證 theia stdout 為合法 JSON（ADR-013 決策 10）。
///
/// `HOME` 不可寫時 theia 會把警告印到 **stdout** 汙染輸出；輸入不可讀時則 **stdout 空白且 exit 0**。
/// 兩種情形都**不得**被當成「掃到 0 項」——一律視為失敗。
pub fn ensure_cbom_json(stdout: &str) -> Result<&str> {
    if stdout.trim().is_empty() {
        return Err(CytraceError::Cbom {
            key: "cbom.err.empty_output",
            detail: None,
        });
    }
    let v: serde_json::Value = serde_json::from_str(stdout).map_err(|e| CytraceError::Cbom {
        key: "cbom.err.stdout_not_json",
        detail: Some(e.to_string()),
    })?;
    // 光是「合法 JSON」不夠：`{}` 也會通過，然後被當成「掃到 0 項」——又是一個 fail-open。
    // 必須確認這確實是一份 CycloneDX BOM。
    let is_cyclonedx = v.get("bomFormat").and_then(|b| b.as_str()) == Some("CycloneDX")
        && v.get("specVersion").is_some();
    if !is_cyclonedx {
        return Err(CytraceError::Cbom {
            key: "cbom.err.not_cyclonedx",
            detail: None,
        });
    }
    Ok(stdout)
}

fn check(out: std::process::Output, name: &str) -> Result<String> {
    if out.status.success() {
        Ok(String::from_utf8_lossy(&out.stdout).into_owned())
    } else {
        Err(CytraceError::Engine(format!(
            "{name} exit {:?}: {}",
            out.status.code(),
            String::from_utf8_lossy(&out.stderr).trim()
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 序列化所有改動**行程全域 cwd** 的測試。
    ///
    /// `std::env::set_current_dir` 是行程層級的，而 `cargo test` 預設多執行緒平行跑：
    /// 兩個測試交錯設定 cwd 時，`cbom_target("nginx")` 會在對方的目錄裡解析而找不到檔案，
    /// 回報 `cbom.err.target_not_local`。實測為 flaky——同一份程式碼一次紅、接著連三次綠
    /// （第十一輪取證時撞到）。
    ///
    /// 隨機紅的測試比沒有測試更糟：它會訓練讀者把紅燈解釋成「又是那個 flaky」，
    /// 於是真的缺陷也被同一句話蓋過去。
    static CWD_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    // ── DB 快照解析（NFR-03 稽核欄位；曾為硬編碼假值）──

    /// **這段 stdout 是 grype v0.114 的真實輸出**（2026-09-29 實地抓取，未經改寫）。
    /// 憑證計數那課的教訓：想像的 fixture 會長成想像的樣子。
    #[test]
    fn db_status_is_parsed_from_the_real_grype_output() {
        let real = r#"{
 "schemaVersion": "v6.1.9",
 "from": "https://grype.anchore.io/databases/v6/vulnerability-db_v6.1.9_2026-09-23T00:31:12Z_1790145099.tar.zst?checksum=sha256%3A93487281c93d3cb3649878932ff9003991b607136b14cb0943b74846bfd611a8",
 "built": "2026-09-23T06:31:39Z",
 "path": "/home/ubuntu/.cache/grype/db/6/vulnerability.db",
 "valid": false,
 "error": "the vulnerability database was built 5 days ago (max allowed age is 5 days)"
}"#;
        let snap = parse_db_status(Some(real));
        assert_eq!(snap.version, "v6.1.9");
        assert_eq!(snap.built, "2026-09-23T06:31:39Z");
        // `valid:false` 不影響稽核標示：時效判斷是稽核者的事，我們負責如實轉錄
    }

    #[test]
    fn db_status_failure_is_an_explicit_sentinel_not_a_fake_value() {
        // 失敗不得假裝有值——那正是本欄位過去的樣子（硬編碼 "snapshot"/"unknown"，
        // SOP 宣稱的時效稽核控制因此實質不存在）
        for bad in [
            None,
            Some(""),
            Some("not json"),
            Some("{}"),
            Some(r#"{"schemaVersion":"v6"}"#),           // 缺 built
            Some(r#"{"schemaVersion":"","built":"x"}"#), // 空字串視同缺
        ] {
            let snap = parse_db_status(bad);
            assert_eq!(snap.version, "unavailable", "輸入 {bad:?}");
            assert_eq!(snap.built, "unavailable");
        }
    }

    // ── 抽乾：抽不到不得當成「空的」（第八輪複審 finding D）──

    #[test]
    fn drain_timeout_is_an_error_not_an_empty_buffer() {
        // 永不送值的 channel：等同「管線寫端仍被孫程序持有」
        let (_tx, rx) = std::sync::mpsc::channel::<Vec<u8>>();
        let r = drain_or_fail(&rx, std::time::Duration::from_millis(10));
        match r {
            Err(CytraceError::Cbom { key, detail }) => {
                assert_eq!(key, "cbom.err.drain_timeout");
                assert!(detail.is_some(), "須帶寬限秒數供操作員判讀");
            }
            Err(other) => panic!("應為 drain_timeout，實為 {other:?}"),
            Ok(buf) => panic!(
                "抽不到卻回報成功（{} bytes）——空 buffer 會讓 skipped / admitted_* 歸零，\n\
                 量子閘門於是對沒掃完的目標回報 Pass（fail-open）",
                buf.len()
            ),
        }
    }

    #[test]
    fn drain_returns_the_buffer_when_the_reader_finishes() {
        let (tx, rx) = std::sync::mpsc::channel::<Vec<u8>>();
        tx.send(b"Skipping large file: ca.pem (exceeds limit of 1048576 bytes)".to_vec())
            .unwrap();
        let buf = drain_or_fail(&rx, std::time::Duration::from_secs(1)).expect("應成功");
        assert!(!buf.is_empty(), "已就緒的 buffer 須原樣取回");
    }

    #[test]
    fn genuinely_empty_stderr_is_not_an_error() {
        // 「真的空」與「抽不到」必須分得出來：前者合法（乾淨目標無警告）
        let (tx, rx) = std::sync::mpsc::channel::<Vec<u8>>();
        tx.send(Vec::new()).unwrap();
        let buf = drain_or_fail(&rx, std::time::Duration::from_secs(1)).expect("空輸出仍是成功");
        assert!(buf.is_empty());
    }

    #[test]
    fn dead_reader_thread_is_a_failure() {
        // reader 在 send 之前 panic → Disconnected，一樣沒有輸出，不得當成空
        let (tx, rx) = std::sync::mpsc::channel::<Vec<u8>>();
        drop(tx);
        assert!(
            drain_or_fail(&rx, std::time::Duration::from_secs(1)).is_err(),
            "reader 掛掉時不得回報空輸出"
        );
    }

    // ── 逾時設定解析（不得存在「無逾時」這個可達狀態）──

    #[test]
    fn timeout_falls_back_to_default_for_invalid_values() {
        // 0 不是「無限制」——無逾時正是 FIFO 永久阻塞、server 停擺的成因
        assert_eq!(parse_timeout_secs(Some("0")), CBOM_TIMEOUT_SECS_DEFAULT);
        assert_eq!(parse_timeout_secs(Some("-1")), CBOM_TIMEOUT_SECS_DEFAULT);
        assert_eq!(parse_timeout_secs(Some("abc")), CBOM_TIMEOUT_SECS_DEFAULT);
        assert_eq!(parse_timeout_secs(Some("")), CBOM_TIMEOUT_SECS_DEFAULT);
        assert_eq!(parse_timeout_secs(None), CBOM_TIMEOUT_SECS_DEFAULT);
    }

    #[test]
    fn timeout_accepts_positive_values() {
        assert_eq!(parse_timeout_secs(Some("30")), 30);
        assert_eq!(parse_timeout_secs(Some(" 45 ")), 45);
        assert_eq!(parse_timeout_secs(Some("86400")), CBOM_TIMEOUT_SECS_MAX);
    }

    #[test]
    fn timeout_rejects_values_that_would_panic_on_instant_add() {
        // u64::MAX 秒能通過 parse 與 >0，但 `Instant::now() + Duration` 依定義會 panic
        // ——那不是「很大的逾時」而是 job thread 崩潰（第七輪複審 finding）
        assert_eq!(
            parse_timeout_secs(Some("18446744073709551615")),
            CBOM_TIMEOUT_SECS_DEFAULT
        );
        assert_eq!(
            parse_timeout_secs(Some("86401")),
            CBOM_TIMEOUT_SECS_DEFAULT,
            "超過上限須回退，不得放行"
        );
        // 上限值本身仍可加到 Instant 上而不 panic（釘住上限選得夠保守）
        let d = std::time::Duration::from_secs(CBOM_TIMEOUT_SECS_MAX);
        assert!(std::time::Instant::now().checked_add(d).is_some());
    }

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
        let _g = CWD_LOCK.lock().unwrap_or_else(|e| e.into_inner());
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
        let _g = CWD_LOCK.lock().unwrap_or_else(|e| e.into_inner());
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
