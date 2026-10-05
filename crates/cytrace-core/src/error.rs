//! 領域錯誤分類（SDS §5；result_type 慣例）。

use thiserror::Error;

/// CyTrace 核心錯誤。退出碼語意見 CLI：`0` 正常 / `2` fail-on 觸發 / 其他非 0 為錯誤。
///
/// **`Display` 是語系中立的 ASCII 診斷**（`engine: …`），不是給使用者看的訊息。
/// 使用者可見的文字一律由呼叫端以 [`CytraceError::i18n_key`] 加
/// [`CytraceError::untranslatable_detail`] 依語系渲染（CLI、server 皆然；T912）。
/// 原本每個變體都帶中文前綴，`--lang en-US` 下經 `to_string()` 漏出的路徑實測有兩條。
#[derive(Debug, Error)]
pub enum CytraceError {
    /// 子程序（Syft/Grype）失敗或找不到 binary。
    #[error("engine: {0}")]
    Engine(String),

    /// JSON 解析失敗（grype / CycloneDX）。
    #[error("parse: {0}")]
    Parse(String),

    /// I/O 錯誤。
    #[error("io: {0}")]
    Io(#[from] std::io::Error),

    /// 設定錯誤（如缺漏必要參數）。
    #[error("config: {0}")]
    Config(String),

    /// CBOM 錯誤：攜帶**純 i18n 鍵**與不可翻譯的細節（路徑、秒數）。
    ///
    /// 與 [`CytraceError::Engine`] / [`CytraceError::Parse`] 分開，是為了讓呼叫端能依
    /// 語系渲染——把鍵與中文散文黏成一個字串的話，`--lang en-US` 會吐中文，
    /// 且該字串會寫進 `scan-result.json` 並經 API 對外（違反 i18n 雙語強制鐵則）。
    #[error("{key}{}", detail.as_ref().map(|d| format!(": {d}")).unwrap_or_default())]
    Cbom {
        /// i18n 鍵（如 `cbom.err.timeout`），**不含散文**。
        key: &'static str,
        /// 不可翻譯的細節（目標路徑、逾時秒數）；插值用。
        detail: Option<String>,
    },

    /// 離線漏洞 DB 快照缺失（ADR-003）。
    #[error("db snapshot missing: {0}")]
    DbMissing(String),
}

impl CytraceError {
    /// 錯誤分類（持久化於 `JobError.kind`，亦為 `server.err.{kind}` 的後綴）。
    pub fn kind(&self) -> &'static str {
        match self {
            CytraceError::Engine(_) => "engine",
            CytraceError::Parse(_) => "parse",
            CytraceError::Io(_) => "io",
            CytraceError::Config(_) => "config",
            CytraceError::DbMissing(_) => "db_missing",
            CytraceError::Cbom { .. } => "cbom",
        }
    }

    /// 可翻譯的鍵。`Cbom` 用自己的成因鍵（`cbom.err.*`）；其餘為 `server.err.{kind}`
    /// ——鍵名沿用 server 命名空間（CLI 與 server 共用同一組文案，不另開一套同義鍵）。
    ///
    /// 不用 `format!("server.err.{}", self.kind())`：回傳 `&'static str` 讓呼叫端可直接
    /// 放進 `Localized`，也讓 i18n-check 看得到每一個鍵的字面值。
    pub fn i18n_key(&self) -> &'static str {
        match self {
            CytraceError::Engine(_) => "server.err.engine",
            CytraceError::Parse(_) => "server.err.parse",
            CytraceError::Io(_) => "server.err.io",
            CytraceError::Config(_) => "server.err.config",
            CytraceError::DbMissing(_) => "server.err.db_missing",
            CytraceError::Cbom { key, .. } => key,
        }
    }

    /// 取出**不含本型別散文**的細節，供需要依語系渲染的呼叫端使用。
    ///
    /// 不用 `to_string()`：`Display` 帶分類前綴（`engine: …`），`Cbom` 的 `Display` 更是
    /// 「鍵: 細節」——混進 `CbomStatus::reason_detail` 或 API 的 `detail` 就會寫進
    /// `scan-result.json` 並對外。T912 之前那段前綴還是中文，`--lang en-US` 下照樣吐中文。
    ///
    /// 第六輪只在單一呼叫端 match 了 `Engine|Parse|Config` 三個變體，`Io` 與 `DbMissing`
    /// 落到 `_ => to_string()` 而繼續帶中文（第七輪複審指認，可達路徑：
    /// `engine::cbom` 裡 `TempDir::new()?` 的 io 錯誤經 `#[from]` 變成 `Io`）。
    /// 改在型別上提供單一出口，新增變體時編譯器會要求在此表態，呼叫端不必各自記得。
    ///
    /// `std::io::Error` 與路徑字串本身不是我們的散文（前者為系統訊息），故原樣帶出。
    pub fn untranslatable_detail(&self) -> Option<String> {
        match self {
            CytraceError::Engine(msg)
            | CytraceError::Parse(msg)
            | CytraceError::Config(msg)
            | CytraceError::DbMissing(msg) => Some(msg.clone()),
            CytraceError::Io(e) => Some(e.to_string()),
            CytraceError::Cbom { detail, .. } => detail.clone(),
        }
    }
}

/// core 統一回傳型別。
pub type Result<T> = std::result::Result<T, CytraceError>;
