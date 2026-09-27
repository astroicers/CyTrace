//! 領域錯誤分類（SDS §5；result_type 慣例）。

use thiserror::Error;

/// CyTrace 核心錯誤。退出碼語意見 CLI：`0` 正常 / `2` fail-on 觸發 / 其他非 0 為錯誤。
#[derive(Debug, Error)]
pub enum CytraceError {
    /// 子程序（Syft/Grype）失敗或找不到 binary。
    #[error("引擎子程序錯誤：{0}")]
    Engine(String),

    /// JSON 解析失敗（grype / CycloneDX）。
    #[error("解析錯誤：{0}")]
    Parse(String),

    /// I/O 錯誤。
    #[error("I/O 錯誤：{0}")]
    Io(#[from] std::io::Error),

    /// 設定錯誤（如缺漏必要參數）。
    #[error("設定錯誤：{0}")]
    Config(String),

    /// CBOM 錯誤：攜帶**純 i18n 鍵**與不可翻譯的細節（路徑、秒數）。
    ///
    /// 與 [`CytraceError::Engine`] / [`CytraceError::Parse`] 分開，是為了讓呼叫端能依
    /// 語系渲染——把鍵與中文散文黏成一個字串的話，`--lang en-US` 會吐中文，
    /// 且該字串會寫進 `scan-result.json` 並經 API 對外（違反 i18n 雙語強制鐵則）。
    #[error("{key}{}", detail.as_ref().map(|d| format!("：{d}")).unwrap_or_default())]
    Cbom {
        /// i18n 鍵（如 `cbom.err.timeout`），**不含散文**。
        key: &'static str,
        /// 不可翻譯的細節（目標路徑、逾時秒數）；插值用。
        detail: Option<String>,
    },

    /// 離線漏洞 DB 快照缺失（ADR-003）。
    #[error("漏洞資料庫快照缺失：{0}")]
    DbMissing(String),
}

impl CytraceError {
    /// 取出**不含本型別中文散文**的細節，供需要依語系渲染的呼叫端使用。
    ///
    /// 每個變體的 `Display` 都帶一段中文前綴（「引擎子程序錯誤：」…）。
    /// 那段前綴若混進 `CbomStatus::reason_detail` 或 API 的 `detail`，就會寫進
    /// `scan-result.json` 並對外，`--lang en-US` 下照樣吐中文——違反 i18n 雙語強制鐵則。
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
