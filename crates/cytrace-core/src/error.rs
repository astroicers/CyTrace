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

    /// 離線漏洞 DB 快照缺失（ADR-003）。
    #[error("漏洞資料庫快照缺失：{0}")]
    DbMissing(String),
}

/// core 統一回傳型別。
pub type Result<T> = std::result::Result<T, CytraceError>;
