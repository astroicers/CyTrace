//! CyTrace Web 服務模式（ADR-011）。
//!
//! 由 CLI 的 `serve` 子命令進入：[`serve`] 自建 tokio runtime（CLI main 保持同步）。
//! 請求路徑禁 panic（`panic=abort` 下 panic = 整個服務終止，crash-only 設計）——
//! 以 clippy `unwrap_used`/`expect_used` deny 機械強制。

#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used))]

pub mod auth;
pub mod config;
pub mod error;
pub mod router;
pub mod state;

use config::ServerConfig;
use cytrace_i18n::Catalog;

/// 啟動 HTTP 服務（阻塞直到收到中止訊號）。`lang` 決定啟動訊息語言（沿用 CLI `--lang`）。
pub fn serve(cfg: ServerConfig, lang: &str) -> anyhow::Result<()> {
    let cat = Catalog::load(lang);
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    rt.block_on(async {
        let listener = tokio::net::TcpListener::bind(cfg.bind).await?;
        let addr = listener.local_addr()?;
        println!(
            "{}",
            cat.t("server.listening", &[("addr", &addr.to_string())])
        );
        let app = router::build_router(cfg);
        axum::serve(listener, app)
            .with_graceful_shutdown(shutdown_signal(cat))
            .await?;
        Ok(())
    })
}

async fn shutdown_signal(cat: Catalog) {
    // ctrl_c 失敗（極罕見的 signal handler 註冊錯誤）時不掛服務，改為永不觸發 graceful path。
    if tokio::signal::ctrl_c().await.is_ok() {
        println!("{}", cat.t("server.shutdown", &[]));
    }
}
