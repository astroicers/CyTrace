//! CyTrace Web 服務模式（ADR-011）。
//!
//! 由 CLI 的 `serve` 子命令進入：[`serve`] 自建 tokio runtime（CLI main 保持同步）。
//! 請求路徑禁 panic（`panic=abort` 下 panic = 整個服務終止，crash-only 設計）——
//! 以 clippy `unwrap_used`/`expect_used` deny 機械強制。

#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used))]

pub mod api;
pub mod archive;
pub mod auth;
pub mod config;
pub mod error;
pub mod extract;
pub mod jobs;
pub mod router;
pub mod session;
pub mod state;
pub mod static_files;
pub mod targets;
pub mod tls;
pub mod upload;

use config::ServerConfig;
use cytrace_i18n::Localized;
use std::net::SocketAddr;
use std::time::Duration;

/// 啟動 HTTP/HTTPS 服務（阻塞直到收到中止訊號）。`lang` 是操作者語言（CLI 的 `--lang`／
/// `CYTRACE_LANG`）：決定啟動、關閉與執行期終端機訊息的語言；錯誤以 [`Localized`] 回傳，
/// 由 CLI 以同一語言渲染。
pub fn serve(mut cfg: ServerConfig, lang: &str) -> Result<(), Localized> {
    cfg.lang = error::Lang::from_code(lang);
    let cat = cfg.lang.catalog();
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|e| {
            Localized::new("server.startup.runtime_failed").var("detail", e.to_string())
        })?;
    rt.block_on(async {
        let app =
            router::build_router(cfg.clone())?.into_make_service_with_connect_info::<SocketAddr>();
        let handle = axum_server::Handle::new();

        // ctrl_c → graceful shutdown（10s 寬限）
        tokio::spawn({
            let handle = handle.clone();
            let msg = cat.t("server.shutdown", &[]);
            async move {
                if tokio::signal::ctrl_c().await.is_ok() {
                    println!("{msg}");
                    handle.graceful_shutdown(Some(Duration::from_secs(10)));
                }
            }
        });

        // 監聽位址確定後印出（含 :0 隨機 port 的實際值）
        tokio::spawn({
            let handle = handle.clone();
            async move {
                if let Some(addr) = handle.listening().await {
                    println!(
                        "{}",
                        cat.t("server.listening", &[("addr", &addr.to_string())])
                    );
                }
            }
        });

        // 綁定失敗（位址占用、權限不足）與執行中的致命 I/O 錯誤都從這裡出來
        let listen_failed = |e: std::io::Error| {
            Localized::new("server.startup.listen_failed")
                .var("addr", cfg.bind.to_string())
                .var("detail", e.to_string())
        };
        match &cfg.tls {
            Some(paths) => {
                let rustls_cfg = tls::rustls_config(paths).await?;
                axum_server::bind_rustls(cfg.bind, rustls_cfg)
                    .handle(handle)
                    .serve(app)
                    .await
                    .map_err(listen_failed)?;
            }
            None => {
                println!("{}", cat.t("server.plaintext_warning", &[]));
                axum_server::bind(cfg.bind)
                    .handle(handle)
                    .serve(app)
                    .await
                    .map_err(listen_failed)?;
            }
        }
        Ok(())
    })
}
