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
    let runtime_failed = |e: std::io::Error| {
        Localized::new("server.startup.runtime_failed").var("detail", e.to_string())
    };
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(runtime_failed)?;
    rt.block_on(async {
        // 中止訊號在綁定位址**之前**就掛好：listening 行印出後按下的 Ctrl-C 一定接得到。
        // 原本 `ctrl_c()` 在 spawn 出的 task 第一次被 poll 時才註冊，與 listening 行沒有先後
        // 保證——剛印出就按的 Ctrl-C 可能直接殺掉行程（未優雅關閉）或被吞掉（T912 複審 newgates#5
        // 以負載實測重現）
        let mut interrupt = interrupt_signal().map_err(runtime_failed)?;

        let app =
            router::build_router(cfg.clone())?.into_make_service_with_connect_info::<SocketAddr>();
        let handle = axum_server::Handle::<SocketAddr>::new();

        // 中止訊號 → graceful shutdown（10s 寬限）
        tokio::spawn({
            let handle = handle.clone();
            let msg = cat.t("server.shutdown", &[]);
            async move {
                if interrupt.recv().await.is_some() {
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

/// 中止訊號（Ctrl-C）。**同步**註冊：回傳時 handler 已經掛上。
#[cfg(unix)]
fn interrupt_signal() -> std::io::Result<tokio::signal::unix::Signal> {
    tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())
}

/// 中止訊號（Ctrl-C）。**同步**註冊：回傳時 handler 已經掛上。
#[cfg(windows)]
fn interrupt_signal() -> std::io::Result<tokio::signal::windows::CtrlC> {
    tokio::signal::windows::ctrl_c()
}
