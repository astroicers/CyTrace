//! TLS：自帶 PEM 憑證載入（ADR-011；零外連——無 ACME）。
//!
//! crypto provider 用 **ring**（musl / windows-msvc 皆可建、免 cmake；授權標註見 NOTICE）。

use crate::config::TlsPaths;
use axum_server::tls_rustls::RustlsConfig;

/// 安裝 ring CryptoProvider（幂等）並載入 PEM 憑證/金鑰。
pub async fn rustls_config(paths: &TlsPaths) -> anyhow::Result<RustlsConfig> {
    // 已安裝（如重複呼叫）時回 Err——安全忽略
    let _ = rustls::crypto::ring::default_provider().install_default();
    RustlsConfig::from_pem_file(&paths.cert, &paths.key)
        .await
        .map_err(|e| {
            anyhow::anyhow!(
                "TLS 憑證載入失敗（cert={}, key={}）：{e}",
                paths.cert.display(),
                paths.key.display()
            )
        })
}
