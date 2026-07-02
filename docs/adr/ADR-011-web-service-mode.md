# [ADR-011]: Web 服務模式（`cytrace serve`）——場域內集中掃描伺服器與登入控制台

| 欄位 | 內容 |
|------|------|
| **狀態** | `Draft` |
| **接受日期** | — |
| **日期** | 2026-07-02 |
| **決策者** | CyTrace Team |

> **狀態說明：** `Draft`（初稿，禁止實作）→ `FIRM`（POC 驗證，允許 commit，需附驗證證據）→ `Accepted`（人類審核通過）

---

## 背景（Context）

CyTrace 目前是單機 CLI（`run/batch/scan/report`）。使用者需求：**簡易網站登入介面 + UI 操作介面**，
登入後可操作系統所有功能（掃描、批次、報表管理），並以 Docker 容器交付（容器交付另立 ADR-012）。

使用場景由「單機 CLI」擴張為「**場域內集中掃描伺服器**」：操作者透過瀏覽器（LAN 內）登入，
上傳掃描目標或選擇伺服器掛載目錄，伺服器執行 Syft/Grype 管線並管理報表產物。

**產品決策已由使用者確認：**
1. 掃描目標進入方式：**上傳檔案/壓縮包 + 掛載目錄（volume）兩者都要**
2. 認證：**單一管理帳號**（軍用封閉網路，無外部 IdP / LDAP）
3. TLS：**支援自帶憑證**（預設 HTTP；掛 PEM 憑證/金鑰啟 HTTPS；不做 ACME——零外連）

**與鐵則的關係：**
- 「零外連」指 **outbound**；在 LAN 內**監聽 inbound** 不違反。整棵依賴樹不得出現 HTTP client（機械可驗）。
- **NFR-09（信任邊界）須顯式修訂**：原文「掃描目標與原始碼不離開目標機」→ 上傳路徑使掃描目標首次離開目標機、
  傳至**同場域**掃描伺服器。本 ADR 提議 SRS 修訂文字見「後果」節；不可默默放寬。

## 評估選項（Options Considered）

### 選項 A：新 lib crate `cytrace-server`（axum/tokio）+ cli 新增 `serve` 子命令，維持單一 binary（採用）
- **優點**：交付/簽章/SHA256SUMS 流程零改動（ADR-007/010 不動）；types/core/report 程式碼共用最大化；
  lib crate 可用 `tower::ServiceExt::oneshot` 做整合測試；cli 以 cargo feature `server`（default on）掛載，
  `cargo build --no-default-features` 可重建**零 tokio 純 CLI**——CLI 零迴歸的結構性保證。
- **缺點**：依賴樹由 35 locked packages 估增至 ~150–200（tokio/axum 生態）；binary 估增 3–6 MB。
- **風險**：`panic=abort`（workspace release profile）下任一 handler panic = 整個服務終止 → 以 crash-only 設計吸收（見後果）。

### 選項 B：獨立 `cytraced` 第二 binary
- **優點**：CLI binary 完全不變、大小不變。
- **缺點**：交付物翻倍（雙簽章、雙 SHA256SUMS、ADR-010 matrix ×2）；types/core 雙 binary 版本漂移風險；
  違反「單一靜態 binary」交付哲學（NFR-04）。

### 選項 C：不做常駐服務——批次 CLI + 排程 + 共享目錄收報表
- **優點**：零新依賴、零新攻擊面。
- **缺點**：無上傳路徑、無隨需掃描、無登入 UI，不符使用者明確需求。

### 選項 D：同步 HTTP 框架（tiny_http/rouille）免 tokio
- **優點**：依賴樹較小。
- **缺點**：multipart 串流、TLS、graceful shutdown 生態薄弱，需大量自造輪子；長期維護風險高於 axum（tokio 官方系、審查面集中）。

## 決策（Decision）

採用 **選項 A**。要點：

1. **Crate 佈局**：新增 `crates/cytrace-server`（lib）；`cytrace-cli` 以 feature `server`（default on）掛
   `serve` / `hash-password` / `health` 子命令。前置重構（零行為變更）：`engine.rs` 由 cli 搬至 core
   （SDS §2 本應如此）並引入 `ScanEngine` trait 測試縫；i18n Catalog 由 cli 搬至新 crate `cytrace-i18n`（cli/server 共用）。
2. **新依賴**（Cargo.lock 釘死 + `cargo vendor` + 新增 `deny.toml`：license 白名單 Apache-2.0/MIT/ISC/BSD/Zlib/Unicode、
   來源僅 crates.io，進 CI）：tokio（features 最小化）、axum 0.8（+multipart）、axum-server（rustls）、
   rustls（**ring** provider；ring 授權混合 ISC/BoringSSL，NOTICE 標註，審查不過改 aws-lc-rs）、rustls-pemfile、
   argon2、getrandom、zip、tar、flate2（rust_backend）、rust-embed（服務 console 靜態資產）。
   **明確禁止**：任何 HTTP client（reqwest/hyper-client 類——零外連的機械保證，CI 以 `cargo tree` 檢查）、
   資料庫（ROADMAP `database: none`）、chrono/uuid（用既有 `epoch_to_iso` 與 getrandom hex）。
3. **認證**：單一管理帳號。`CYTRACE_ADMIN_PASSWORD_HASH`（argon2id PHC 字串；缺失或格式錯 → 拒絕啟動）；
   `cytrace hash-password` 離線產 hash。Session：32B CSPRNG token（伺服端存 SHA-256），
   cookie `HttpOnly; SameSite=Strict`（TLS 時 +`Secure`），TTL 12h 絕對過期，in-memory（重啟即全登出）。
   登入節流 per-IP 5 次/15 分 + 全域 20 次/15 分。CSRF：SameSite=Strict + 變更型請求強制自訂標頭
   `X-CyTrace-Request: 1` + 全站不啟用 CORS。
4. **Job 模型**（無資料庫）：`tokio::task::spawn_blocking` 包既有同步管線；`Semaphore` 限併發（預設 2）、
   佇列上限 32；狀態機 `queued → running → done/failed`（+`canceled`/`interrupted`）；
   `{data_dir}/jobs/<id>/{job.json, input/, sbom.cdx.json, grype.json, scan-result.json, report.html}`，
   job.json 以 tmp+rename 原子落盤；重啟走訪重建索引、非終態→`interrupted`。
   `failon_triggered` 是**狀態非錯誤**（≙ CLI exit 2 語意）。
5. **上傳安全**：multipart 串流落盤（預設上限 512MB，`CYTRACE_MAX_UPLOAD_MB`）；zip/tar/tar.gz 解壓三道防護——
   zip-slip（zip `enclosed_name()`；tar 逐 component 拒 `..`/絕對路徑/Prefix，違規**整包拒收**）、
   symlink/hardlink entry 一律跳過、zip-bomb（entry 數 + 單檔 + 總解壓量三重上限，只信實際解出 bytes）。
   掃描完成後 input 預設刪除（`CYTRACE_KEEP_INPUT=false`）——縮小機密資料駐留窗。
6. **掛載掃描**：`CYTRACE_SCAN_ROOTS=name=path,...` 白名單；先語彙檢查（拒 `..`/絕對路徑）再
   `canonicalize` + 前綴驗證（擋 symlink 逃逸）；違規一律 403 並記稽核 log。
7. **API**：`/api/v1`（session/targets/jobs/jobs upload/report/result/artifacts/version）+ `/healthz`（無 auth）。
   語言協商 `?lang=` > `Accept-Language` > `zh-TW`；錯誤格式 `{error:{kind, i18n_key, message, detail}}`
   沿用 CytraceError 5 類 + server 新增類；所有使用者可見訊息走 locales 鍵（`server.*` 命名空間，NFR-06 延伸）。
8. **前端 console**：單一 frontend 專案**雙 Vite config**——`vite.config.ts`（report 樣板，**一個位元組不改**）+
   `vite.console.config.ts`（console SPA，無 singlefile）。自寫 hash routing（~60 行，不引 react-router）、
   不引 Zustand/SWR（fetch wrapper + setTimeout 鏈輪詢 + XHR 上傳進度）。產物 commit 至
   `crates/cytrace-server/assets/console/`（rust-embed），與 report-template 策略一致。
   Console CSP 由 axum header 下發：`default-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline';
   connect-src 'self'; img-src 'self' data:; form-action 'self'; frame-ancestors 'none'`。
   報表檢視另開分頁（沿用報表自帶 `connect-src 'none'` CSP）。locales 新增 `console.*` 命名空間。
9. **TLS**：`CYTRACE_TLS_CERT`/`CYTRACE_TLS_KEY`（或 CLI 旗標）載入 PEM → rustls；未設 TLS 啟動時以 i18n 鍵警告明文模式。

### 提議之 SRS NFR-09 修訂文字（隨本 ADR 核准後落稿）

> 掃描目標與原始碼**不離開目標場域**。單機模式維持「不離開目標機」；Web 服務模式允許操作者將目標
> 上傳至**同場域內**的 CyTrace 掃描伺服器（傳輸建議啟用 TLS），上傳內容僅落於伺服器受控資料目錄、
> 掃描完成後預設刪除；報表僅含依賴與弱點元資料。任何資料不出場域（SaaS 收 SBOM 仍為範圍外）。

## 後果（Consequences）

**正面影響：**
- 新增場域內集中掃描與瀏覽器操作能力，覆蓋「登入後可操作所有功能」需求；CLI 交付路線與簽章流程不變。
- feature gate + 前置重構讓 CLI 可獨立退回零 tokio build，迴歸風險受控。

**負面影響 / 技術債：**
- **攻擊面擴大**：新增網路監聽（登入、上傳解壓、路徑解析三大向量）——以本 ADR §3/§5/§6 設計約束，
  且 security review 進 ship gate；server crate clippy 加 `unwrap_used` deny（請求路徑禁 panic）。
- **供應鏈**：直接依賴 5→~14、locked 35→~150–200；以 cargo deny + vendor + dogfooding SBOM + NOTICE 收斂。
- **crash-only**：`panic=abort` 不為 server 改動；panic = 進程終止，由容器 restart policy 補位，
  重啟後非終態 job 標 `interrupted`（不自動重跑，確定性優先）。
- **NFR-09 放寬**：上傳使目標離開目標機（仍在場域內）；SRS 修訂 + input 掃後即刪 + TLS 建議作為緩解。
- in-memory session：重啟全登出（單一管理員可接受，符合無 DB 哲學）。

**後續追蹤：**
- SDS 新增 server 章節；SRS NFR-09 修訂落稿（本 ADR Accepted 後）。
- Windows 平台（ADR-010）：serve 僅以 Linux 容器交付，但 Windows build 須維持全 feature 編譯通過（CI matrix 既有 job 涵蓋）。

## 成功指標（Success Metrics）

| 指標 | 目標值 | 驗證方式 | 檢查時間 |
|------|--------|----------|----------|
| CLI 零迴歸 | `cargo test --workspace` 全綠、golden 不變 | CI | 每次 push |
| 純 CLI 可退 | `cargo build --no-default-features -p cytrace-cli` 成功且無 tokio | CI/本機 | PR2 起 |
| 供應鏈守門 | `cargo deny check licenses sources` 綠；依賴樹無 HTTP client | CI（`cargo tree` grep 空） | 每次 push |
| 上傳安全 | 惡意壓縮包（zip-slip/symlink/bomb）測試全拒 | `cytrace-server` 整合測試 | 每次 push |
| 路徑防護 | `../`、絕對路徑、symlink 逃逸 → 403 | 單元 + 整合測試 | 每次 push |
| 斷網可用 | 斷網環境登入→上傳→掃描→報表全流程通 | 手動驗收清單 | M8 驗收 |
| i18n 完整 | `scripts/i18n-check.py` 綠（`server.*`+`console.*` 成對） | CI | 每次 push |

## 關聯（Relations）

- 擴充：ADR-001（技術棧：Rust + React）、ADR-005（報表單檔架構——report 樣板 build 契約不動）、
  ADR-009（ScanResult 稽核產物——server 直接沿用）、ADR-006（fail-on 語意 → `failon_triggered` 狀態）
- 不動：ADR-007（裸機交付與簽章流程零改動——單一 binary 讓 SHA256SUMS/minisign 流程照舊）
- 配套：ADR-012（容器化交付與 GHCR——本功能的主要交付形態）
- 修訂：SRS NFR-09（信任邊界）；SDS §2（engine 歸位 core）
- 參考：ROADMAP M8（T801–T809）
