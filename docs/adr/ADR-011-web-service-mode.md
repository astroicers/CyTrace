# [ADR-011]: Web 服務模式（`cytrace serve`）——場域內集中掃描伺服器與登入控制台

| 欄位 | 內容 |
|------|------|
| **狀態** | `Accepted` |
| **接受日期** | 2026-07-02（使用者確認直升，跳過 FIRM POC——風險已明示並由 PR2/PR8 實作即時回驗） |
| **日期** | 2026-07-02 |
| **決策者** | CyTrace Team |

> **狀態說明：** `Draft`（初稿，禁止實作）→ `FIRM`（POC 驗證，允許 commit，需附驗證證據）→ `Accepted`（人類審核通過）

> ⬆️ 由 `Draft` 升 `Accepted`：使用者 2026-07-02 透過 `/asp:approve-adr ADR-011` 呼叫、看完指令摘要
> （決策重點、無 Verification Evidence 章節之事實、Draft 直升跳過 FIRM POC 的風險提示）與升級當下
> 既有佐證（G1 gate 審查 `.asp-gate-log/20260702T054319Z-G1-ADR-011.md` CONDITIONAL PASS 且發現已修復）
> 後回覆「確認直升」明確同意（人類顯式授權，非 AI 自行升級，符合 ADR 狀態變更鐵則）。

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
   `canonicalize` + 前綴驗證（擋 symlink 逃逸）；違規一律 403 ~~並記稽核 log~~。
   （2026-10-05 修訂：不記伺服器端稽核 log，原因與請求的 root、path 附在回應的 `detail`；見文末修訂節）
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

## 修訂：路徑違規的稽核紀錄（2026-10-05，T916）

決策 6 原寫「違規一律 403 並記稽核 log」，但實作從未有稽核 log：server 不依賴 tracing／log，沒有任何日誌
輸出。違規的實際處置是回 403（`server.err.forbidden_path`），並在回應的 `detail` 附上原因碼
（`unknown_root`／`lexical_violation`／`escape`／`not_found`）與請求的 root、path（`crates/cytrace-server/src/api/jobs.rs`）。
上傳封存檔的路徑穿越同樣以 403 與 `detail` 回報。

**修訂**：刪除「並記稽核 log」，以上述實際行為為準，不補實作。

- 理由：本服務為**單一管理帳號**（決策 3），會觸發路徑違規的請求必定來自已登入的那一位管理者，
  違規內容已原樣回給他；伺服器端再記一份，對「誰做了什麼」沒有新增資訊。
  補實作則須另外裁定格式、落點、保存期限，以及 log 是否可含機密目標的路徑（NFR-09 信任邊界），
  成本與風險都不小，而目前沒有需求方。
- 日後若出現多帳號或稽核需求（例如交件單位要求留存存取紀錄），另開 ADR 處理，而不是回頭恢復這一句。
- 裁定：使用者 2026-10-05 於對話中選擇此方案（「按你的建議」，回應「建議 B：修訂 ADR-011 拿掉這句」）。
  本修訂只更正一句與實作不符的宣稱，不改變本 ADR 的狀態與其他決策。
- 同步更正：`crates/cytrace-server/src/targets.rs` 的註解（「detail 進稽核 log」）、`docs/SDS.md` §10。

## 修訂：job 目錄的產物（2026-10-05，T919）

**裁定來源**：使用者 2026-10-05 授權依建議推進至專案完整；SPDX 產出本身屬 ADR-002 既有決策。

- 決策 4 列出的 job 目錄檔案不完整：實際另有 `cbom.cdx.json`（要求 CBOM 且引擎產出時；ADR-013），
  T919 起另有 `sbom.spdx.json`（Web 服務模式一律產出）。
- 決策 7 的 artifacts 端點種類：`sbom`、`spdx`、`grype`、`cbom`，以附件下載；單筆 job 查詢另附
  `artifacts` 欄位，列出實際存在的產物。落盤的 `job.json` 格式不變。

## 修訂：映像 tar 的掃描目標形態（2026-10-07，T927／#49）

**裁定來源**：使用者於 2026-10-07 核准後續工作計畫（T927）。

**實測起因**（釘選版 Syft 1.45.1，Docker 28 匯出的 alpine）：
- 上傳的 `docker save` tar 被判為一般 tar，解開後以 `dir:` 掃描，結果**靜默得到 0 個元件**。CLI 以 `docker-archive:` 掃描同一個 tar，可抓到 16 個套件。
- 掛載目標一律組成 `dir:`。掛載映像 `.tar` 檔時，Syft 以 not a directory 失敗。

**決定**：
- **上傳**：解開後依內容決定目標形態（`upload::image_aware_target`）。
  - 根目錄的 `manifest.json` 是非空陣列，且每個元素都有 `Layers` 陣列，視為 docker-save：
    - 一般 tar → `docker-archive:<原始 tar>`。
    - gzip 壓縮 → 先解壓成 `<input>/image.tar`，再以 `docker-archive:` 掃描，因為 Syft 讀不了壓縮的映像 tar。
      解壓量的上限是「解壓上限＋檔頭餘量」（每個檔案 4 KiB，外加 16 個）：tar 串流比內容多出檔頭與補齊，
      只用內容上限的話，內容剛好在上限內的合法映像會在這一步被拒收。tar 結尾之後的填充則在這一步擋下。
    - 前端專案常見的 PWA `manifest.json` 是物件，不會被誤判；空陣列也不算。
  - Docker 25 起的 `docker save` 會同時寫出 OCI layout。Syft 1.45.1 的 `oci-dir` 解析不了它的巢狀 index，所以有 docker-save 清單時一律走 `docker-archive:`。
  - 只有 OCI layout（例如 skopeo 匯出）→ `oci-dir:<解開的目錄>`。真引擎測試以手工構造的扁平 layout 驗證可掃到套件（`pinned_syft_oci_dir_reads_flat_layout_and_fails_loudly_on_nested_index`）。
  - 其餘 → `dir:`。zip 包不做上述 docker-save 轉換（見已知限制）。
- **掛載**：
  - 解析出的目標是檔案時不加 `dir:`，交給 Syft 自動辨識。實測可認出 docker-archive；一般原始碼 tar 與 Go 執行檔照常掃描其內容。
  - 目錄是 OCI layout 時給 `oci-dir:`，其餘目錄維持 `dir:`。扁平 layout 給 `dir:` 時 Syft 也會認作映像；但 Docker 匯出的巢狀 index 給 `dir:` 會**靜默得到 0**，給 `oci-dir:` 則明確失敗——寧可失敗，不交出空報表。
- **CBOM**：`cbom_target` 先剝除 `dir:`／`docker-archive:`／`oci-archive:`／`oci-dir:` 前綴。目錄依 `is_oci_layout` 決定 theia 的 image 或 dir 模式，與上述 Syft 的判斷共用同一個函式；檔案一律依 magic bytes 當映像處理。掛載的非映像檔案在 CBOM 側盤點失敗並記錄於報表（實測：原始碼 tar → `cbom.err.empty_output`、Go 執行檔 → `cbom.err.target_not_archive`），SBOM 與弱點照常產出；這是既有行為，與 CLI 相同。
- **實測**（釘選 Syft 1.45.1／Grype 0.114.0／theia 1.1.2、真實漏洞 DB，同一個 alpine 映像，皆帶 CBOM）：CLI `run docker-archive:`、上傳 tar、上傳 tar.gz、掛載 tar 四條路徑都是 96 個元件、30 筆弱點、CBOM 2904 項。
- **已知限制**（實測原文見 #49 的 PR）：
  - gzip 壓縮的映像以**掛載**方式提供時，Syft 讀不了，且不加前綴時靜默得到 0 個元件。請改以上傳方式提供，或先解壓再掛載。
  - **zip 包的映像**不轉成 docker-archive：舊式匯出落到 `dir:`，靜默得到 0；Docker 25 起的匯出因帶 OCI layout 落到 `oci-dir:`，Syft 報錯。映像請以 tar 或 tar.gz 上傳。
  - **映像放在子目錄裡**（例如 tar 內是 `images/app.tar` 或 `app/manifest.json`）只看根目錄，落到 `dir:`，靜默得到 0。
  - **多映像**（`docker save a b`）：Syft 以 `cannot process multiple docker manifests` 失敗，job 顯示失敗。請一個映像一個 tar。
  - 掛載**已解開的** Docker 匯出目錄：Docker 25 起的匯出因巢狀 index 明確失敗；更舊的匯出沒有 OCI layout，落到 `dir:`，靜默得到 0。請掛載 tar 檔本身。
  - 磁碟峰值：映像 tar 仍會完整解開到 `extracted/` 以判斷形態。tar 約佔兩份（原檔＋解開內容），tar.gz 約三份（再加 `image.tar`），都在 job 的 `input/` 底下、受解壓上限約束。
- 原始上傳檔與解壓產物都在 `input/` 底下，掃描結束後照 #39 的規則刪除。
