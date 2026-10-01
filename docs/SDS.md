# SDS — CyTrace 軟體設計規格書

> **v0.3.0 增補（2026-09-29）**：本文主體寫於雙引擎時期，尚未全文改寫。
> CBOM（第三引擎 CBOMkit-theia）的設計權威是 **ADR-013**（含決策 1–10 與成功指標），
> `ScanResult` schema v2 的稽核契約見 **ADR-009 修訂節**。以下各節先以行內註記對齊：
> §1 管線多一條 `--cbom → cbomkit-theia` 分支；§2 crates 為 6（另有 `-i18n`／`-server`）；
> §3 子程序編排同樣涵蓋 theia（專用可寫 HOME、逾時、管線併發抽乾、fail-closed，
> 細節見 `crates/cytrace-core/src/engine.rs` 的文件註解）；§4 資料模型加 `crypto` 區段。
> 全文改寫見 **ROADMAP T910**（不阻擋 v0.3.0；release 準備複審 major #24 的處置記錄）。

| 欄位 | 內容 |
|------|------|
| **文件** | Software Design Specification |
| **專案** | CyTrace |
| **版本** | 0.1（草案） |
| **日期** | 2026-06-24 |
| **狀態** | Draft |
| **對應** | SRS（FR-001…010）、ADR-001~007 |

---

## 1. 架構總覽

CyTrace 為 **Rust Cargo workspace 單體（monolith）CLI**，以子程序呼叫外部引擎，前端報表 build 後內嵌。

```
目標(目錄/映像/FS)
        │
        ▼
  cytrace-cli (clap: run|scan|report)
        │  spawn 子程序
   ┌────┴─────────────┐
   ▼                  ▼
 Syft            Grype(離線 DB)
 (SBOM)          (CVE 比對)
   │                  │
 sbom.cdx.json     grype.json
   └────────┬─────────┘
            ▼
   cytrace-core (parser → 統一模型 → severity/風險總評 → --fail-on)
            ▼
   cytrace-report (rust-embed 內嵌前端單檔 → 注入資料 → *.report.html)
```

## 2. Workspace crate 切分

| crate | 職責 | 主要依賴（候選） |
|-------|------|-----------------|
| `cytrace-types` | 共用領域型別（零依賴）：Component、Vulnerability、Severity、ScanResult、ReportModel。 | serde |
| `cytrace-core` | 子程序編排、解析（CycloneDX + grype JSON）、嚴重度對映、風險總評、`--fail-on` 判定。 | serde_json, anyhow, thiserror |
| `cytrace-report` | 內嵌前端單檔樣板、注入資料、輸出 `*.report.html`。 | rust-embed |
| `cytrace-cli` | `clap` 子命令 `run`/`scan`/`report`、i18n catalog、退出碼。 | clap, anyhow |

> 模組邊界鐵律：解析與評級邏輯只在 `cytrace-core`；型別只在 `cytrace-types`；CLI 不含業務規則。

## 3. 子程序編排（Syft / Grype）

- 以釘選版本的 Syft/Grype binary 路徑（安裝包內）呼叫；不依賴 PATH 上的任意版本。
- Grype 強制離線（ADR-003 完整變數集合）：`GRYPE_DB_AUTO_UPDATE=false`、`GRYPE_DB_VALIDATE_AGE=false`（否則 DB 過舊會中止掃描）、`GRYPE_DB_CACHE_DIR`/`--db` 指向安裝包內快照路徑。
- 子程序失敗（非零退出、找不到 binary、DB 缺失）→ 以 `thiserror` 定義領域錯誤、`anyhow` 串接上下文，CLI 回非 0、非 2 的錯誤碼（與 `--fail-on` 的 2 區隔）。

## 4. 資料模型（統一）

```
ScanResult {
  schema_version: u32                                              // 稽核產物版本（ADR-009 相容政策）
  meta: { target, tool_versions{syft,grype}, db_snapshot{version,date}, generated_at }
  components: [ Component{ name, version, type, licenses[] } ]      // → 軟體產品文件表
  findings:   [ Vulnerability{ id(CVE), severity, cvss?, component, fixed_version?, source } ]
  summary:    { counts_by_severity, overall_risk }                  // overall_risk = 最高等級
}
```

- 嚴重度 `Severity` 為 enum（Critical/High/Medium/Low/Negligible/Unknown）；對映與雙語標籤鍵見 ADR-006。
- `report` 子命令可由既有 `ScanResult` JSON **離線重現**報表（稽核複核）。`ScanResult` 為**版本化稽核產物**，
  新版 `cytrace report` 須能重現舊版 JSON；schema 穩定性與相容政策見 **ADR-009**。
- `meta.generated_at` 等時間/易變欄位於 golden baseline 比對前正規化或排除（§9、ADR-008）。

## 5. 錯誤處理（result_type）

- 一律 `Result<T, CytraceError>`；`CytraceError`（thiserror）分類：`Engine`（子程序）、`Parse`（JSON）、`Io`、`Config`、`DbMissing`。
- 退出碼語意：`0` 正常、`2` `--fail-on` 觸發、其他非 0 為錯誤。

## 6. i18n（CLI 端）

- 載入共用 `locales/{zh-TW,en-US}.json`（與前端同來源）；以 key 取訊息，缺鍵 fallback zh-TW。
- 語言來源：`--lang` 旗標 > 環境變數 > 預設 zh-TW。
- **共用值契約（ADR-004）**：前端 react-i18next 與 Rust loader 共用「鍵」也共用「值語意」。釘一種插值語法 `{{var}}`，
  Rust loader 實作同樣的簡單替換；**共用命名空間禁用複數/context/nesting（`_one`/`_other`、`_male`、`$t()`）**，
  CLI-facing 字串僅用 `{{var}}`。否則鍵雖同步、值會默默發散（前端寫 `{{count}}` 在 CLI 變字面值）。
- **CI 檢查（NFR-06）**：不只比對鍵集合，還要做**遞迴葉鍵集合 diff**（巢狀命名空間），並 lint 共用值只能用 Rust loader 支援的特性。
  注意 ASP 內建 `make i18n-check` 只比頂層鍵數量，不足以守住巢狀「無缺鍵」，須 T003 自建專案檢查。

## 7. 報表內嵌與資料注入契約（ADR-009）

- 前端（Vite 單檔內聯）build → 產物 `report-template.html` 置於 `cytrace-report/assets/`。
- `rust-embed` 於**編譯期**內嵌樣板（唯讀 `&[u8]`）；`report` 於執行期依下列契約注入 `ScanResult` 並輸出單檔：
  - **注入點**＝樣板 head 內單一 sentinel：`<!--CYTRACE_DATA-->`。
  - 替換為：`<script id="cytrace-data" type="application/json">{…ScanResult JSON…}</script>`（`type=application/json` 使資料不進 `script-src`）。
  - 前端以 `JSON.parse(document.getElementById('cytrace-data').textContent)` 讀取。
  - **跳脫（必須）**：注入前對 JSON 做 `</` → `<\/`、U+2028/U+2029 處理，避免破版/XSS 等價；以 golden 測試驗證含 `</script>` 與 U+2028 的欄位能 round-trip。
- 報表零外連、字型本地子集化內嵌；CSP 細節見 ADR-005（內聯自身腳本需 `script-src 'unsafe-inline'`，外連以 `connect-src 'none'` 擋）。

## 8. 建置與交付

- 目標 triple：`x86_64-unknown-linux-musl`（靜態連結、零 runtime）——此為**預設假設，未向驗收單位驗證**（SRS §6、ADR-007）。
  若目標機為 Windows / arm64 / 國產 Linux（麒麟、UOS、RHEL clone），須同時 cross-compile Rust binary 與重建隨附的 Syft/Grype Go binary，並重新檢視 ADR-001 的 musl 靜態價值主張（musl 限 Linux）。
- 釘選 `rust-toolchain.toml`、`Cargo.lock`、引擎版本與 DB 快照（ADR-007）。
- 可重現建置；release 產 `SHA256SUMS` + 簽章 + 自產 SBOM。

## 9. 測試策略

- 單元：嚴重度對映、風險總評、`--fail-on` 退出碼、解析器（樣本 grype/CycloneDX JSON）。
- 整合：`scan`/`report` 端到端（以釘選引擎與樣本目標）。
- 回歸：golden baseline（釘選引擎版本下輸出快照比對；升級才更新 baseline）——策略由 **ADR-008** 擁有。
- **非決定性欄位**：比對 baseline 前正規化或排除 `ScanResult.meta.generated_at` 等時間/易變欄位，否則同輸入每次跑都會因時間戳造成假性 diff（ADR-008/ADR-009）。
- 覆蓋率目標 ≥ 80%（NFR-07）。
- **Web 服務（`cytrace-server`）**：`tower::ServiceExt::oneshot` 整合測試（不開真實 socket、注入 `FakeEngine` 免引擎 binary）——認證生命週期、節流、CSRF、上傳惡意壓縮包（zip-slip/symlink/bomb）、path traversal、job 狀態機與重啟恢復、console 服務與 CSP。

## 10. Web 服務模式（`serve`；ADR-011）

- **crate**：`cytrace-server`（lib，axum/tokio）+ cli feature `server`（default on，`--no-default-features` 可退零 tokio 純 CLI）。`engine`/`i18n`/`timefmt` 已由 cli 前置重構搬至 `cytrace-core`/`cytrace-i18n`（SDS §2 歸位）。
- **執行模型**：`serve` 自建 tokio runtime（`main()` 保持同步）；掃描管線同步、經 `spawn_blocking` 隔離；`Semaphore` 限併發；請求路徑禁 panic（`panic=abort` crash-only，clippy `unwrap_used` deny）。
- **認證**：單一管理帳號（argon2id PHC、`CYTRACE_ADMIN_PASSWORD_HASH` 缺失拒啟動）；in-memory session（token SHA-256 存端、cookie HttpOnly/SameSite=Strict/TLS 時 Secure、TTL 12h）；登入節流 + CSRF（自訂標頭 + 無 CORS）。TLS 自帶 PEM（rustls/ring）。
- **Job 模型**：無資料庫，`{data_dir}/jobs/<id>/` 檔案系統為狀態真相（job.json 原子落盤）；重啟非終態→`interrupted`。
- **輸入**：上傳（multipart 串流 + zip/tar/tar.gz 三道解壓防護）+ 掛載目錄白名單（語彙檢查 + canonicalize 前綴驗證）。
- **API**：`/api/v1`（session/targets/jobs/upload/report/result/artifacts/version）+ `/healthz`；錯誤格式 `{error:{kind,i18n_key,message,detail}}` 沿用 `CytraceError` 分類；訊息走 locales（`server.*`）。
- **前端 console**：雙 Vite config（與報表樣板分離）、hash routing、rust-embed 內嵌服務；CSP header 硬化（report 端點自帶較寬 CSP 不被覆蓋）。
- **交付**：容器（ADR-012）為主要交付形態；見 docs/DOCKER.md、DELIVERY_SOP §7。
