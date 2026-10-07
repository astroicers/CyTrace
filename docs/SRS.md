# SRS — CyTrace 軟體需求規格書

| 欄位 | 內容 |
|------|------|
| **文件** | Software Requirements Specification |
| **專案** | CyTrace |
| **版本** | 0.4 |
| **日期** | 2026-10-05 |
| **狀態** | 現行，與 v0.5.0 對齊（各需求的實作狀態見「狀態」欄） |

> **v0.4 更新**：0.1 草案寫於只有 Syft／Grype、只有 CLI 的時期。本版補上之後經 ADR 核准並已實作的需求
> （CBOM 與量子閘門、Web 服務模式、容器、雙平台），並為每條需求標註實作狀態。需求文字本身未刪改；
> 尚未實作者照實標註。

---

## 1. 目的與範圍

CyTrace 是**地端、無網際網路（軍用網路）場域的軟體依賴風險報表產生器**。封裝 Syft（產 SBOM）、
Grype（比對 CVE）與 CBOMkit-theia（密碼學資產盤點），對指定目標（原始碼目錄／容器映像／檔案系統）產出
**依賴風險報表**、**軟體產品文件表（SBOM）**與選用的**密碼學資產清單（CBOM）**，可併入交件。

**範圍內**：本地掃描、離線漏洞比對、嚴重度分級、密碼學資產盤點與量子脆弱判定、雙語離線報表、
離線封裝交付（Linux／Windows）、批次與 CI 整合、場域內 Web 服務模式與容器交付。
**範圍外**：SaaS 雲端監管（延後）、PDF 內建產出（延後）、3D/滾動視覺敘事。

## 2. 關鍵字定義（術語）

| 術語 | 定義 |
|------|------|
| SBOM | 軟體物料清單（Software Bill of Materials），本產品以 CycloneDX 為主、SPDX 為備。 |
| 軟體產品文件表 | 交件用的 SBOM 呈現（元件名/版本/類型/授權）。 |
| 依賴風險報表 | 嚴重度分級 + 風險總評 + 弱點明細的雙語報表。 |
| CBOM | 密碼學物料清單（Cryptography Bill of Materials），CycloneDX 1.6 的 `cryptographic-asset`。 |
| 量子脆弱 | 演算法可被量子電腦破解（如 RSA、ECC）；判定規則見 ADR-013 決策 6。 |
| 風險總評 | 以掃描結果中最高嚴重度等級決定的整體評級。 |
| DB 快照 | grype 漏洞資料庫的離線版本，附建立日期。 |

## 3. 功能需求（Functional Requirements）

| ID | 需求 | 對應 ADR | 里程碑 | 狀態 |
|----|------|---------|--------|------|
| **FR-001** | 對目標（目錄/容器映像/檔案系統）以 Syft 產生 SBOM，輸出 CycloneDX（主）與 SPDX（備）。 | ADR-001/002 | M1 | 已實作：CycloneDX 1.6；SPDX 2.3 於 `scan --spdx` 與 Web 服務模式產出（T919） |
| **FR-002** | 以 Grype 對 SBOM 進行 CVE 比對，使用**離線**漏洞 DB 快照，輸出 grype JSON。 | ADR-002/003 | M1 | 已實作 |
| **FR-003** | 解析 grype 結果與 CycloneDX 元件清單，彙整為統一資料模型（版本化 ScanResult）。 | ADR-001/009 | M2 | 已實作（schema v3：元件與弱點帶來源欄位，ADR-009 修訂） |
| **FR-004** | 將嚴重度對映為雙語六級（極高/高/中/低/極低/未知）並計算風險總評。 | ADR-006 | M2 | 已實作 |
| **FR-005** | 提供 `--fail-on <severity>` 閘門；達門檻以**退出碼 2** 結束，正常為 0（供 CI/批次）。錯誤（含參數打錯）為 1。 | ADR-006 | M2 | 已實作 |
| **FR-006** | 產出**自包含離線單檔 HTML** 報表，含：機關識別、風險總評、弱點明細、軟體產品文件表、DB 快照時效；零外連。 | ADR-005 | M3 | 已實作（另含密碼學資產區段，FR-011） |
| **FR-007** | 全產品（報表 + 控制台 + CLI 輸出與 `--help`）走 i18n，支援 zh-TW（fallback）與 en-US，禁止硬編碼。 | ADR-004 | M0/M3 | 已實作（v0.4.0 起含終端訊息與 `--help`） |
| **FR-008** | 提供離線安裝包：靜態 binary + 釘選 Syft/Grype/CBOMkit-theia + grype DB 快照 + SHA256SUMS/簽章。 | ADR-007/003/013 | M4 | 已實作（Linux／Windows）；minisign 簽章（交付公鑰 ID `055ACC6F1822B10E`，T402），v0.5.0 起 Release 附 `SHA256SUMS.minisig` |
| **FR-009** | dogfooding：對 CyTrace 自身產出 SBOM 並隨安裝包附上。 | ADR-007/003 | M4 | 已實作 |
| **FR-010** | 支援多目標批次掃描與 CI 閘門整合範例。 | ADR-006/007 | M5 | 已實作（`batch`） |
| **FR-011** | 選用（`--cbom`）盤點檔案系統／映像層的密碼學資產，輸出 CycloneDX CBOM，報表列量子脆弱、弱金鑰、憑證到期；未掃描項目分類揭露，不含金鑰內容。 | ADR-013 | M9 | 已實作 |
| **FR-012** | 選用量子閘門 `--fail-on-quantum-vulnerable`：有量子脆弱資產以 2 結束；未取得完整 CBOM 結果以 1 結束（fail-closed）。 | ADR-013 | M9 | 已實作 |
| **FR-013** | Web 服務模式（`serve`）：單一管理帳號登入控制台，以上傳或掛載目錄送掃描，查看 job 狀態、報表與產物；API 依請求語系回應。 | ADR-011 | M8 | 已實作 |
| **FR-014** | 容器交付：映像含三個引擎、不含 DB（以 volume 掛入），可離線搬運；`docker stop` 優雅關閉。 | ADR-012 | M8 | 已實作 |
| **FR-015** | 雙平台發布：Linux（musl 靜態）與 Windows（msvc 靜態 CRT）執行檔隨 Release 發佈。 | ADR-010 | M7 | 已實作 |

### CLI 介面（概要）

| 子命令 | 行為 |
|--------|------|
| `cytrace run <目標>` | 一鍵：產 SBOM → 比對 → 出報表（`--fail-on`、`--cbom`、`--fail-on-quantum-vulnerable`）。 |
| `cytrace batch <目標…>` | 多目標批次掃描，逐一出報表；退出碼取各目標最嚴重者（1 優先於 2）。 |
| `cytrace scan <目標>` | 只產 `sbom.cdx.json` 與 `grype.json`（`--spdx` 另產 `sbom.spdx.json`、`--cbom` 另產 `cbom.cdx.json`）。 |
| `cytrace report <json>` | 由既有 JSON 離線重現報表（稽核複核用）。 |
| `cytrace serve` | Web 服務模式（FR-013）。 |
| `cytrace hash-password` | 離線產生管理密碼的 argon2id PHC 字串。 |
| `cytrace health` | 服務存活檢查（容器 HEALTHCHECK）。 |

全域旗標 `--lang zh-TW｜en-US`；未給時讀 `CYTRACE_LANG`，皆無則 zh-TW。

## 4. 非功能需求（Non-Functional Requirements）

| ID | 類別 | 需求 |
|----|------|------|
| **NFR-01** | 無網路 | 執行期、報表、CI 一律零外連；報表以 CSP 鎖死。 |
| **NFR-02** | 穩定性 | 釘選 toolchain/crate/引擎/DB 版本；golden baseline 回歸測試；可重現建置。 |
| **NFR-03** | 可稽核 | 交付物可 `sha256` + 簽章驗證；報表標註工具（Syft/Grype/theia）與 DB 版本/日期，並標示掃描執行身分。 |
| **NFR-04** | 可攜性 | 報表為單檔；產品為單一靜態 binary；交付為單包。 |
| **NFR-05** | 供應鏈純淨 | 第三方工具本體皆 Apache-2.0（Syft/Grype/CBOMkit-theia）；theia 相依含 gitleaks MIT 與 MPL-2.0 三項，須列 NOTICE。**禁中國來源依賴**（規範對象為專案／組織，不及於個別貢獻者國籍；ADR-013）；附 NOTICE 與自產 SBOM。 |
| **NFR-06** | i18n | 雙語鍵集合一致、無缺鍵；新增使用者可見字串必走鍵。 |
| **NFR-07** | 測試覆蓋 | 目標 ≥ 80%；核心分級/閘門邏輯需單元 + 整合測試。2026-10-05 實測（`make coverage`，cargo-llvm-cov）：行覆蓋 89.45%。 |
| **NFR-08** | 可及性 | 報表符合 WCAG-2.1-AA（對比、鍵盤、語意）。 |
| **NFR-09** | 信任邊界 | 掃描目標與原始碼**不離開目標場域**。單機模式維持「不離開目標機」；Web 服務模式（`serve`，ADR-011）允許操作者將目標**上傳至同場域內**的 CyTrace 掃描伺服器（傳輸建議啟用 TLS），上傳內容僅落於伺服器受控資料目錄、掃描完成後預設刪除（`CYTRACE_KEEP_INPUT=false`）；報表僅含依賴與弱點元資料。任何資料不出場域。支援含機密等級目標。SaaS 只收 SBOM 且延後（範圍外）。 |
| **NFR-10** | 法遵免責定位 | 報表須自我定位為「**產出/核發依賴風險報表，非滲透測試/資安檢測**」，避免責任誤解（雙語）。 |

## 5. 法規與標準邊界

- SBOM 標準：CycloneDX（主）、SPDX（備）。
- 參考最小要素：NTIA SBOM Minimum Elements。
- 政府/軍規 SBOM 趨勢：原設計文件 §7 指出自 1140204 起政府採購對 SBOM 的要求漸明（CyTrace 以此為目標市場）。
- 產地要件：禁用中國大陸來源工具/依賴（如 OpenSCA-cli）。

## 6. 假設與限制

- 目標機無網際網路；漏洞 DB 時效取決於離線快照攜入頻率（報表須揭露）。
- Syft/Grype/CBOMkit-theia 為外部 Go binary，以子程序呼叫並釘選版本（`scripts/versions.env`）。
- **目標平台**：已支援 x86_64 的 Linux（musl 靜態）與 Windows（msvc 靜態 CRT）兩個平台（ADR-010）。
  arm64 與國產 Linux（麒麟、UOS、RHEL clone）**未支援**：若驗收環境為此類平台，須重新規劃 cross-compile
  （Rust + 隨附 Go 引擎）（ADR-001/007、SDS §8）。Windows 版 CBOM 引擎尚未於場域機器實地驗證。
- **PDF 驗收風險**：PDF 產出暫以瀏覽器列印替代；若軍方驗收強制要求 PDF 歸檔/印發，須升級 M3 或另開 PDF ADR（ADR-005）。
