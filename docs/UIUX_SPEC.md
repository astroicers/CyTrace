# UIUX_SPEC — CyTrace 報表檢視器

| 欄位 | 內容 |
|------|------|
| **文件** | UI/UX Specification |
| **專案** | CyTrace |
| **版本** | 0.4 |
| **日期** | 2026-10-05 |
| **狀態** | 現行，與 v0.5.0 對齊 |
| **對應** | ADR-004（i18n）、ADR-005（單檔報表）、ADR-011（Web 控制台）、ADR-013（密碼學資產）、SRS FR-006/FR-007/FR-011/FR-013、NFR-08 |

> **v0.4 更新**：§1–§7 為報表檢視器；§8 新增 Web 控制台（v0.3.0 起）。並更正 0.1 草案中與實作不符的三處：
> 報表不持久化語言（持久化的是控制台）、主題只有亮／暗（無高對比）、列印為按鈕而非說明。

---

## 1. 產品形態與技術棧

報表檢視器是**自包含離線單檔 HTML**（非常駐網站、無路由、無後端、零外連）。
採 **visual-web-stack DOM/UI 子集**（依使用者決策，**不含** R3F/3D/Lenis/GSAP 滾動敘事）：

| 層 | 套件 | 用途 |
|----|------|------|
| UI | React 19 + Tailwind | 版面、排版、卡片、表格 |
| 元件 | Radix UI | Tabs、Dialog、Tooltip、DropdownMenu（語言切換）、無障礙原語 |
| 動畫 | Motion（`motion/react`） | 進出場/展開的輕量過場（只動 transform/opacity） |
| 主題 | next-themes | 亮 / 暗 |
| 狀態 | Zustand | 語言、主題、嚴重度篩選 |
| i18n | react-i18next | zh-TW（fallback）/ en-US |
| 建置 | Vite（單檔內聯） | 內聯 JS/CSS/字型 → 單檔，供 Rust 內嵌 |

> 遵循 visual-web-stack 鐵則中與本場景相關者：DOM 動畫只動 transform/opacity；Radix×Motion 退場需
> `forceMount + AnimatePresence + asChild`；一元素只由一套引擎驅動。3D/Lenis/ScrollTrigger 相關鐵則本產品不適用（未採用）。

## 2. 版面與區塊（單頁，六大區塊；v0.3.0 起）

| 順序 | 區塊 | 內容 | i18n 鍵命名空間 |
|------|------|------|----------------|
| 1 | **封面 / 機關識別** | 受測目標、產生時間、工具版本（Syft/Grype/**CBOMkit-theia**）、**掃描身分**、**DB 快照版本/日期**（真值；取不到或為 v1 假值時顯示 `report.db_unavailable`）。機關名稱／SBOM 格式為規劃欄位，v0.3.0 尚未渲染 | `report.cover` |
| 2 | **風險總評** | 總評等級（色塊）、各嚴重度計數、元件總數、弱點總數 | `report.summary` |
| 3 | **弱點明細** | 表格：嚴重度 / CVE / CVSS / 元件（名稱與現用版本，下方一行列出所在位置，多處時「另 N 處」可展開）/ 修補版本 / 公告來源（Grype 的漏洞公告網址）；可依嚴重度篩選 | `report.findings` |
| 4 | **軟體產品文件表** | 元件名（下方以小號等寬字列 purl）/ 版本 / 類型 / 授權 / 位置（前 2 處，其餘「另 N 處」可展開；完整清單保留在 ScanResult 與 SBOM JSON）。不列 Syft 的 file 類元件（以主機路徑為名的檔案紀錄，原始 SBOM JSON 仍保留；ADR-009 修訂，T928）。SBOM 呈現，可併入交件 | `report.sbom` |
| 5 | **密碼學資產**（ADR-013；`--cbom` 時） | 摘要計數（總數/量子脆弱/弱金鑰/過期）、三類未掃描警示、資產表（名稱/類型/金鑰長度/量子狀態徽章/弱金鑰/位置）；四態訊息（未執行/引擎缺席/失敗含成因/完成）；量子徽章用獨立命名空間（`--color-q-*`）便於整族調整；其中兩色現值與嚴重度色票同 hex，屬刻意沿用而非隔離失敗 | `report.crypto` |
| 6 | **附註** | 格式標準、資料來源/時效（DB 快照日期）、授權聲明、**免責定位** | `report.notes` |

> **區段資料來源（v3 起，ADR-009 修訂）**：弱點明細、軟體產品文件表、密碼學資產三個區段的標題下各有一行小字，
> 標明產生該區段資料的工具與版本（`report.provenance.*`）：弱點明細列 Grype 與漏洞資料庫快照，
> 軟體產品文件表列 Syft，密碼學資產列 CBOMkit-theia（僅在有執行盤點時顯示）。舊版 ScanResult 同樣適用。

> **免責定位（NFR-10，必含）**：附註區須含雙語固定句，鍵 `report.notes.disclaimer_not_pentest`，
> 明示「本報表為**產出/核發之依賴風險報表，非滲透測試或資安檢測**」，避免被誤認為滲透測試而生責任誤解。
> 此句為 T301/T302 的驗收條件，不可省略、不可硬編碼。

## 3. 嚴重度色票（設計 token，禁硬編碼色值）

| 等級 | token | 亮色 | 暗色 | 對比要求 |
|------|-------|------|------|---------|
| 極高 Critical | `--sev-critical` | 深紅 | 亮紅 | AA |
| 高 High | `--sev-high` | 橙 | 亮橙 | AA |
| 中 Medium | `--sev-medium` | 琥珀 | 亮黃 | AA |
| 低 Low | `--sev-low` | 藍 | 亮藍 | AA |
| 極低 Negligible | `--sev-negligible` | 灰 | 亮灰 | AA |
| 未知 Unknown | `--sev-unknown` | 中性 | 中性 | AA |

> 色彩**不可作為唯一資訊載體**：每個嚴重度同時以文字標籤 + 圖示呈現（色盲友善）。

## 4. 互動

- **語言切換**：右上 Radix DropdownMenu（zh-TW / English），即時切換。報表以**產生時的語言**開啟
  （CLI 的 `--lang`／`CYTRACE_LANG`；Web 服務為送出掃描時的介面語言），讀者可再切換；切換不持久化（T918）。
- **主題切換**：亮 / 暗（next-themes；預設亮）。
- **嚴重度篩選**：總評區點等級 → 過濾弱點明細表。
- **展開細節**：弱點列可展開顯示描述（Radix + Motion 過場）。
- **列印**：右上「列印 / 存 PDF」按鈕呼叫瀏覽器列印；列印樣式隱藏工具列等互動元件（ADR-005 不內建 PDF）。

## 5. 無障礙（WCAG-2.1-AA，NFR-08）

- 所有互動元件鍵盤可達（Radix 原生支援）；focus ring 明顯。
- 色彩對比 ≥ 4.5:1（正文）/ 3:1（大字）。
- 表格具 `scope`/表頭語意；圖示具 `aria-label`（走 i18n 鍵）。
- 語言切換更新 `<html lang>`。

## 6. 離線與安全約束

- **零外連**：不載入任何 CDN/字型/分析；字型本地子集化內嵌（`Inter` + `Noto Sans TC`，拉丁在前、CJK 在後）。
- **CSP（具體，見 ADR-005）**：`default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; img-src 'self' data:; font-src 'self' data:; connect-src 'none'; base-uri 'none'; form-action 'none'`。
  零外連靠 `connect-src 'none'`＋無外部資源；inline 是單檔 bundle 自身腳本/樣式所必需，**不可**省略 `'unsafe-inline'`，否則報表空白。
- file:// 下 `'self'` 可能為 null/opaque origin、行為依瀏覽器而異 → 不依賴 `'self'` 取路徑相對資源（全部內嵌）。
- 不使用任何需要網路的功能（地圖、遠端圖片等）。

## 7. i18n 規範

- 任何使用者可見字串一律走 `react-i18next` 鍵；**禁止硬編碼**（`frontend_quality` 把關）。
- 兩語系鍵集合一致、無缺鍵（CI 檢查）。
- 嚴重度標籤鍵與 ADR-006 對齊（`severity.*`）。

## 8. Web 控制台（`cytrace serve`；ADR-011，v0.3.0 起）

控制台是 `serve` 提供的單頁應用，與報表樣板分屬兩份 Vite 建置產物，以 rust-embed 內嵌進 binary。
採 hash routing（`#/…`），同樣零外連；CSP 由 server 以標頭下發。

| 路由 | 頁面 | 內容 | i18n 鍵命名空間 |
|------|------|------|----------------|
| （未登入） | 登入 | 單一管理帳號的密碼登入 | `console.login` |
| `#/` | 掃描任務 | job 列表：目標、狀態、風險、建立時間；重新整理、新增掃描、檢視 | `console.jobs` |
| `#/scans/new` | 新增掃描 | 兩種來源：上傳封存檔（zip／tar／tar.gz，顯示進度）或掛載目錄白名單（root + 相對路徑）；`fail_on` 門檻；CBOM 勾選項 | `console.scan` |
| `#/jobs/{id}` | 任務詳情 | 狀態、時間、風險與計數；失敗時顯示依語系渲染的原因；下載報表與 ScanResult | `console.job` |
| `#/reports` | 報表 | 已完成掃描的報表列表 | `console.reports` |
| `#/system` | 系統 | CyTrace 版本、DB 快照狀態、掃描白名單、上傳上限 | `console.system` |

- **語系**：控制台語言持久化在 localStorage 鍵 `cytrace.lang`，只接受 zh-TW／en-US，其他值退回 zh-TW。
  送往 API 的 `?lang=` 一律是**畫面實際使用的語系**，報表與結果連結也帶語系，時間依介面語系格式化
  （前端以 AST 檢查把關：`frontend/scripts/console-lang-check.mts`）。
- **API 錯誤**：顯示依請求語系渲染的 `message`；job 失敗原因的退回鏈與 server 共用同一份 fixture
  （鍵 → 分類泛用句 → 原始細節 → 內部錯誤）。
- **零外連**：除同源 `/api` 外不發任何請求；`/api` 字串只准出現在 `api/client.ts`、`api/upload.ts`。

