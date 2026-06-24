# UIUX_SPEC — CyTrace 報表檢視器

| 欄位 | 內容 |
|------|------|
| **文件** | UI/UX Specification |
| **專案** | CyTrace |
| **版本** | 0.1（草案） |
| **日期** | 2026-06-24 |
| **狀態** | Draft |
| **對應** | ADR-004（i18n）、ADR-005（單檔報表）、SRS FR-006/FR-007、NFR-08 |

---

## 1. 產品形態與技術棧

報表檢視器是**自包含離線單檔 HTML**（非常駐網站、無路由、無後端、零外連）。
採 **visual-web-stack DOM/UI 子集**（依使用者決策，**不含** R3F/3D/Lenis/GSAP 滾動敘事）：

| 層 | 套件 | 用途 |
|----|------|------|
| UI | React 19 + Tailwind | 版面、排版、卡片、表格 |
| 元件 | Radix UI | Tabs、Dialog、Tooltip、DropdownMenu（語言切換）、無障礙原語 |
| 動畫 | Motion（`motion/react`） | 進出場/展開的輕量過場（只動 transform/opacity） |
| 主題 | next-themes | 亮/暗與高對比 |
| 狀態 | Zustand | 語言、主題、嚴重度篩選 |
| i18n | react-i18next | zh-TW（fallback）/ en-US |
| 建置 | Vite（單檔內聯） | 內聯 JS/CSS/字型 → 單檔，供 Rust 內嵌 |

> 遵循 visual-web-stack 鐵則中與本場景相關者：DOM 動畫只動 transform/opacity；Radix×Motion 退場需
> `forceMount + AnimatePresence + asChild`；一元素只由一套引擎驅動。3D/Lenis/ScrollTrigger 相關鐵則本產品不適用（未採用）。

## 2. 版面與區塊（單頁，五大區塊）

| 順序 | 區塊 | 內容 | i18n 鍵命名空間 |
|------|------|------|----------------|
| 1 | **封面 / 機關識別** | 機關名稱、受測目標、掃描時間、工具版本（Syft/Grype）、SBOM 格式、**DB 快照版本/日期** | `report.cover` |
| 2 | **風險總評** | 總評等級（色塊）、各嚴重度計數、元件總數、弱點總數 | `report.summary` |
| 3 | **弱點明細** | 表格：嚴重度 / CVE / CVSS / 元件 / 現用版本 / 修補版本 / 來源；可依嚴重度篩選 | `report.findings` |
| 4 | **軟體產品文件表** | 元件名 / 版本 / 類型 / 授權（SBOM 呈現，可併入交件） | `report.sbom` |
| 5 | **附註** | 格式標準、資料來源/時效（DB 快照日期）、授權聲明、**免責定位** | `report.notes` |

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

- **語言切換**：右上 Radix DropdownMenu（zh-TW / English），即時切換、寫入 Zustand + 持久化（localStorage 鍵 `cytrace.lang`）。
- **主題切換**：亮 / 暗 / 高對比（next-themes）。
- **嚴重度篩選**：總評區點等級 → 過濾弱點明細表。
- **展開細節**：弱點列可展開顯示描述（Radix + Motion 過場）。
- **列印**：提供「列印 / 另存 PDF」說明（瀏覽器列印；ADR-005 暫不內建 PDF）。

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
