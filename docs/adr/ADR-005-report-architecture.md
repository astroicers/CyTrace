# [ADR-005]: 報表架構（自包含離線單檔 HTML）

| 欄位 | 內容 |
|------|------|
| **狀態** | `Draft` |
| **日期** | 2026-06-24 |
| **決策者** | CyTrace Team |

> **狀態說明：** `Draft`（初稿，禁止實作）→ `FIRM`（POC 驗證，允許 commit，需附驗證證據）→ `Accepted`（人類審核通過）

---

## 背景（Context）

報表是 CyTrace 的主要交付面，須在**無網際網路的軍用地端**開啟、可攜、可併入交件，並支援**雙語切換**。
原設計文件曾列 Jinja2 + weasyprint 產 HTML/PDF，但本產品已選 React（visual-web-stack）為前端、Rust 為核心，
且使用者已確認交付形態為**離線單檔 HTML**。

## 評估選項（Options Considered）

### 選項 A：自包含單檔 HTML（內嵌 JS/CSS/字型/資料，零外連）
- **優點**：可攜（單一檔）；任何瀏覽器離線開啟；雙語即時切換（react-i18next）；以 CSP 鎖死外連、安全可稽核；前端 build 一次內嵌進 Rust binary，產生時注入掃描資料。
- **缺點**：單檔體積較大（字型/資料內嵌）；列印為 PDF 需靠瀏覽器列印（先不內建 PDF 產出）。
- **風險**：大型掃描資料使單檔過大 → 以資料精簡/分頁渲染緩解。

### 選項 B：多檔靜態網站資料夾
- **優點**：資源拆分、體積分散。
- **缺點**：交付笨重、易缺檔、可攜性差。

### 選項 C：伺服器渲染 + 內建 PDF（weasyprint 類）
- **優點**：直接產 PDF。
- **缺點**：引入額外 runtime/依賴，與「單一靜態 binary、零 runtime」衝突。

## 決策（Decision）

採用 **選項 A**：**自包含離線單檔 HTML**。前端以 Vite 單檔內聯 build → Rust `cytrace-report` 以 `rust-embed`
內嵌樣板 → `report` 子命令注入掃描資料產出 `*.report.html`。**資料注入契約見 ADR-009**（sentinel `<!--CYTRACE_DATA-->` → JSON script tag + 跳脫）。
字型本地子集化內嵌。**PDF 產出延後**（先靠瀏覽器列印；未來里程碑再評估純 Rust/headless 方案）。

**CSP（具體，取代抽象「鎖死」）**：Vite 單檔內聯會產生 inline `<script>`/`<style>`，故嚴格 CSP 不能省略 inline，否則自身腳本被擋、報表空白。採用：

```
default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline';
img-src 'self' data:; font-src 'self' data:; connect-src 'none'; base-uri 'none'; form-action 'none'
```

air-gapped 安全來自 `connect-src 'none'` ＋ 無任何外部資源，**非**禁止 inline（inline 是自身 bundle 必要的，且每份報表注入的資料 tag 會變動，sha256 hash 不實際）。
注意 file:// 下 `'self'` 可能解析為 null/opaque origin、行為依瀏覽器而異；故不依賴 `'self'` 取路徑相對資源（全部內嵌）。

## 後果（Consequences）

**正面影響：**
- 單檔可攜、離線可開、雙語、安全可稽核；與單一 binary 交付一致。

**負面影響 / 技術債：**
- 無內建 PDF（暫以瀏覽器列印替代）；單檔體積需控管。
- **PDF 驗收風險**：軍方驗收若**強制要求 PDF 歸檔/印發**，現行單檔 HTML 無法滿足、將阻斷交付。M4 前須向驗收單位確認；若需 PDF 則升級此里程碑或另開 PDF ADR。
- 嚴格 CSP 仍須允許 inline script/style（見上）；「零外連」靠 `connect-src 'none'`，不是禁 inline。

**後續追蹤：**
- 報表須含：機關識別、風險總評、弱點明細、軟體產品文件表、DB 快照時效（ADR-003）。
- PDF 需求若由軍方驗收提出，另開 ADR 評估。

## 成功指標（Success Metrics）

| 指標 | 目標值 | 驗證方式 | 檢查時間 |
|------|--------|----------|----------|
| 報表外部網路請求數 | 0 | file:// 在 Chromium+Firefox 開啟，Network 面板=0 請求 | M3 |
| 單檔離線可開且渲染 | 是 | 斷網開啟、五區塊有渲染（驗 CSP 未過嚴把報表變空白）、雙語切換正常 | M3 |
| 含必要區塊 | 5 區塊齊備 | 對照 UIUX_SPEC 區塊清單 | M3 |

## 關聯（Relations）

- 參考：ADR-001（內嵌）、ADR-003（DB 時效標註）、ADR-004（雙語）、UIUX_SPEC
