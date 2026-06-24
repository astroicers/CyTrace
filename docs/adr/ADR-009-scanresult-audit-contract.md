# [ADR-009]: ScanResult 稽核產物 schema 與報表重現契約

| 欄位 | 內容 |
|------|------|
| **狀態** | `Draft` |
| **日期** | 2026-06-24 |
| **決策者** | CyTrace Team |

> **狀態說明：** `Draft`（初稿，禁止實作）→ `FIRM`（POC 驗證，允許 commit，需附驗證證據）→ `Accepted`（人類審核通過）

---

## 背景（Context）

CyTrace 的核心稽核能力是 `cytrace report <json>`：由先前產出的 **ScanResult JSON** **離線重現**同一份報表，供查核/複核
（原設計文件 §8 風險表「保留 report 重現機制供複核」）。這定義了 **core ↔ report 之間的穩定資料契約**，也是稽核人員從留存證據獨立重現報表的依據。
此外，報表是把 ScanResult 注入內嵌樣板產生的——**注入契約**若不定義，前端 bundle 與 Rust 注入器會各做各的、互不相容（T303 高複雜度任務的卡點）。
目前 ScanResult 結構只在 SDS §4 描述、注入只在 SDS §7 以「注入點（佔位）」帶過，**無 ADR 擁有 schema 穩定性與重現/注入契約**。

## 評估選項（Options Considered）

### 選項 A：版本化 ScanResult schema + 明定資料注入契約（sentinel + JSON script tag + 跳脫規則）
- **優點**：留存的 ScanResult 可跨 CyTrace 版本重現報表；前端與 Rust 注入器對同一契約實作；可稽核、可回溯。
- **缺點**：需維護 `schema_version` 與相容政策。
- **風險**：注入未正確跳脫會造成 HTML/script 破壞或 XSS 等價問題 → 以契約 + golden 測試（ADR-008）緩解。

### 選項 B：不版本化、注入細節留給實作
- **優點**：短期省事。
- **缺點**：舊證據無法保證可重現；前端/注入器契約不一致；軍方無法獨立複核。
- **風險**：稽核賣點落空。

## 決策（Decision）

採用 **選項 A**。

1. **schema 穩定性**：`ScanResult` 加 `schema_version` 欄位；定義向後相容政策——新版 `cytrace report` 須能重現舊版 ScanResult JSON。
2. **資料注入契約**（取代 SDS §7「注入點（佔位）」）：
   - 注入點＝樣板 head 內單一 sentinel：`<!--CYTRACE_DATA-->`。
   - 產生時替換為：`<script id="cytrace-data" type="application/json">{…}</script>`（`type=application/json` 使資料不進 `script-src`、避開多數跳脫陷阱）。
   - 前端以 `JSON.parse(document.getElementById('cytrace-data').textContent)` 讀取。
   - Rust 注入器**必須跳脫**：至少 `</` → `<\/`，加 U+2028/U+2029（若不用 script-tag 形式則另需處理裸 `<`）。
3. **重現契約**：`cytrace report <ScanResult.json>` 為純函式——同一 JSON（除 `meta.generated_at` 等時間欄位外）產生內容一致的報表。
4. **與 golden baseline 一致**：時間/易變欄位於比對前正規化或排除（見 ADR-008、SDS §9）。

## 後果（Consequences）

**正面影響：**
- 稽核人員可由留存 JSON 獨立重現報表；前端與注入器契約一致；注入安全（避免破版/XSS 等價）。

**負面影響 / 技術債：**
- 維護 schema 版本與相容性；注入器需完整跳脫實作與測試。

**後續追蹤：**
- SDS §4 加 `schema_version`；SDS §7 改寫為本注入契約；ROADMAP T303 description 引用本契約；FR-003 / SRS CLI 表交叉引用。

## 成功指標（Success Metrics）

| 指標 | 目標值 | 驗證方式 | 檢查時間 |
|------|--------|----------|----------|
| 舊 ScanResult 可被新版重現 | 是 | 以舊 JSON + 新 `cytrace report` 重現並比對（排除時間欄位） | M3/M5 |
| 注入跳脫安全 | 是 | golden 測試：欄位含 `</script>` 與 U+2028 仍正確 round-trip | M3 |
| 報表重現為純函式 | 是 | 同 JSON 兩次產出內容一致（排除 generated_at） | M3 |

## 關聯（Relations）

- 參考：ADR-005（單檔報表）、ADR-008（golden baseline 欄位正規化）、SDS §4/§7/§9、SRS FR-003/FR-006、ROADMAP T303
