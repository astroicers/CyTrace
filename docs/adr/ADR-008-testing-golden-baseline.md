# [ADR-008]: 測試與 golden-baseline 回歸策略

| 欄位 | 內容 |
|------|------|
| **狀態** | `Draft` |
| **日期** | 2026-06-24 |
| **決策者** | CyTrace Team |

> **狀態說明：** `Draft`（初稿，禁止實作）→ `FIRM`（POC 驗證，允許 commit，需附驗證證據）→ `Accepted`（人類審核通過）

---

## 背景（Context）

「穩定優先」是 CyTrace 的最高原則，而抵禦**上游引擎漂移**（Syft/Grype 版本變動造成輸出改變）的安全網是
**golden-baseline 回歸測試**。但此機制被 ADR-002（「golden baseline 回歸測試緩解」）、ADR-007（「golden baseline 回歸測試 ROADMAP M5」）、
SDS §9、ROADMAP T503 多處引用，卻**沒有任何 ADR 擁有它**——亦即「如何證明引擎升級沒有改變結果」這個軍方驗收必問的問題，缺一個可引用的決策。本 ADR 將分散於各處的測試策略收斂為單一治理決策。

## 評估選項（Options Considered）

### 選項 A：分層測試（單元＋整合）＋ 版本綁定 golden baseline，baseline 僅在「刻意升級引擎」時更新
- **優點**：明確界定誰擁有測試策略；golden baseline 與引擎版本綁定，任何非預期輸出變動會被 CI 擋下；可重現、可稽核。
- **缺點**：需維護基準語料與 baseline 快照；引擎升級時要人工複核 diff 並更新 baseline。
- **風險**：baseline 含非決定性欄位（如 `generated_at`）會造成假性 diff → 以正規化/排除欄位緩解。

### 選項 B：只做單元測試，不做 golden baseline
- **優點**：維護成本低。
- **缺點**：無法偵測引擎升級造成的端到端輸出漂移——直接違反穩定優先。
- **風險**：上游變動無聲破壞交件結果。

## 決策（Decision）

採用 **選項 A**。測試策略由本 ADR 擁有：

1. **分層**：單元（嚴重度對映、風險總評、`--fail-on` 退出碼、解析器）＋ 整合（`scan`/`report` 端到端，釘選引擎與樣本目標）。
2. **golden baseline**：固定**基準語料**（一組代表性目標 + 釘選版 Syft/Grype + 釘選 DB 快照），對其輸出存快照；
   CI 比對輸出與 baseline。
3. **更新規則**：baseline **僅在刻意升級引擎/DB 時**由人工複核 diff 後更新；其餘任何 diff 視為回歸、CI 失敗。
4. **非決定性欄位**：比對前正規化或排除 `ScanResult.meta` 的 `generated_at` 等時間/易變欄位（見 ADR-009 / SDS §9）。
5. **覆蓋率**：整體 ≥ 80%（NFR-07）；核心分級/閘門邏輯須有單元＋整合測試。

## 後果（Consequences）

**正面影響：**
- 「引擎升級是否改變結果」有可引用的 ADR 答案與機械化把關；穩定優先有牙齒。

**負面影響 / 技術債：**
- 維護 baseline 與基準語料；引擎升級流程多一道人工複核。

**後續追蹤：**
- ADR-002 / ADR-007 對 golden baseline 的引用改指向本 ADR；ROADMAP T503 的 `adr` 指向 ADR-008。

## 成功指標（Success Metrics）

| 指標 | 目標值 | 驗證方式 | 檢查時間 |
|------|--------|----------|----------|
| 測試覆蓋率 | ≥ 80% | `make coverage` | 每次 G4/G5 |
| golden baseline 存在且綠燈 | 是 | CI 對基準語料比對通過 | M5 起每次 |
| 引擎升級可偵測輸出漂移 | 是 | 故意換引擎版本 → baseline diff 觸發失敗 | M5 |
| 非決定性欄位不造成假性 diff | 是 | 同輸入兩次跑 baseline 比對穩定 | M5 |

## 關聯（Relations）

- 被引用：ADR-002（引擎選型）、ADR-007（封裝）、ADR-009（ScanResult 欄位正規化）
- 參考：SDS §9、ROADMAP T503、SRS NFR-02/NFR-07
