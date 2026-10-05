# [ADR-002]: 掃描引擎選型（Syft + Grype；避開中國來源）

| 欄位 | 內容 |
|------|------|
| **狀態** | `Accepted` |
| **接受日期** | 2026-06-24（使用者授權代為升版） |
| **日期** | 2026-06-24 |
| **決策者** | CyTrace Team |

> **狀態說明：** `Draft`（初稿，禁止實作）→ `FIRM`（POC 驗證，允許 commit，需附驗證證據）→ `Accepted`（人類審核通過）

---

## 背景（Context）

CyTrace 需要兩種能力：（1）掃描目標（原始碼/容器映像/目錄）**產生 SBOM**；（2）以 SBOM **比對 CVE 漏洞**。
產品要進軍用採購，工具的**授權乾淨度**與**供應鏈來源**會被審查。SBOM 工具本身若引入有疑慮的來源，是自相矛盾的。

## 評估選項（Options Considered）

### 選項 A：Syft（SBOM）+ Grype（漏洞）+ Trivy（候補）
- **優點**：Syft/Grype 皆 Apache-2.0、同源（Anchore）、搭配順、可離線；輸出 CycloneDX/SPDX 標準格式；Trivy 亦 Apache-2.0，可作為錯誤比對的交叉驗證候補。
- **缺點**：多一個外部 binary 相依（以子程序隔離可控）。
- **風險**：上游版本變動 → 以釘選版本 + golden baseline 回歸測試緩解（策略見 **ADR-008** / ROADMAP T503）。

### 選項 B：OpenSCA-cli
- **優點**：功能涵蓋 SCA。
- **缺點**：**屬中國大陸來源**，踩採購產地汰除要件。
- **風險**：軍用驗收直接出局。

## 決策（Decision）

採用 **選項 A**：**Syft 產 SBOM、Grype 比對 CVE**，兩者皆 Apache-2.0、可離線、同源搭配；
**Trivy 列為候補**（交叉驗證/未來告警），同為 Apache-2.0。
**明確禁止採用 OpenSCA-cli 等中國大陸來源工具或依賴**（寫入 CLAUDE.md 鐵則）。
引擎以**子程序**呼叫，與核心解耦，便於釘選版本與替換。

## 後果（Consequences）

**正面影響：**
- 授權乾淨（Apache-2.0），NOTICE 可清楚標示；通過產地審查。
- 標準 SBOM 格式（CycloneDX 主、SPDX 備），可直接併入交件。

**負面影響 / 技術債：**
- 需管理外部 binary 版本與其漏洞 DB（見 ADR-003）。

**後續追蹤：**
- ADR-003 處理離線漏洞 DB；ADR-007 處理引擎釘選與封裝。

## 成功指標（Success Metrics）

| 指標 | 目標值 | 驗證方式 | 檢查時間 |
|------|--------|----------|----------|
| 交件第三方元件授權 | 工具本體全為 Apache-2.0；相依之非 Apache 成分（MIT／MPL-2.0）須列 NOTICE（ADR-013 修訂） | NOTICE/授權盤點 | M4 |
| 中國來源依賴數（專案／組織層級） | 0 | 依賴盤點（域名／著作權／維護組織三層）+ CyTrace 自掃 SBOM | M4/M5 |
| SBOM 格式相容性 | CycloneDX + SPDX 可輸出 | 以標準驗證器檢查輸出 | M1 |

## 關聯（Relations）

- 參考：ADR-003（離線 DB）、ADR-007（封裝）、ADR-008（golden baseline 策略）

## 待辦（範圍註記）

- **Trivy 候補目前無 ROADMAP 任務/spike 佔位**：本 ADR 將 Trivy 列為候補（交叉驗證/設定錯誤/secrets/IaC），但 M0–M5 未排任何任務。
  若未來要落地「交叉驗證」能力，須另開 spike 與 ADR；現階段刻意不納入（穩定優先、不加非必要功能）。

## 修訂：SPDX 輸出落地（2026-10-05，T919）

**裁定來源**：本 ADR 原已決定「CycloneDX 主、SPDX 備」，本節記錄實作與一項取捨，不改變決策。使用者 2026-10-05
授權依建議推進至專案完整。

- **產出方式**：同一次 syft 執行以 `-o cyclonedx-json -o spdx-json=<暫存檔>` 產出兩種格式，元件出自同一次編目，
  不為 SPDX 再掃一次。釘選版 syft 1.45.1 輸出 SPDX 2.3。
- **何時產出**：CLI `scan --spdx` 才產（預設關閉，既有產物不變）；web 模式一律產，由使用者在控制台選擇下載格式。
- **成功指標「以標準驗證器檢查輸出」的實際作法**：以 spdx-spec 官方 2.3 JSON schema 一次性實測零違規
  （schema 未 vendored，查證紀錄在本機 `.asp-fact-check.md`）。持續性的檢查是 CI 真引擎 job：以釘選 syft
  驗 `spdxVersion` 為 SPDX-2.3，且兩種格式的套件（名稱與版本）一致。
- **失敗處置採 fail-closed（與 CBOM 不同）**：SPDX 缺檔、不是 JSON、或缺 `spdxVersion` 時，整次掃描失敗
  （CLI 退出碼 1；web 模式 job 失敗）。CBOM 失敗只降級該區段（ADR-013 決策 4），SPDX 不比照，理由：
  SPDX 與 CycloneDX 出自同一次 syft 執行，SPDX 壞掉代表 syft 本身的輸出不可信，CycloneDX 也不宜單獨交件；
  而 CBOM 是另一支獨立引擎，壞掉不影響 SBOM 的可信度。
