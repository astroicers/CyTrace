# CyTrace

> 地端、無網際網路（軍用網路）場域的**軟體依賴風險報表產生器**。
> Air-gapped software dependency risk report generator for on-premise / military networks.

CyTrace 封裝 **Syft**（產 SBOM）與 **Grype**（比對 CVE）兩個 Apache-2.0 工具，
一鍵對目標（原始碼目錄／容器映像／檔案系統）產出可併入交件的**依賴風險報表**與
**軟體產品文件表（SBOM）**。

## 設計原則

- **零外連（air-gapped）**：執行期、報表、CI 一律不連網；漏洞比對用離線 grype DB 快照。
- **穩定優先**：Rust 單一 musl 靜態 binary、零 runtime 依賴、釘選版本、可重現建置、golden baseline 回歸測試。
- **可稽核交付**：交付物可 `sha256` + 簽章驗證；報表標註工具與 DB 版本/日期；附自產 SBOM。
- **雙語 i18n**：強制 `zh-TW`（fallback）與 `en-US`，禁止硬編碼。
- **供應鏈純淨**：僅 Apache-2.0 第三方（Syft/Grype），明確禁用中國來源依賴。

## 架構（概要）

**Rust CLI 核心**（`cytrace run|scan|report`，呼叫 Syft+Grype 子程序、serde 解析、嚴重度分級、`--fail-on`）
＋ **visual-web-stack DOM 子集前端**（雙語離線單檔 HTML 報表，build 後內嵌進 binary）。

```
cytrace run <目標> → Syft(SBOM) → Grype(離線DB,CVE) → 解析/分級 → 單檔 HTML 報表 + SBOM
```

## 文件

| 文件 | 說明 |
|------|------|
| [docs/SRS.md](docs/SRS.md) | 軟體需求規格（FR / NFR） |
| [docs/SDS.md](docs/SDS.md) | 軟體設計規格（Cargo workspace、子程序編排、資料模型） |
| [docs/UIUX_SPEC.md](docs/UIUX_SPEC.md) | 報表檢視器 UI/UX（雙語、嚴重度色票、a11y） |
| [docs/adr/](docs/adr/) | 架構決策紀錄 ADR-001 ～ ADR-009 |
| [ROADMAP.yaml](ROADMAP.yaml) | Autopilot 任務清單（唯一 live 狀態權威） |

## 開發治理（ASP）

本專案以 [AI-SOP-Protocol](https://github.com/astroicers/AI-SOP-Protocol) 治理（level: standard、autopilot enabled）。

- ADR 初始為 `Draft`；人類 `/asp:approve-adr` 升 `Accepted` 後，`/asp-autopilot` 才會解鎖對應里程碑實作。
- 常用：`make autopilot-validate`（驗證 ROADMAP）、`make audit-health`（健康審計）、`make help`（ASP 指令）。

## 狀態

🟡 規劃完成（治理骨架 + ROADMAP + 文件草案）。實作待 ADR 經人類審核 `Accepted` 後由 autopilot 逐里程碑進行。
