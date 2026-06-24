# [ADR-001]: 初始技術棧選型（Rust 核心 + React 報表 + 內嵌單檔）

| 欄位 | 內容 |
|------|------|
| **狀態** | `Draft` |
| **日期** | 2026-06-24 |
| **決策者** | CyTrace Team |

> **狀態說明：** `Draft`（初稿，禁止實作）→ `FIRM`（POC 驗證，允許 commit，需附驗證證據）→ `Accepted`（人類審核通過）

---

## 背景（Context）

CyTrace 是**軍用地端、無網際網路**場域的依賴風險報表產生器。原設計文件（暫名 `twsbom`）選 Python 為核心，
理由是「純 CLI、攻擊面小、易稽核」。但本產品的兩個硬約束會放大語言選型的後果：

1. **進場部署/更新申請耗時** → 目標機上若需安裝/維護直譯器 runtime（Python/Node）將顯著拖慢且增加風險。
2. **穩定與可稽核是第一優先** → 軍方驗收偏好可簽章、可 checksum、無傳遞依賴爆炸的單一交付物。

同時，前端報表要求採用 `visual-web-stack`（React），因此無論核心選什麼語言，都會帶進一套 Node build 工具鏈。

## 評估選項（Options Considered）

### 選項 A：Rust 核心 + React 報表檢視器（前端 build 成靜態 bundle 內嵌進 binary）
- **優點**：編出單一 musl 靜態 binary，零 runtime 依賴；目標機免裝直譯器；可簽章/checksum 稽核；可 `rust-embed` 內嵌報表 → 交付物收斂為「一顆 binary」；與既有 Athena/rust-skills 環境一致；型別系統編譯期擋錯。
- **缺點**：核心開發較 Python 慢；前端仍需 Node build（但只在開發/release 端，不上目標機）。
- **風險**：團隊需 Rust 熟練度（已具備）。

### 選項 B：Python 核心 + React 報表（文件原案）
- **優點**：開發快、生態豐富。
- **缺點**：目標機需 Python 3.10 runtime；pip 傳遞依賴多、攻擊面與稽核成本較大；離線封裝與長期維護較麻煩。
- **風險**：air-gapped 機房直譯器版本/相依漂移。

### 選項 C：全 TypeScript（CLI + 前端同一 Node 鏈）
- **優點**：單一語言鏈、與前端共用 i18n。
- **缺點**：目標機需 Node runtime，與「單一靜態 binary、可稽核」目標衝突。
- **風險**：同 B 的 runtime 問題。

## 決策（Decision）

採用 **選項 A**：**Rust（edition 2021）Cargo workspace 為核心**，`clap` 提供 `cytrace run|scan|report` 子命令；
**前端採 visual-web-stack DOM/UI 子集**，build 成單檔靜態 bundle，由核心 `rust-embed`/`include_bytes!` 內嵌，
報表產生時注入掃描資料。Syft/Grype 為 Go binary，以子程序呼叫，與核心語言無關。

**產品命名**：正式產品名與 binary 名為 **`CyTrace` / `cytrace`**，取代原設計文件暫名 `twsbom`；地端版為主要交付，SaaS 監管延後（範圍外）。

## 後果（Consequences）

**正面影響：**
- 交付物為單一可簽章靜態 binary（＋引擎與 DB 快照），最貼合 air-gapped 與長更新週期。
- 攻擊面小、可稽核；無目標機 runtime 維護負擔。

**負面影響 / 技術債：**
- 維持兩套 build 工具鏈（Rust + Node），release 端需各自離線可建。
- 報表變更需重 build 前端再重 embed。

**後續追蹤：**
- ADR-005（報表內嵌與單檔策略）、ADR-007（封裝/簽章）承接交付細節。

## 成功指標（Success Metrics）

| 指標 | 目標值 | 驗證方式 | 檢查時間 |
|------|--------|----------|----------|
| 目標機 runtime 依賴數 | 0 | `ldd cytrace`（musl 靜態應為 not a dynamic executable） | M4 |
| 交付 binary 可 checksum 驗證 | 是 | `sha256sum` 比對 release 清單 | M4 |
| 冷機（無直譯器）可執行 | 是 | 乾淨容器/VM 直接跑 `cytrace --version` | M4 |

## 關聯（Relations）

- 取代：（無，文件原案 Python 未落地）
- 參考：ADR-002（引擎）、ADR-004（i18n）、ADR-005（報表）、ADR-007（封裝）
