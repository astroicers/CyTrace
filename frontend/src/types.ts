// 對應 Rust cytrace-types::ScanResult（serde 序列化形式）。
export type Severity =
  | 'Critical'
  | 'High'
  | 'Medium'
  | 'Low'
  | 'Negligible'
  | 'Unknown'

export const SEVERITY_ORDER: Severity[] = [
  'Critical',
  'High',
  'Medium',
  'Low',
  'Negligible',
  'Unknown',
]

export const SEVERITY_KEY: Record<Severity, string> = {
  Critical: 'severity.critical',
  High: 'severity.high',
  Medium: 'severity.medium',
  Low: 'severity.low',
  Negligible: 'severity.negligible',
  Unknown: 'severity.unknown',
}

export interface Vulnerability {
  id: string
  severity: Severity
  cvss?: number | null
  component: string
  fixed_version?: string | null
  /** 漏洞公告來源（Grype `dataSource` 網址）；不是元件位置。 */
  source: string
  /** v3：受影響元件的版本與 purl、所在位置（ADR-009「修訂：schema v3」）。舊版 JSON 無此欄位。 */
  component_version?: string | null
  component_purl?: string | null
  locations?: string[]
}

export interface Component {
  name: string
  version: string
  type: string
  licenses: string[]
  /** v3：CycloneDX bom-ref、purl、被找到的位置（相對於掃描根目錄）。舊版 JSON 無此欄位。 */
  bom_ref?: string | null
  purl?: string | null
  locations?: string[]
}

// ── CBOM 密碼學資產（ADR-013）──

export type QuantumStatus = 'Safe' | 'Vulnerable' | 'NotApplicable' | 'Unknown'

export const QUANTUM_KEY: Record<QuantumStatus, string> = {
  Safe: 'crypto.quantum.safe',
  Vulnerable: 'crypto.quantum.vulnerable',
  NotApplicable: 'crypto.quantum.not_applicable',
  Unknown: 'crypto.quantum.unknown',
}

/**
 * CBOM 掃描狀態。四態必須可區分——空輸出絕不等於「掃到 0 項」（ADR-013 決策 4/7）。
 * Rust 端為 externally-tagged enum：單位變體序列化為字串，Failed 序列化為物件。
 */
export type CbomStatus =
  | 'NotRequested'
  | 'EngineAbsent'
  | 'Completed'
  | { Failed: { reason_key: string; reason_detail?: string | null } }

/** 單一密碼學資產。不含金鑰內容（NFR-09）。 */
export interface CryptoAsset {
  name: string
  asset_type: string
  quantum: QuantumStatus
  /** 弱金鑰；與 quantum 為獨立兩軸（RSA-4096 為 Vulnerable 但非弱金鑰）。 */
  weak_key: boolean
  location: string
  primitive?: string | null
  key_size?: number | null
  not_after?: string | null
}

export interface CryptoInventory {
  status: CbomStatus
  assets: CryptoAsset[]
  /** 因**權限不可讀**而未掃描的項目數——可由操作員調整權限解決。 */
  unscanned_unreadable: number
  /** 因**引擎 1 MiB 大小門檻**而未掃描的檔案數——操作員無法以權限或參數解除。 */
  unscanned_oversize: number
  /** 引擎**自承偵測到但未能建模輸出**的資產數——引擎覆蓋率限制。 */
  unscanned_undetermined: number
}

export interface ScanResult {
  schema_version: number
  meta: {
    target: string
    tool_versions: { syft: string; grype: string; theia?: string | null }
    db_snapshot: { version: string; built: string }
    generated_at: string
    /** 執行掃描的身分（ADR-013 決策 10）。 */
    scan_identity?: string | null
  }
  components: Component[]
  findings: Vulnerability[]
  summary: {
    counts_by_severity: Partial<Record<Severity, number>>
    overall_risk: Severity
  }
  /** v1 報表無此欄位。 */
  crypto?: CryptoInventory | null
}
