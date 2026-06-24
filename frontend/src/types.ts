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
  source: string
}

export interface Component {
  name: string
  version: string
  type: string
  licenses: string[]
}

export interface ScanResult {
  schema_version: number
  meta: {
    target: string
    tool_versions: { syft: string; grype: string }
    db_snapshot: { version: string; built: string }
    generated_at: string
  }
  components: Component[]
  findings: Vulnerability[]
  summary: {
    counts_by_severity: Partial<Record<Severity, number>>
    overall_risk: Severity
  }
}
