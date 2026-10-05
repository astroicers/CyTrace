// Console API 型別（對應 cytrace-server JSON）。
import type { Severity } from '../../types'

export type JobStatus =
  | 'queued'
  | 'running'
  | 'done'
  | 'failed'
  | 'canceled'
  | 'interrupted'

export interface JobError {
  kind: string
  i18n_key: string
  detail: string
}

export interface JobSummary {
  overall_risk: Severity
  counts_by_severity: Partial<Record<Severity, number>>
}

export interface JobRecord {
  id: string
  status: JobStatus
  target: string
  fail_on?: string | null
  created_at: string
  started_at?: string | null
  finished_at?: string | null
  summary?: JobSummary | null
  failon_triggered?: boolean | null
  error?: JobError | null
  /** 實際存在的產物（僅單筆查詢附上；T919）。 */
  artifacts?: ArtifactKind[]
}

/** 產物種類，對應 `GET /api/v1/jobs/{id}/artifacts/{kind}`（server `api::reports::ARTIFACTS`）。 */
export type ArtifactKind = 'sbom' | 'spdx' | 'grype' | 'cbom'

export interface JobList {
  jobs: JobRecord[]
  total: number
}

export interface VersionInfo {
  cytrace: string
  db: { present: boolean }
  upload_limit_mb: number
  scan_roots: string[]
}

export interface SessionInfo {
  user: string
  created_at: string
  expires_at: string
}

/** API 錯誤（client 統一 normalize）。 */
// 欄位明寫、不用參數屬性（`constructor(public status…)`）：node 的型別剝離不支援需要
// 轉換的語法，而 console-lang-check.mts 要能載入 client.ts（它 import 本檔）。
export class ApiError extends Error {
  status: number
  code: string
  constructor(status: number, code: string, message: string) {
    super(message)
    this.status = status
    this.code = code
    this.name = 'ApiError'
  }
}
