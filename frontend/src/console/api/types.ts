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
}

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
export class ApiError extends Error {
  constructor(
    public status: number,
    public code: string,
    message: string,
  ) {
    super(message)
    this.name = 'ApiError'
  }
}
