// Thin fetch wrapper：同源相對路徑、cookie 認證、統一錯誤 normalize、401 集中攔截。
import { ApiError } from './types'
import type { JobList, JobRecord, SessionInfo, VersionInfo } from './types'

// 變更型請求強制帶此標頭（後端 CSRF 第 2 層防禦，ADR-011）。
const CSRF_HEADER = 'X-CyTrace-Request'

let onUnauthorized: (() => void) | null = null
/** 註冊 401 攔截 callback（SessionProvider 設定：清 session + 導回登入）。 */
export function setUnauthorizedHandler(fn: () => void) {
  onUnauthorized = fn
}

interface Options {
  method?: string
  body?: unknown
  /** 401 時不觸發全域攔截（登入/whoami 探測用）。 */
  silent401?: boolean
}

async function request<T>(path: string, opts: Options = {}): Promise<T> {
  const method = opts.method ?? 'GET'
  const headers: Record<string, string> = {}
  const mutating = method !== 'GET' && method !== 'HEAD'
  if (mutating) headers[CSRF_HEADER] = '1'
  let body: BodyInit | undefined
  if (opts.body !== undefined) {
    headers['Content-Type'] = 'application/json'
    body = JSON.stringify(opts.body)
  }

  let resp: Response
  try {
    resp = await fetch(path, {
      method,
      headers,
      body,
      credentials: 'same-origin',
    })
  } catch {
    throw new ApiError(0, 'network', 'console.errors.network')
  }

  if (resp.status === 401 && !opts.silent401) {
    onUnauthorized?.()
  }
  if (resp.status === 204) return undefined as T
  const isJson = resp.headers.get('content-type')?.includes('application/json')
  const payload = isJson ? await resp.json() : null
  if (!resp.ok) {
    const err = payload?.error
    throw new ApiError(
      resp.status,
      err?.kind ?? 'error',
      err?.message ?? 'console.common.error',
    )
  }
  return payload as T
}

export const api = {
  // ── session ──
  login: (password: string) =>
    request<void>('/api/v1/session', {
      method: 'POST',
      body: { password },
      silent401: true,
    }),
  whoami: () =>
    request<SessionInfo>('/api/v1/session', { silent401: true }),
  logout: () => request<void>('/api/v1/session', { method: 'DELETE' }),

  // ── version / targets ──
  version: () => request<VersionInfo>('/api/v1/version'),

  // ── jobs ──
  listJobs: () => request<JobList>('/api/v1/jobs'),
  getJob: (id: string) => request<JobRecord>(`/api/v1/jobs/${id}`),
  createMountedJob: (root: string, path: string, failOn?: string) =>
    request<JobRecord>('/api/v1/jobs', {
      method: 'POST',
      body: {
        target: { kind: 'mounted', root, path },
        ...(failOn ? { fail_on: failOn } : {}),
      },
    }),
  deleteJob: (id: string) =>
    request<void>(`/api/v1/jobs/${id}`, { method: 'DELETE' }),
}

/** 報表/產物同源 URL（另開分頁或下載，不經 JSON client）。 */
export const artifactUrl = {
  report: (id: string, download = false) =>
    `/api/v1/jobs/${id}/report${download ? '?download=1' : ''}`,
  result: (id: string) => `/api/v1/jobs/${id}/result`,
}
