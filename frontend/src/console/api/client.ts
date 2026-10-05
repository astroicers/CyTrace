// Thin fetch wrapper：同源相對路徑、cookie 認證、統一錯誤 normalize、401 集中攔截。
import i18n from '../../i18n.ts'
import { appendLang, effectiveLang } from '../../langs.ts'
import { ApiError } from './types.ts'
import type { JobList, JobRecord, SessionInfo, VersionInfo } from './types.ts'

/**
 * 送給 server 的語系：**console 的 UI 語系**，不是瀏覽器的。
 *
 * server 依 `Accept-Language` 渲染錯誤 message。不送的話瀏覽器會帶自己的預設值——
 * 使用者把 console 切成 en-US、瀏覽器是 zh-TW，錯誤訊息照樣是中文（T909：
 * 「en-US 用戶端不得收到中文」的前端那一半）。fetch、上傳的 XHR 與 `withLang` 共用本函式。
 * 取的是**解析後**的語系，理由見 `effectiveLang`。
 */
export function uiLanguage(): string {
  return effectiveLang(i18n)
}

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
  const headers: Record<string, string> = { 'Accept-Language': uiLanguage() }
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
  createMountedJob: (root: string, path: string, failOn?: string, cbom = false) =>
    request<JobRecord>('/api/v1/jobs', {
      method: 'POST',
      body: {
        target: { kind: 'mounted', root, path },
        ...(failOn ? { fail_on: failOn } : {}),
        ...(cbom ? { cbom: true } : {}),
      },
    }),
  deleteJob: (id: string) =>
    request<void>(`/api/v1/jobs/${id}`, { method: 'DELETE' }),
}

/**
 * 在 URL 附上 UI 語系（`?lang=`）。
 *
 * `<a href>` 導覽請求無法設 header，所以 `Accept-Language` 那條路走不到——
 * 錯誤回應（404、壞路徑）會依**瀏覽器**語系渲染。server 的協商順序是
 * `?lang=` > `Accept-Language`，故導覽式請求以查詢參數帶語系
 * （T909 對抗式複審 v12/v17：原本只修了 fetch 與 XHR，第三條路徑漏了）。
 * 分隔符邏輯在 `appendLang`（純函式，行為由 console-lang-check.mts 驗）。
 */
export function withLang(url: string): string {
  return appendLang(url, uiLanguage())
}

/** 報表/產物同源 URL（另開分頁或下載，不經 JSON client）。一律經 `withLang`。 */
export const artifactUrl = {
  report: (id: string, download = false) =>
    withLang(`/api/v1/jobs/${id}/report${download ? '?download=1' : ''}`),
  result: (id: string) => withLang(`/api/v1/jobs/${id}/result`),
  /** 掃描產物（SBOM 兩種格式、grype、CBOM；server 以附件回應）。 */
  artifact: (id: string, kind: string) => withLang(`/api/v1/jobs/${id}/artifacts/${kind}`),
}
