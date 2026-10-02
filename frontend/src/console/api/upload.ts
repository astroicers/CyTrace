// 上傳用 XMLHttpRequest（fetch 無可靠 upload progress）。回傳可取消的 promise。
import { uiLanguage } from './client'
import { ApiError } from './types'
import type { JobRecord } from './types'

export interface UploadHandle {
  promise: Promise<JobRecord>
  abort: () => void
}

/** multipart 上傳掃描：file + 選用 fail_on；onProgress 回報 0–100。 */
export function uploadScan(
  file: File,
  failOn: string | undefined,
  onProgress: (percent: number) => void,
  cbom = false,
): UploadHandle {
  const xhr = new XMLHttpRequest()
  const form = new FormData()
  form.append('file', file)
  if (failOn) form.append('fail_on', failOn)
  if (cbom) form.append('cbom', 'true')

  const promise = new Promise<JobRecord>((resolve, reject) => {
    xhr.open('POST', '/api/v1/jobs/upload')
    xhr.withCredentials = true
    xhr.setRequestHeader('X-CyTrace-Request', '1')
    xhr.setRequestHeader('Accept-Language', uiLanguage())

    xhr.upload.onprogress = (e) => {
      if (e.lengthComputable) onProgress(Math.round((e.loaded / e.total) * 100))
    }
    xhr.onload = () => {
      let payload: unknown = null
      try {
        payload = JSON.parse(xhr.responseText)
      } catch {
        /* 非 JSON 回應：payload 留 null */
      }
      if (xhr.status >= 200 && xhr.status < 300) {
        resolve(payload as JobRecord)
      } else {
        const err = (payload as { error?: { kind?: string; message?: string } })
          ?.error
        reject(
          new ApiError(
            xhr.status,
            err?.kind ?? 'error',
            err?.message ?? 'console.common.error',
          ),
        )
      }
    }
    xhr.onerror = () =>
      reject(new ApiError(0, 'network', 'console.errors.network'))
    xhr.onabort = () => reject(new ApiError(0, 'aborted', 'console.common.cancel'))
    xhr.send(form)
  })

  return { promise, abort: () => xhr.abort() }
}
