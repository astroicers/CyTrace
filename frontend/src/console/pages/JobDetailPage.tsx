import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { describeJobError } from '../jobError'
import { api, artifactUrl } from '../api/client'
import { ApiError, type ArtifactKind, type JobRecord } from '../api/types'
import { usePolling } from '../hooks/usePolling'
import { StatusBadge } from '../components/StatusBadge'
import { SeverityBadge } from '../../components/ui'
import { SEVERITY_ORDER, SEVERITY_KEY } from '../../types'
import { navigate } from '../router'
import { fmtTime } from '../format'
import { effectiveLang } from '../../langs'

/** 產物下載連結的文字（鍵寫成字面值，i18n-check 才查得到）。 */
const ARTIFACT_LABEL: Record<ArtifactKind, string> = {
  sbom: 'console.job.download_sbom',
  spdx: 'console.job.download_spdx',
  grype: 'console.job.download_grype',
  cbom: 'console.job.download_cbom',
}

// 非終態 → 2s 輪詢；終態停止。
function interval(job: JobRecord | null): number {
  if (job && (job.status === 'queued' || job.status === 'running')) return 2000
  return 1_000_000_000 // 終態：實質停止
}

export function JobDetailPage({ id }: { id: string }) {
  const { t, i18n } = useTranslation()
  const { data: job, error } = usePolling(() => api.getJob(id), interval)
  // 取消／刪除失敗時 server 回的訊息（例如已開始掃描時取消得到 409，#46），連同失敗的是哪個操作
  const [actionError, setActionError] = useState<{ msg: string; op: 'cancel' | 'delete' } | null>(
    null,
  )

  if (error && !job) {
    return (
      <section>
        <BackLink />
        <p role="alert" className="mt-6 text-sm text-sev-critical">
          {t('console.common.error')}
        </p>
      </section>
    )
  }
  if (!job) {
    return (
      <section>
        <BackLink />
        <p className="mt-6 text-sm text-gray-500">{t('console.common.loading')}</p>
      </section>
    )
  }

  const terminal = job.status !== 'queued' && job.status !== 'running'
  const canCancel = job.status === 'queued'
  const canDelete = terminal
  const hasReport = job.status === 'done'

  const remove = async () => {
    const op = canCancel ? 'cancel' : 'delete'
    setActionError(null)
    try {
      await api.deleteJob(id)
      navigate({ page: 'dashboard' })
    } catch (err) {
      // 401 由 client 攔截（導回登入）；其餘把 server 的訊息顯示出來，與新掃描頁的做法相同
      const msg = err instanceof ApiError ? t(err.message) : t('console.common.error')
      setActionError({ msg, op })
    }
  }
  // 取消失敗的提示只在 job 尚未結束時有意義：掃描完成後「刪除」鈕出現，「請等掃描完成」已過時。
  // 刪除失敗（對已結束的 job）的提示則照常顯示，不能一律以 terminal 隱藏
  const shownError = actionError && !(actionError.op === 'cancel' && terminal) ? actionError.msg : null

  return (
    <section>
      <BackLink />
      <div className="mt-4 flex items-center gap-3">
        <h1 className="text-lg font-bold">{t('console.job.title')}</h1>
        <StatusBadge status={job.status} />
        {job.failon_triggered && (
          <span className="rounded bg-status-interrupted px-2 py-0.5 text-xs font-semibold text-white">
            {t('console.jobs.failon_triggered')}
          </span>
        )}
      </div>

      <dl className="mt-6 grid gap-3 text-sm">
        <Row label={t('console.job.target')} value={<span className="font-mono text-xs">{job.target}</span>} />
        <Row label={t('console.job.created')} value={fmtTime(job.created_at)} />
        <Row label={t('console.job.started')} value={fmtTime(job.started_at)} />
        <Row label={t('console.job.finished')} value={fmtTime(job.finished_at)} />
        {job.summary && (
          <Row
            label={t('console.job.risk')}
            value={<SeverityBadge severity={job.summary.overall_risk} />}
          />
        )}
      </dl>

      {!terminal && (
        <p className="mt-4 text-sm text-gray-500" aria-live="polite">
          {t('console.job.running_hint')}
        </p>
      )}

      {job.summary && (
        <div className="mt-6">
          <h2 className="text-sm font-semibold text-gray-600 dark:text-gray-400">
            {t('console.job.counts')}
          </h2>
          <ul className="mt-2 flex flex-wrap gap-2">
            {SEVERITY_ORDER.map((sev) => {
              const n = job.summary?.counts_by_severity[sev] ?? 0
              return (
                <li
                  key={sev}
                  className="flex items-center gap-1.5 rounded border border-gray-200 px-2 py-1 text-xs dark:border-gray-800"
                >
                  <span>{t(SEVERITY_KEY[sev])}</span>
                  <span className="font-mono font-semibold">{n}</span>
                </li>
              )
            })}
          </ul>
        </div>
      )}

      {job.error && (
        <div className="mt-6 rounded border border-sev-critical/40 bg-sev-critical/5 p-3">
          <h2 className="text-sm font-semibold text-sev-critical">
            {t('console.job.error_title')}
          </h2>
          {/* 訊息與 detail 的分工由 describeJobError 一次決定，`<pre>` 只看它的回報。
              兩處各判一次必然會不同步——第九輪加退回路徑時 `<p>` 印了 detail、
              `<pre>` 的守衛沒跟著改，同一段印兩次（第十輪複審），而同一個 commit
              在 CLI 側正好斷言「細節不得重複出現」。 */}
          {(() => {
            const { text, detailConsumed } = describeJobError(job.error, t, effectiveLang(i18n))
            return (
              <>
                <p className="mt-1 text-sm">{text}</p>
                {job.error.detail && !detailConsumed && (
                  <pre className="mt-2 overflow-x-auto text-xs text-gray-500">
                    {job.error.detail}
                  </pre>
                )}
              </>
            )
          })()}
        </div>
      )}

      <div className="mt-8 flex flex-wrap gap-2">
        {hasReport && (
          <>
            <a
              href={artifactUrl.report(id)}
              target="_blank"
              rel="noopener noreferrer"
              className="rounded bg-gray-900 px-3 py-1.5 text-sm font-semibold text-white hover:bg-gray-800 dark:bg-gray-100 dark:text-gray-900 dark:hover:bg-white"
            >
              {t('console.job.view_report')}
            </a>
            <a
              href={artifactUrl.report(id, true)}
              className="rounded border border-gray-300 px-3 py-1.5 text-sm hover:bg-gray-100 dark:border-gray-600 dark:hover:bg-gray-800"
            >
              {t('console.job.download_report')}
            </a>
            <a
              href={artifactUrl.result(id)}
              className="rounded border border-gray-300 px-3 py-1.5 text-sm hover:bg-gray-100 dark:border-gray-600 dark:hover:bg-gray-800"
            >
              {t('console.job.download_result')}
            </a>
            {/* 只列實際存在的產物（server 回報）；升級前的 job 沒有 SPDX，不給點了才 404 的按鈕 */}
            {(job.artifacts ?? []).map((kind) => (
              <a
                key={kind}
                href={artifactUrl.artifact(id, kind)}
                className="rounded border border-gray-300 px-3 py-1.5 text-sm hover:bg-gray-100 dark:border-gray-600 dark:hover:bg-gray-800"
              >
                {t(ARTIFACT_LABEL[kind])}
              </a>
            ))}
          </>
        )}
      </div>
      {/* 破壞性操作獨立一列：下載連結變多後會換行，混在同一列時位置不固定、容易誤按 */}
      {(canCancel || canDelete) && (
        <div className="mt-6">
          <button
            type="button"
            onClick={() => void remove()}
            className="rounded border border-sev-critical/50 px-3 py-1.5 text-sm text-sev-critical hover:bg-sev-critical/5"
          >
            {t(canCancel ? 'console.job.cancel' : 'console.job.delete')}
          </button>
        </div>
      )}
      {/* 放在按鈕區塊之外：取消失敗多半是 job 剛開始掃描，下一次輪詢讀到 running 後按鈕會消失，
          訊息要留著說明原因 */}
      {shownError && (
        <p role="alert" className="mt-2 text-sm text-sev-critical">
          {shownError}
        </p>
      )}
    </section>
  )
}

function BackLink() {
  const { t } = useTranslation()
  return (
    <button
      type="button"
      onClick={() => navigate({ page: 'dashboard' })}
      className="text-sm text-gray-500 hover:underline"
    >
      ← {t('console.common.back')}
    </button>
  )
}

function Row({ label, value }: { label: string; value: React.ReactNode }) {
  return (
    <div className="flex gap-4">
      <dt className="w-28 shrink-0 text-gray-500">{label}</dt>
      <dd>{value}</dd>
    </div>
  )
}
