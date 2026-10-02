import { useTranslation } from 'react-i18next'
import { describeJobError } from '../jobError'
import { api, artifactUrl } from '../api/client'
import type { JobRecord } from '../api/types'
import { usePolling } from '../hooks/usePolling'
import { StatusBadge } from '../components/StatusBadge'
import { SeverityBadge } from '../../components/ui'
import { SEVERITY_ORDER, SEVERITY_KEY } from '../../types'
import { navigate } from '../router'
import { fmtTime } from '../format'
import { effectiveLang } from '../../langs'

// 非終態 → 2s 輪詢；終態停止。
function interval(job: JobRecord | null): number {
  if (job && (job.status === 'queued' || job.status === 'running')) return 2000
  return 1_000_000_000 // 終態：實質停止
}

export function JobDetailPage({ id }: { id: string }) {
  const { t, i18n } = useTranslation()
  const { data: job, error } = usePolling(() => api.getJob(id), interval)

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
    try {
      await api.deleteJob(id)
      navigate({ page: 'dashboard' })
    } catch {
      /* 401 由 client 攔截；其餘忽略（列表頁會反映） */
    }
  }

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
          </>
        )}
        {(canCancel || canDelete) && (
          <button
            type="button"
            onClick={() => void remove()}
            className="rounded border border-sev-critical/50 px-3 py-1.5 text-sm text-sev-critical hover:bg-sev-critical/5"
          >
            {t(canCancel ? 'console.job.cancel' : 'console.job.delete')}
          </button>
        )}
      </div>
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
