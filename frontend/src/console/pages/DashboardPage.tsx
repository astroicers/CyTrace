import { useTranslation } from 'react-i18next'
import { api } from '../api/client'
import type { JobList } from '../api/types'
import { usePolling } from '../hooks/usePolling'
import { StatusBadge } from '../components/StatusBadge'
import { SeverityBadge } from '../../components/ui'
import { hrefFor, navigate } from '../router'
import { fmtTime } from '../format'

// 有進行中 job → 3s，否則 15s（setTimeout 鏈，非裸 interval）。
function interval(list: JobList | null): number {
  const active = list?.jobs.some(
    (j) => j.status === 'queued' || j.status === 'running',
  )
  return active ? 3000 : 15000
}

export function DashboardPage() {
  const { t } = useTranslation()
  const { data, error, reload } = usePolling(api.listJobs, interval)

  return (
    <section>
      <div className="flex items-center justify-between">
        <h1 className="text-lg font-bold">{t('console.jobs.title')}</h1>
        <div className="flex items-center gap-2">
          <button
            type="button"
            onClick={reload}
            className="rounded border border-gray-300 px-3 py-1.5 text-sm hover:bg-gray-100 dark:border-gray-600 dark:hover:bg-gray-800"
          >
            {t('console.jobs.refresh')}
          </button>
          <a
            href={hrefFor({ page: 'newScan' })}
            className="rounded bg-gray-900 px-3 py-1.5 text-sm font-semibold text-white hover:bg-gray-800 dark:bg-gray-100 dark:text-gray-900 dark:hover:bg-white"
          >
            {t('console.jobs.new_scan')}
          </a>
        </div>
      </div>

      {error && !data && (
        <p role="alert" className="mt-6 text-sm text-sev-critical">
          {t('console.common.error')}
        </p>
      )}
      {!data && !error && (
        <p className="mt-6 text-sm text-gray-500">{t('console.common.loading')}</p>
      )}
      {data && data.jobs.length === 0 && (
        <p className="mt-6 text-sm text-gray-500">{t('console.jobs.empty')}</p>
      )}

      {data && data.jobs.length > 0 && (
        <div className="mt-6 overflow-x-auto">
          <table className="w-full border-collapse text-sm">
            <thead>
              <tr className="border-b border-gray-200 text-left text-gray-500 dark:border-gray-800">
                <th className="py-2 pr-4 font-medium">{t('console.jobs.col_target')}</th>
                <th className="py-2 pr-4 font-medium">{t('console.jobs.col_status')}</th>
                <th className="py-2 pr-4 font-medium">{t('console.jobs.col_risk')}</th>
                <th className="py-2 pr-4 font-medium">{t('console.jobs.col_created')}</th>
                <th className="py-2 font-medium">{t('console.jobs.col_actions')}</th>
              </tr>
            </thead>
            <tbody>
              {data.jobs.map((job) => (
                <tr
                  key={job.id}
                  className="border-b border-gray-100 dark:border-gray-900"
                >
                  <td className="py-2 pr-4 font-mono text-xs">{job.target}</td>
                  <td className="py-2 pr-4">
                    <StatusBadge status={job.status} />
                  </td>
                  <td className="py-2 pr-4">
                    {job.summary ? (
                      <SeverityBadge severity={job.summary.overall_risk} />
                    ) : (
                      <span className="text-gray-400">-</span>
                    )}
                  </td>
                  <td className="py-2 pr-4 whitespace-nowrap text-gray-500">
                    {fmtTime(job.created_at)}
                  </td>
                  <td className="py-2">
                    <button
                      type="button"
                      onClick={() => navigate({ page: 'job', id: job.id })}
                      className="text-sm font-medium text-sev-low hover:underline"
                    >
                      {t('console.jobs.view')}
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </section>
  )
}
