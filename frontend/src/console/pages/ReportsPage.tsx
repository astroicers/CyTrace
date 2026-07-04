import { useTranslation } from 'react-i18next'
import { api, artifactUrl } from '../api/client'
import type { JobList } from '../api/types'
import { usePolling } from '../hooks/usePolling'
import { SeverityBadge } from '../../components/ui'
import { navigate } from '../router'
import { fmtTime } from '../format'

// 報表列表 = 已完成 job；沿用 jobs 列表過濾。有進行中 job 時 5s，否則 30s。
function interval(list: JobList | null): number {
  const active = list?.jobs.some(
    (j) => j.status === 'queued' || j.status === 'running',
  )
  return active ? 5000 : 30000
}

export function ReportsPage() {
  const { t } = useTranslation()
  const { data, error } = usePolling(api.listJobs, interval)
  const done = data?.jobs.filter((j) => j.status === 'done') ?? []

  return (
    <section>
      <h1 className="text-lg font-bold">{t('console.reports.title')}</h1>

      {error && !data && (
        <p role="alert" className="mt-6 text-sm text-sev-critical">
          {t('console.common.error')}
        </p>
      )}
      {!data && !error && (
        <p className="mt-6 text-sm text-gray-500">{t('console.common.loading')}</p>
      )}
      {data && done.length === 0 && (
        <p className="mt-6 text-sm text-gray-500">{t('console.reports.empty')}</p>
      )}

      {done.length > 0 && (
        <div className="mt-6 overflow-x-auto">
          <table className="w-full border-collapse text-sm">
            <thead>
              <tr className="border-b border-gray-200 text-left text-gray-500 dark:border-gray-800">
                <th className="py-2 pr-4 font-medium">{t('console.reports.col_target')}</th>
                <th className="py-2 pr-4 font-medium">{t('console.reports.col_risk')}</th>
                <th className="py-2 pr-4 font-medium">{t('console.reports.col_generated')}</th>
                <th className="py-2 font-medium" />
              </tr>
            </thead>
            <tbody>
              {done.map((job) => (
                <tr key={job.id} className="border-b border-gray-100 dark:border-gray-900">
                  <td className="py-2 pr-4 font-mono text-xs">{job.target}</td>
                  <td className="py-2 pr-4">
                    {job.summary && <SeverityBadge severity={job.summary.overall_risk} />}
                  </td>
                  <td className="py-2 pr-4 whitespace-nowrap text-gray-500">
                    {fmtTime(job.finished_at)}
                  </td>
                  <td className="py-2">
                    <div className="flex gap-3">
                      <a
                        href={artifactUrl.report(job.id)}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="text-sm font-medium text-sev-low hover:underline"
                      >
                        {t('console.reports.view')}
                      </a>
                      <button
                        type="button"
                        onClick={() => navigate({ page: 'job', id: job.id })}
                        className="text-sm text-gray-500 hover:underline"
                      >
                        {t('console.reports.detail')}
                      </button>
                    </div>
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
