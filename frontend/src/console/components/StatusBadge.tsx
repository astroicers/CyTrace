import { useTranslation } from 'react-i18next'
import type { JobStatus } from '../api/types'

const STATUS_BG: Record<JobStatus, string> = {
  queued: 'bg-status-queued',
  running: 'bg-status-running',
  done: 'bg-status-done',
  failed: 'bg-status-failed',
  canceled: 'bg-status-canceled',
  interrupted: 'bg-status-interrupted',
}

/** job 狀態徽章：色塊 + 文字（色非唯一資訊載體）。 */
export function StatusBadge({ status }: { status: JobStatus }) {
  const { t } = useTranslation()
  return (
    <span
      className={`inline-flex items-center gap-1 rounded px-2 py-0.5 text-xs font-semibold text-white ${STATUS_BG[status]}`}
    >
      <span aria-hidden="true">●</span>
      {t(`console.jobs.status_${status}`)}
    </span>
  )
}
