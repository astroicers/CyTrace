import { useEffect, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { api } from '../api/client'
import type { VersionInfo } from '../api/types'

export function SystemPage() {
  const { t } = useTranslation()
  const [info, setInfo] = useState<VersionInfo | null>(null)
  const [error, setError] = useState(false)

  useEffect(() => {
    api.version().then(setInfo).catch(() => setError(true))
  }, [])

  if (error)
    return (
      <section>
        <h1 className="text-lg font-bold">{t('console.system.title')}</h1>
        <p role="alert" className="mt-6 text-sm text-sev-critical">
          {t('console.common.error')}
        </p>
      </section>
    )
  if (!info)
    return (
      <section>
        <h1 className="text-lg font-bold">{t('console.system.title')}</h1>
        <p className="mt-6 text-sm text-gray-500">{t('console.common.loading')}</p>
      </section>
    )

  return (
    <section>
      <h1 className="text-lg font-bold">{t('console.system.title')}</h1>
      <dl className="mt-6 grid gap-3 text-sm">
        <Row label={t('console.system.cytrace_version')} value={<span className="font-mono">{info.cytrace}</span>} />
        <Row
          label={t('console.system.db_status')}
          value={
            <span className={info.db.present ? 'text-status-done' : 'text-sev-critical'}>
              {t(info.db.present ? 'console.system.db_present' : 'console.system.db_absent')}
            </span>
          }
        />
        <Row
          label={t('console.system.upload_limit')}
          value={<span className="font-mono">{info.upload_limit_mb} MB</span>}
        />
        <Row
          label={t('console.system.scan_roots')}
          value={
            info.scan_roots.length > 0 ? (
              <span className="font-mono text-xs">{info.scan_roots.join(', ')}</span>
            ) : (
              <span className="text-gray-400">-</span>
            )
          }
        />
      </dl>
    </section>
  )
}

function Row({ label, value }: { label: string; value: React.ReactNode }) {
  return (
    <div className="flex gap-4">
      <dt className="w-40 shrink-0 text-gray-500">{label}</dt>
      <dd>{value}</dd>
    </div>
  )
}
