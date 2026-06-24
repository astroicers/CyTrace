import { useMemo, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { loadScanResult } from './data'
import { SEVERITY_ORDER, type Severity } from './types'
import { SeverityBadge, Toolbar } from './components/ui'

const result = loadScanResult()

function Section({
  id,
  title,
  children,
}: {
  id: string
  title: string
  children: React.ReactNode
}) {
  return (
    <section id={id} className="mt-8">
      <h2 className="mb-3 border-b border-gray-200 pb-1 text-lg font-bold dark:border-gray-700">
        {title}
      </h2>
      {children}
    </section>
  )
}

function Cover() {
  const { t } = useTranslation()
  const m = result.meta
  const rows: [string, string][] = [
    [t('report.cover'), m.target],
    ['Syft / Grype', `${m.tool_versions.syft} / ${m.tool_versions.grype}`],
    ['DB', `${m.db_snapshot.version}（${m.db_snapshot.built}）`],
    ['Generated', m.generated_at],
  ]
  return (
    <Section id="cover" title={t('report.cover')}>
      <dl className="grid grid-cols-[max-content_1fr] gap-x-6 gap-y-1 text-sm">
        {rows.map(([k, v]) => (
          <div key={k} className="contents">
            <dt className="text-gray-500">{k}</dt>
            <dd className="font-mono">{v}</dd>
          </div>
        ))}
      </dl>
    </Section>
  )
}

function RiskSummary({
  onPick,
  active,
}: {
  onPick: (s: Severity | null) => void
  active: Severity | null
}) {
  const { t } = useTranslation()
  const counts = result.summary.counts_by_severity
  return (
    <Section id="summary" title={t('report.summary')}>
      <div className="mb-3 flex items-center gap-3 text-sm">
        <span className="text-gray-500">{t('report.summary')}:</span>
        <SeverityBadge severity={result.summary.overall_risk} />
        <span className="text-gray-500">
          · {result.components.length} components · {result.findings.length}{' '}
          findings
        </span>
      </div>
      <div className="flex flex-wrap gap-2">
        {SEVERITY_ORDER.map((s) => (
          <button
            key={s}
            type="button"
            onClick={() => onPick(active === s ? null : s)}
            className={`rounded border px-3 py-1 text-sm ${
              active === s
                ? 'border-gray-900 ring-2 ring-gray-400 dark:border-gray-100'
                : 'border-gray-200 dark:border-gray-700'
            }`}
            aria-pressed={active === s}
          >
            <SeverityBadge severity={s} />
            <span className="ml-2 font-mono">{counts[s] ?? 0}</span>
          </button>
        ))}
      </div>
    </Section>
  )
}

function Findings({ filter }: { filter: Severity | null }) {
  const { t } = useTranslation()
  const rows = useMemo(
    () =>
      filter ? result.findings.filter((f) => f.severity === filter) : result.findings,
    [filter],
  )
  return (
    <Section id="findings" title={t('report.findings')}>
      <div className="overflow-x-auto">
        <table className="w-full border-collapse text-sm">
          <thead>
            <tr className="border-b border-gray-300 text-left dark:border-gray-600">
              <th scope="col" className="py-1 pr-3">
                {t('report.findings')}
              </th>
              <th scope="col" className="py-1 pr-3">
                CVE
              </th>
              <th scope="col" className="py-1 pr-3">
                CVSS
              </th>
              <th scope="col" className="py-1 pr-3">
                Component
              </th>
              <th scope="col" className="py-1 pr-3">
                Fixed
              </th>
              <th scope="col" className="py-1 pr-3">
                Source
              </th>
            </tr>
          </thead>
          <tbody>
            {rows.length === 0 && (
              <tr>
                <td colSpan={6} className="py-3 text-gray-500">
                  —
                </td>
              </tr>
            )}
            {rows.map((f) => (
              <tr
                key={f.id + f.component}
                className="border-b border-gray-100 dark:border-gray-800"
              >
                <td className="py-1 pr-3">
                  <SeverityBadge severity={f.severity} />
                </td>
                <td className="py-1 pr-3 font-mono">{f.id}</td>
                <td className="py-1 pr-3 font-mono">{f.cvss ?? '—'}</td>
                <td className="py-1 pr-3 font-mono">{f.component}</td>
                <td className="py-1 pr-3 font-mono">{f.fixed_version ?? '—'}</td>
                <td className="py-1 pr-3 text-gray-500">{f.source}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </Section>
  )
}

function Sbom() {
  const { t } = useTranslation()
  return (
    <Section id="sbom" title={t('report.sbom')}>
      <div className="overflow-x-auto">
        <table className="w-full border-collapse text-sm">
          <thead>
            <tr className="border-b border-gray-300 text-left dark:border-gray-600">
              <th scope="col" className="py-1 pr-3">
                Name
              </th>
              <th scope="col" className="py-1 pr-3">
                Version
              </th>
              <th scope="col" className="py-1 pr-3">
                Type
              </th>
              <th scope="col" className="py-1 pr-3">
                Licenses
              </th>
            </tr>
          </thead>
          <tbody>
            {result.components.map((c) => (
              <tr
                key={c.name + c.version}
                className="border-b border-gray-100 dark:border-gray-800"
              >
                <td className="py-1 pr-3 font-mono">{c.name}</td>
                <td className="py-1 pr-3 font-mono">{c.version}</td>
                <td className="py-1 pr-3 text-gray-500">{c.type}</td>
                <td className="py-1 pr-3 font-mono">{c.licenses.join(', ') || '—'}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </Section>
  )
}

function Notes() {
  const { t } = useTranslation()
  return (
    <Section id="notes" title={t('report.notes.title')}>
      <p className="rounded border border-amber-300 bg-amber-50 p-3 text-sm dark:border-amber-700 dark:bg-amber-950">
        ⚠️ {t('report.notes.disclaimer_not_pentest')}
      </p>
    </Section>
  )
}

export default function App() {
  const { t } = useTranslation()
  const [filter, setFilter] = useState<Severity | null>(null)
  return (
    <div className="mx-auto max-w-4xl bg-white px-4 py-6 text-gray-900 dark:bg-gray-950 dark:text-gray-100">
      <header className="flex items-center justify-between">
        <h1 className="text-xl font-bold">CyTrace — {t('report.title')}</h1>
        <Toolbar />
      </header>
      <Cover />
      <RiskSummary onPick={setFilter} active={filter} />
      <Findings filter={filter} />
      <Sbom />
      <Notes />
    </div>
  )
}
