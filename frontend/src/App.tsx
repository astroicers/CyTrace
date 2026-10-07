import { useMemo, useState } from 'react'
import type { TFunction } from 'i18next'
import { useTranslation } from 'react-i18next'
import { loadScanResult } from './data'
import { SEVERITY_ORDER, type CryptoInventory, type Severity } from './types'
import { renderCbomFailure } from './cbom'
import { effectiveLang } from './langs'
import { QuantumBadge, SeverityBadge, Toolbar } from './components/ui'

const result = loadScanResult()

function Section({
  id,
  title,
  source,
  children,
}: {
  id: string
  title: string
  /** 產生本區段資料的工具與版本（ADR-009「修訂：schema v3」）。 */
  source?: string
  children: React.ReactNode
}) {
  return (
    <section id={id} className="mt-8">
      <h2 className="mb-3 border-b border-gray-200 pb-1 text-lg font-bold dark:border-gray-700">
        {title}
      </h2>
      {source && <p className="-mt-2 mb-3 text-xs text-gray-500">{source}</p>}
      {children}
    </section>
  )
}

/** 弱點資料庫快照的顯示字串；'unavailable'（v2 sentinel）與 'snapshot'（v1 假值）不得渲染成像真值。
 *  括號依語言（中文全形、英文半形），由 `report.db_label` 決定。 */
function dbLabel(t: TFunction): string {
  const db = result.meta.db_snapshot
  return db.version === 'unavailable' || db.version === 'snapshot'
    ? t('report.db_unavailable')
    : t('report.db_label', { version: db.version, built: db.built })
}

/**
 * 位置清單：先列 `limit` 處，其餘按需展開。展開前不渲染其餘位置，控制長清單的 DOM 與列印篇幅；
 * 完整清單仍在 ScanResult 與 SBOM JSON（ADR-009「修訂：schema v3」）。
 */
function Locations({ paths, limit }: { paths?: string[]; limit: number }) {
  const { t } = useTranslation()
  const [open, setOpen] = useState(false)
  const all = paths ?? []
  if (all.length === 0) return <span className="text-gray-500">—</span>
  const shown = open ? all : all.slice(0, limit)
  const rest = all.length - limit
  return (
    <div className="text-xs">
      {shown.map((p, i) => (
        <div key={i} className="font-mono break-all">
          {p}
        </div>
      ))}
      {rest > 0 && (
        <button
          type="button"
          aria-expanded={open}
          onClick={() => setOpen(!open)}
          className="mt-0.5 text-gray-500 underline hover:text-gray-700 dark:hover:text-gray-300"
        >
          {open ? t('report.fewer_locations') : t('report.more_locations', { n: rest })}
        </button>
      )}
    </div>
  )
}

function Cover() {
  const { t } = useTranslation()
  const m = result.meta
  const rows: [string, string][] = [
    [t('report.meta.target'), m.target],
    ['Syft / Grype', `${m.tool_versions.syft} / ${m.tool_versions.grype}`],
    ...(m.tool_versions.theia
      ? ([['CBOMkit-theia', m.tool_versions.theia]] as [string, string][])
      : []),
    ...(m.scan_identity
      ? ([[t('report.scan_identity'), m.scan_identity]] as [string, string][])
      : []),
    // "unavailable" 是 core 的 fail-closed sentinel（grype db status 取不到時）；
    // 原樣印英文 sentinel 對操作員無意義，譯為明確的「無法取得」訊息（NFR-03/NFR-06）
    [t('report.meta.db'), dbLabel(t)],
    [t('report.meta.generated_at'), m.generated_at],
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
        <span className="text-gray-500">
          {t('ui.labeled', { label: t('report.summary') })}
        </span>
        <SeverityBadge severity={result.summary.overall_risk} />
        <span className="text-gray-500">
          {t('report.counts', {
            components: result.components.length,
            findings: result.findings.length,
          })}
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
    <Section
      id="findings"
      title={t('report.findings')}
      source={t('report.provenance.findings', {
        version: result.meta.tool_versions.grype,
        db: dbLabel(t),
      })}
    >
      <div className="overflow-x-auto">
        <table className="w-full border-collapse text-sm">
          <thead>
            <tr className="border-b border-gray-300 text-left dark:border-gray-600">
              {(
                ['severity', 'cve', 'cvss', 'component', 'fixed', 'source'] as const
              ).map((c) => (
                <th key={c} scope="col" className="py-1 pr-3">
                  {t(`report.col.${c}`)}
                </th>
              ))}
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
            {rows.map((f, i) => (
              // 同一 CVE 可能命中同名元件的多個實例，id＋名稱會撞號
              <tr key={`${f.id}-${i}`} className="border-b border-gray-100 dark:border-gray-800">
                <td className="py-1 pr-3">
                  <SeverityBadge severity={f.severity} />
                </td>
                <td className="py-1 pr-3 font-mono">{f.id}</td>
                <td className="py-1 pr-3 font-mono">{f.cvss ?? '—'}</td>
                <td className="py-1 pr-3">
                  <div className="font-mono">
                    {f.component}
                    {f.component_version ? ` ${f.component_version}` : ''}
                  </div>
                  {f.locations && f.locations.length > 0 && (
                    <Locations paths={f.locations} limit={1} />
                  )}
                </td>
                <td className="py-1 pr-3 font-mono">{f.fixed_version ?? '—'}</td>
                <td className="py-1 pr-3 break-all text-gray-500">{f.source}</td>
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
    <Section
      id="sbom"
      title={t('report.sbom')}
      source={t('report.provenance.sbom', { version: result.meta.tool_versions.syft })}
    >
      <div className="overflow-x-auto">
        <table className="w-full border-collapse text-sm">
          <thead>
            <tr className="border-b border-gray-300 text-left dark:border-gray-600">
              {(['name', 'version', 'type', 'licenses', 'location'] as const).map((c) => (
                <th key={c} scope="col" className="py-1 pr-3">
                  {t(`report.col.${c}`)}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {result.components.map((c, i) => (
              // 同一 name@version 出現在多份 lockfile 時是不同元件；以 bom-ref 為鍵，舊版 JSON 以索引補位
              <tr key={c.bom_ref ?? `i${i}`} className="border-b border-gray-100 dark:border-gray-800">
                <td className="py-1 pr-3">
                  <div className="font-mono">{c.name}</div>
                  {c.purl && <div className="font-mono text-xs break-all text-gray-500">{c.purl}</div>}
                </td>
                <td className="py-1 pr-3 font-mono">{c.version}</td>
                <td className="py-1 pr-3 text-gray-500">{c.type}</td>
                <td className="py-1 pr-3 font-mono">{c.licenses.join(', ') || '—'}</td>
                <td className="py-1 pr-3">
                  <Locations paths={c.locations} limit={2} />
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </Section>
  )
}

/**
 * 未取得盤點結果時的說明（四態中的三態；ADR-013 決策 4）。
 *
 * `Failed` 另外帶**成因**：Rust 端存的是純 i18n 鍵 + 不可翻譯細節，於此依當前語系渲染。
 * 少了它，操作員拿到交件報表只看到「盤點未完成」，不知道是逾時、目標被拒還是輸出不合法
 * ——fail-closed 的訊息就斷在 CLI stderr，交件對象完全看不到。
 */
function cryptoStatus(
  crypto: CryptoInventory | null | undefined,
): { key: string; failure?: { reasonKey?: string; reasonDetail?: string | null } } | null {
  if (!crypto) return { key: 'report.crypto.not_executed' }
  const s = crypto.status
  if (s === 'NotRequested') return { key: 'report.crypto.not_executed' }
  if (s === 'EngineAbsent') return { key: 'report.crypto.engine_absent' }
  if (typeof s === 'object' && 'Failed' in s) {
    return {
      key: 'report.crypto.failed',
      failure: {
        reasonKey: s.Failed.reason_key,
        reasonDetail: s.Failed.reason_detail,
      },
    }
  }
  return null
}

function Crypto() {
  const { t, i18n } = useTranslation()
  const crypto = result.crypto
  const status = cryptoStatus(crypto)
  const assets = crypto?.assets ?? []
  const stats = useMemo(() => {
    const now = Date.now()
    return {
      total: assets.length,
      vulnerable: assets.filter((a) => a.quantum === 'Vulnerable').length,
      weak: assets.filter((a) => a.weak_key).length,
      expired: assets.filter(
        (a) => a.not_after && Date.parse(a.not_after) < now,
      ).length,
    }
  }, [assets])

  return (
    <Section
      id="crypto"
      title={t('report.crypto.title')}
      // 只在盤點完成時標來源：未執行、引擎缺席、失敗時沒有由該工具產出的資料
      source={
        !status && result.meta.tool_versions.theia
          ? t('report.provenance.crypto', { version: result.meta.tool_versions.theia })
          : undefined
      }
    >
      {status ? (
        <div className="text-sm text-gray-500">
          <p>{t(status.key)}</p>
          {status.failure && (
            <p className="mt-1 font-mono text-xs break-all">
              {renderCbomFailure(
                t,
                status.failure.reasonKey,
                status.failure.reasonDetail,
                effectiveLang(i18n),
              )}
            </p>
          )}
        </div>
      ) : (
        <>
          <div className="mb-3 flex flex-wrap gap-x-6 gap-y-1 text-sm">
            {(
              [
                ['total', stats.total],
                ['vulnerable', stats.vulnerable],
                ['weak_keys', stats.weak],
                ['expired', stats.expired],
              ] as const
            ).map(([key, value]) => (
              <span key={key}>
                <span className="text-gray-500">
                  {t('ui.labeled', { label: t(`report.crypto.summary.${key}`) })}
                </span>
                <span className="ml-1 font-mono font-semibold">{value}</span>
              </span>
            ))}
          </div>

          {crypto && crypto.unscanned_unreadable +
            crypto.unscanned_oversize +
            crypto.unscanned_undetermined >
            0 && (
            <div className="mb-3 space-y-1 rounded border border-amber-300 bg-amber-50 p-3 text-sm dark:border-amber-700 dark:bg-amber-950">
              {crypto.unscanned_unreadable > 0 && (
                <p>
                  {t('report.crypto.unscanned_unreadable', {
                    count: crypto.unscanned_unreadable,
                  })}
                </p>
              )}
              {crypto.unscanned_oversize > 0 && (
                <p>
                  {t('report.crypto.unscanned_oversize', {
                    count: crypto.unscanned_oversize,
                  })}
                </p>
              )}
              {crypto.unscanned_undetermined > 0 && (
                <p>
                  {t('report.crypto.unscanned_undetermined', {
                    count: crypto.unscanned_undetermined,
                  })}
                </p>
              )}
            </div>
          )}

          {assets.length === 0 ? (
            <p className="text-sm text-gray-500">{t('report.crypto.empty')}</p>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full border-collapse text-sm">
                <thead>
                  <tr className="border-b border-gray-300 text-left dark:border-gray-600">
                    {(
                      ['name', 'type', 'key_size', 'quantum', 'weak_key', 'location'] as const
                    ).map((c) => (
                      <th key={c} scope="col" className="py-1 pr-3">
                        {t(`report.crypto.col.${c}`)}
                      </th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {assets.map((a, i) => (
                    <tr
                      key={`${a.name}-${a.location}-${i}`}
                      className="border-b border-gray-100 dark:border-gray-800"
                    >
                      <td className="py-1 pr-3 font-mono">{a.name}</td>
                      <td className="py-1 pr-3 text-gray-500">
                        {a.primitive ?? a.asset_type}
                      </td>
                      <td className="py-1 pr-3 font-mono">{a.key_size ?? '—'}</td>
                      <td className="py-1 pr-3">
                        <QuantumBadge status={a.quantum} />
                      </td>
                      <td className="py-1 pr-3">
                        {a.weak_key ? t('report.crypto.weak_key_yes') : '—'}
                      </td>
                      <td className="py-1 pr-3 font-mono break-all">{a.location}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </>
      )}

      <p className="mt-3 text-xs text-gray-500">
        {t('report.crypto.scope_note')}
        <br />
        {t('report.crypto.draft_note')}
      </p>
    </Section>
  )
}

function Notes() {
  const { t } = useTranslation()
  return (
    <Section id="notes" title={t('report.notes.title')}>
      <p className="rounded border border-amber-300 bg-amber-50 p-3 text-sm dark:border-amber-700 dark:bg-amber-950">
        {t('report.notes.disclaimer_not_pentest')}
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
        <div className="no-print flex items-center gap-2">
          <button
            type="button"
            onClick={() => window.print()}
            className="rounded border border-gray-300 px-3 py-1 text-sm hover:bg-gray-100 dark:border-gray-600 dark:hover:bg-gray-800"
          >
            {t('report.print')}
          </button>
          <Toolbar />
        </div>
      </header>
      <Cover />
      <RiskSummary onPick={setFilter} active={filter} />
      <Findings filter={filter} />
      <Sbom />
      <Crypto />
      <Notes />
    </div>
  )
}
