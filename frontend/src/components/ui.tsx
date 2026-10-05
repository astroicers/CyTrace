import { useTranslation } from 'react-i18next'
import { useTheme } from 'next-themes'
import * as DropdownMenu from '@radix-ui/react-dropdown-menu'
import type { QuantumStatus, Severity } from '../types'
import { QUANTUM_KEY, SEVERITY_KEY } from '../types'
import { SUPPORTED_LANGS } from '../i18n'
import { effectiveLang } from '../langs'

const SEV_BG: Record<Severity, string> = {
  Critical: 'bg-sev-critical',
  High: 'bg-sev-high',
  Medium: 'bg-sev-medium',
  Low: 'bg-sev-low',
  Negligible: 'bg-sev-negligible',
  Unknown: 'bg-sev-unknown',
}

/** 嚴重度徽章：色彩 + 文字標籤（色非唯一資訊載體，a11y）。 */
export function SeverityBadge({ severity }: { severity: Severity }) {
  const { t } = useTranslation()
  return (
    <span
      className={`inline-flex items-center gap-1 rounded px-2 py-0.5 text-xs font-semibold text-white ${SEV_BG[severity]}`}
    >
      <span aria-hidden="true">●</span>
      {t(SEVERITY_KEY[severity])}
    </span>
  )
}

const QUANTUM_BG: Record<QuantumStatus, string> = {
  Safe: 'bg-q-safe',
  Vulnerable: 'bg-q-vulnerable',
  NotApplicable: 'bg-q-na',
  Unknown: 'bg-q-unknown',
}

/** 量子狀態徽章（ADR-013）。同 SeverityBadge：色彩非唯一資訊載體。 */
export function QuantumBadge({ status }: { status: QuantumStatus }) {
  const { t } = useTranslation()
  return (
    <span
      className={`inline-flex items-center gap-1 rounded px-2 py-0.5 text-xs font-semibold text-white ${QUANTUM_BG[status]}`}
    >
      <span aria-hidden="true">◆</span>
      {t(QUANTUM_KEY[status])}
    </span>
  )
}

/**
 * 語言切換（Radix DropdownMenu，鍵盤可達）。
 *
 * 不用 emoji 圖示：交付場域多為無彩色 emoji 字型的離線機器，🌐 會變成豆腐字（T917）。
 */
function LangSwitch() {
  const { t, i18n } = useTranslation()
  const current =
    SUPPORTED_LANGS.find((l) => l.code === effectiveLang(i18n)) ?? SUPPORTED_LANGS[0]
  return (
    <DropdownMenu.Root>
      <DropdownMenu.Trigger
        className="rounded border border-gray-300 px-3 py-1 text-sm hover:bg-gray-100 dark:border-gray-600 dark:hover:bg-gray-800"
        // 無障礙名稱須包含可見文字（WCAG 2.5.3 Label in Name）
        aria-label={t('ui.language', { lang: current.label })}
      >
        {current.label}
      </DropdownMenu.Trigger>
      <DropdownMenu.Portal>
        <DropdownMenu.Content
          className="z-50 min-w-32 rounded border border-gray-200 bg-white p-1 shadow-md dark:border-gray-700 dark:bg-gray-900"
          sideOffset={4}
        >
          {SUPPORTED_LANGS.map((l) => (
            <DropdownMenu.Item
              key={l.code}
              className="cursor-pointer rounded px-2 py-1 text-sm outline-none focus:bg-gray-100 dark:focus:bg-gray-800"
              onSelect={() => {
                void i18n.changeLanguage(l.code)
                document.documentElement.lang = l.code
              }}
            >
              {l.label}
            </DropdownMenu.Item>
          ))}
        </DropdownMenu.Content>
      </DropdownMenu.Portal>
    </DropdownMenu.Root>
  )
}

/**
 * 亮/暗主題切換（next-themes）。按鈕文字是**切換後**的主題。
 *
 * 判斷用 `resolvedTheme`：`theme` 可能是 'system'，此時拿它比 'dark' 會把已是深色的畫面
 * 再設成深色、按了沒反應。
 */
function ThemeToggle() {
  const { t } = useTranslation()
  const { resolvedTheme, setTheme } = useTheme()
  const next = resolvedTheme === 'dark' ? 'light' : 'dark'
  const label = t(next === 'dark' ? 'ui.theme_dark' : 'ui.theme_light')
  // 無障礙名稱須包含可見文字（WCAG 2.5.3 Label in Name）：語音操作說「深色」要點得到
  return (
    <button
      type="button"
      onClick={() => setTheme(next)}
      className="rounded border border-gray-300 px-3 py-1 text-sm hover:bg-gray-100 dark:border-gray-600 dark:hover:bg-gray-800"
      aria-label={t('ui.theme_switch_to', { theme: label })}
    >
      {label}
    </button>
  )
}

export function Toolbar() {
  return (
    <div className="flex items-center gap-2">
      <LangSwitch />
      <ThemeToggle />
    </div>
  )
}
