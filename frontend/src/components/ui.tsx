import { useTranslation } from 'react-i18next'
import { useTheme } from 'next-themes'
import * as DropdownMenu from '@radix-ui/react-dropdown-menu'
import type { Severity } from '../types'
import { SEVERITY_KEY } from '../types'
import { SUPPORTED_LANGS } from '../i18n'

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

/** 語言切換（Radix DropdownMenu，鍵盤可達）。 */
function LangSwitch() {
  const { i18n } = useTranslation()
  const current =
    SUPPORTED_LANGS.find((l) => l.code === i18n.language) ?? SUPPORTED_LANGS[0]
  return (
    <DropdownMenu.Root>
      <DropdownMenu.Trigger
        className="rounded border border-gray-300 px-3 py-1 text-sm hover:bg-gray-100 dark:border-gray-600 dark:hover:bg-gray-800"
        aria-label="language"
      >
        🌐 {current.label}
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

/** 亮/暗主題切換（next-themes）。 */
function ThemeToggle() {
  const { theme, setTheme } = useTheme()
  const next = theme === 'dark' ? 'light' : 'dark'
  return (
    <button
      type="button"
      onClick={() => setTheme(next)}
      className="rounded border border-gray-300 px-3 py-1 text-sm hover:bg-gray-100 dark:border-gray-600 dark:hover:bg-gray-800"
      aria-label="theme"
    >
      {theme === 'dark' ? '☀️' : '🌙'}
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
