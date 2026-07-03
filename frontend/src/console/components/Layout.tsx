import { useTranslation } from 'react-i18next'
import type { ReactNode } from 'react'
import { Toolbar } from '../../components/ui'
import { useSession } from '../state/session'
import { hrefFor, useRoute, type Route } from '../router'

interface NavItem {
  route: Route
  key: string
}

const NAV: NavItem[] = [
  { route: { page: 'dashboard' }, key: 'console.app.nav_dashboard' },
  { route: { page: 'newScan' }, key: 'console.app.nav_new_scan' },
  { route: { page: 'reports' }, key: 'console.app.nav_reports' },
  { route: { page: 'system' }, key: 'console.app.nav_system' },
]

/** 應用外殼：單行頂欄（品名 + nav + 語言/主題/登出）+ 內容區。 */
export function Layout({ children }: { children: ReactNode }) {
  const { t } = useTranslation()
  const { logout } = useSession()
  const current = useRoute()

  return (
    <div className="min-h-[100dvh] bg-white text-gray-900 dark:bg-gray-950 dark:text-gray-100">
      <header className="border-b border-gray-200 dark:border-gray-800">
        <div className="mx-auto flex h-16 max-w-5xl items-center gap-6 px-4">
          <a
            href={hrefFor({ page: 'dashboard' })}
            className="text-sm font-bold tracking-tight whitespace-nowrap"
          >
            {t('console.app.title')}
          </a>
          <nav className="flex flex-1 items-center gap-1 overflow-x-auto">
            {NAV.map((item) => {
              const active = item.route.page === current.page
              return (
                <a
                  key={item.key}
                  href={hrefFor(item.route)}
                  aria-current={active ? 'page' : undefined}
                  className={`rounded px-3 py-1.5 text-sm whitespace-nowrap ${
                    active
                      ? 'bg-gray-100 font-semibold text-gray-900 dark:bg-gray-800 dark:text-gray-100'
                      : 'text-gray-600 hover:bg-gray-50 dark:text-gray-400 dark:hover:bg-gray-900'
                  }`}
                >
                  {t(item.key)}
                </a>
              )
            })}
          </nav>
          <div className="flex items-center gap-2">
            <Toolbar />
            <button
              type="button"
              onClick={() => void logout()}
              className="rounded border border-gray-300 px-3 py-1 text-sm hover:bg-gray-100 dark:border-gray-600 dark:hover:bg-gray-800"
            >
              {t('console.app.logout')}
            </button>
          </div>
        </div>
      </header>
      <main className="mx-auto max-w-5xl px-4 py-8">{children}</main>
    </div>
  )
}
