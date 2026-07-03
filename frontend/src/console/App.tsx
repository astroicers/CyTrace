import { useTranslation } from 'react-i18next'
import { useSession } from './state/session'
import { useRoute } from './router'
import { Layout } from './components/Layout'
import { LoginPage } from './pages/LoginPage'
import { DashboardPage } from './pages/DashboardPage'
import { NewScanPage } from './pages/NewScanPage'
import { JobDetailPage } from './pages/JobDetailPage'
import { ReportsPage } from './pages/ReportsPage'
import { SystemPage } from './pages/SystemPage'

export function App() {
  const { t } = useTranslation()
  const { status } = useSession()
  const route = useRoute()

  // 開機探測 cookie 中 → loading（避免登入頁閃現）。
  if (status === 'unknown') {
    return (
      <div className="grid min-h-[100dvh] place-items-center bg-white text-gray-500 dark:bg-gray-950">
        {t('console.common.loading')}
      </div>
    )
  }
  if (status === 'anon') return <LoginPage />

  return (
    <Layout>
      {route.page === 'dashboard' && <DashboardPage />}
      {route.page === 'newScan' && <NewScanPage />}
      {route.page === 'job' && <JobDetailPage id={route.id} />}
      {route.page === 'reports' && <ReportsPage />}
      {route.page === 'system' && <SystemPage />}
    </Layout>
  )
}
