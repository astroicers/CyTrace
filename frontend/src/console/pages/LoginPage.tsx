import { useState, type FormEvent } from 'react'
import { useTranslation } from 'react-i18next'
import { Toolbar } from '../../components/ui'
import { useSession } from '../state/session'
import { ApiError } from '../api/types'

/** 登入頁：整頁置中單卡（軍規場域，無插圖無動畫）。 */
export function LoginPage() {
  const { t } = useTranslation()
  const { login } = useSession()
  const [password, setPassword] = useState('')
  const [busy, setBusy] = useState(false)
  const [errorKey, setErrorKey] = useState<string | null>(null)

  const onSubmit = async (e: FormEvent) => {
    e.preventDefault()
    setBusy(true)
    setErrorKey(null)
    try {
      await login(password)
    } catch (err) {
      if (err instanceof ApiError && err.status === 429) {
        setErrorKey('console.login.error_rate_limited')
      } else if (err instanceof ApiError && err.code === 'network') {
        setErrorKey('console.login.error_network')
      } else {
        setErrorKey('console.login.error_invalid')
      }
      setBusy(false)
    }
  }

  return (
    <div className="flex min-h-[100dvh] flex-col bg-white text-gray-900 dark:bg-gray-950 dark:text-gray-100">
      <div className="flex justify-end p-4">
        <Toolbar />
      </div>
      <div className="flex flex-1 items-center justify-center px-4 pb-16">
        <div className="w-full max-w-sm">
          <h1 className="text-xl font-bold tracking-tight">
            {t('console.login.title')}
          </h1>
          <p className="mt-1 text-sm text-gray-500 dark:text-gray-400">
            {t('console.login.subtitle')}
          </p>
          <form onSubmit={onSubmit} className="mt-6 grid gap-4">
            <div className="grid gap-2">
              <label
                htmlFor="password"
                className="text-sm font-medium text-gray-700 dark:text-gray-300"
              >
                {t('console.login.password')}
              </label>
              <input
                id="password"
                type="password"
                autoComplete="current-password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                autoFocus
                className="rounded border border-gray-300 bg-white px-3 py-2 text-sm text-gray-900 outline-none focus:border-gray-500 focus:ring-2 focus:ring-gray-300 dark:border-gray-600 dark:bg-gray-900 dark:text-gray-100 dark:focus:ring-gray-700"
              />
            </div>
            {errorKey && (
              <p
                role="alert"
                className="text-sm font-medium text-sev-critical"
              >
                {t(errorKey)}
              </p>
            )}
            <button
              type="submit"
              disabled={busy || password.length === 0}
              className="rounded bg-gray-900 px-4 py-2 text-sm font-semibold text-white transition active:translate-y-px hover:bg-gray-800 disabled:opacity-50 dark:bg-gray-100 dark:text-gray-900 dark:hover:bg-white"
            >
              {busy ? t('console.login.signing_in') : t('console.login.submit')}
            </button>
          </form>
        </div>
      </div>
    </div>
  )
}
