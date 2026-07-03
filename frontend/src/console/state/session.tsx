// Session 狀態：開機探測 cookie、登入/登出、401 集中攔截 → 清 session。
import {
  createContext,
  useContext,
  useEffect,
  useState,
  type ReactNode,
} from 'react'
import { api, setUnauthorizedHandler } from '../api/client'

type Status = 'unknown' | 'authed' | 'anon'

interface SessionState {
  status: Status
  user: string | null
  login: (password: string) => Promise<void>
  logout: () => Promise<void>
}

const SessionContext = createContext<SessionState | null>(null)

export function SessionProvider({ children }: { children: ReactNode }) {
  const [status, setStatus] = useState<Status>('unknown')
  const [user, setUser] = useState<string | null>(null)

  useEffect(() => {
    // 401 集中攔截：任一請求 401 → 清 session（頁面自動回登入）。
    setUnauthorizedHandler(() => {
      setStatus('anon')
      setUser(null)
    })
    // 開機探測既有 cookie。
    api
      .whoami()
      .then((s) => {
        setUser(s.user)
        setStatus('authed')
      })
      .catch(() => setStatus('anon'))
  }, [])

  const value: SessionState = {
    status,
    user,
    login: async (password) => {
      await api.login(password)
      const s = await api.whoami()
      setUser(s.user)
      setStatus('authed')
    },
    logout: async () => {
      try {
        await api.logout()
      } finally {
        setStatus('anon')
        setUser(null)
      }
    },
  }
  return (
    <SessionContext.Provider value={value}>{children}</SessionContext.Provider>
  )
}

export function useSession(): SessionState {
  const ctx = useContext(SessionContext)
  if (!ctx) throw new Error('useSession must be used within SessionProvider')
  return ctx
}
