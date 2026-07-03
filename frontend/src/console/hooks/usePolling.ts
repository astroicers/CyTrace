// setTimeout 鏈輪詢（非裸 setInterval）：上一輪完成才排下一輪、背景分頁暫停、
// 連續失敗指數退避、卸載即清除。
import { useEffect, useRef, useState } from 'react'

interface PollResult<T> {
  data: T | null
  error: boolean
  reload: () => void
}

export function usePolling<T>(
  fetcher: () => Promise<T>,
  intervalMs: (data: T | null) => number,
  enabled = true,
): PollResult<T> {
  const [data, setData] = useState<T | null>(null)
  const [error, setError] = useState(false)
  const [tick, setTick] = useState(0)
  const fetcherRef = useRef(fetcher)
  const intervalRef = useRef(intervalMs)
  fetcherRef.current = fetcher
  intervalRef.current = intervalMs

  useEffect(() => {
    if (!enabled) return
    let cancelled = false
    let timer: ReturnType<typeof setTimeout> | undefined
    let backoff = 0

    const schedule = (ms: number) => {
      timer = setTimeout(run, ms)
    }
    const run = async () => {
      if (cancelled) return
      if (document.visibilityState === 'hidden') {
        schedule(1000) // 背景分頁：只輕量重試排程，不打 API
        return
      }
      try {
        const next = await fetcherRef.current()
        if (cancelled) return
        setData(next)
        setError(false)
        backoff = 0
        schedule(intervalRef.current(next))
      } catch {
        if (cancelled) return
        setError(true)
        backoff = Math.min(backoff === 0 ? 2000 : backoff * 2, 30000)
        schedule(backoff)
      }
    }
    void run()
    return () => {
      cancelled = true
      if (timer) clearTimeout(timer)
    }
  }, [enabled, tick])

  return { data, error, reload: () => setTick((n) => n + 1) }
}
