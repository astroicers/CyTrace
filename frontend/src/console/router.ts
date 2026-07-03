// 自寫 hash routing（~60 行，不引 react-router）：所有 URL 同一份 console.html，
// axum 免 SPA fallback（rust-embed 服務靜態檔即可）。
import { useSyncExternalStore } from 'react'

export type Route =
  | { page: 'dashboard' }
  | { page: 'newScan' }
  | { page: 'job'; id: string }
  | { page: 'reports' }
  | { page: 'system' }

export function parseHash(hash: string): Route {
  const h = hash.replace(/^#\/?/, '')
  const [head, ...rest] = h.split('/')
  switch (head) {
    case 'scans':
      if (rest[0] === 'new') return { page: 'newScan' }
      break
    case 'jobs':
      if (rest[0]) return { page: 'job', id: rest[0] }
      break
    case 'reports':
      return { page: 'reports' }
    case 'system':
      return { page: 'system' }
  }
  return { page: 'dashboard' }
}

export function hrefFor(route: Route): string {
  switch (route.page) {
    case 'dashboard':
      return '#/'
    case 'newScan':
      return '#/scans/new'
    case 'job':
      return `#/jobs/${route.id}`
    case 'reports':
      return '#/reports'
    case 'system':
      return '#/system'
  }
}

export function navigate(route: Route) {
  window.location.hash = hrefFor(route)
}

function subscribe(cb: () => void) {
  window.addEventListener('hashchange', cb)
  return () => window.removeEventListener('hashchange', cb)
}

/** 目前路由（hashchange 驅動）。 */
export function useRoute(): Route {
  const hash = useSyncExternalStore(
    subscribe,
    () => window.location.hash,
    () => '',
  )
  return parseHash(hash)
}
