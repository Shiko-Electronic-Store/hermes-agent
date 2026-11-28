import type { HermesApiRequest } from '@/global'

/**
 * The renderer's REST door. Electron's preload (or the browser-host bridge)
 * installs `window.hermesDesktop`; a page served without either (no bootstrap,
 * a stale tab after the host went away) has none. Calling through a missing
 * bridge used to throw synchronously inside render effects and take the root
 * boundary down; reject instead, so every caller's ordinary error path (a
 * `.catch`, a query error state) handles it and the page degrades.
 */
export function desktopApi<T>(request: HermesApiRequest): Promise<T> {
  const bridge =
    typeof window === 'undefined' ? undefined : (window.hermesDesktop as Partial<Window['hermesDesktop']> | undefined)

  if (typeof bridge?.api !== 'function') {
    return Promise.reject(new Error('Hermes backend bridge is unavailable'))
  }

  return bridge.api<T>(request)
}
