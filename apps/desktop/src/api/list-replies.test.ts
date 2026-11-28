import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import { getAutomationBlueprints, getCronJobs } from './cron'
import { desktopApi } from './desktop-bridge'
import { getProfiles } from './profiles'
import { getSkills } from './skills'
import { getTerminalBackends, getToolsets } from './toolsets'

// A gateway older/newer than this renderer, or one mid-restart, can answer a
// list endpoint with `{}`. The views then called `.filter`/`.find`/`.length`
// on it: the cron view took the ROOT boundary down ("g.filter is not a
// function"), capabilities failed its workspace boundary, and the profile
// list / terminal-backend probe threw at boot. List fetchers now normalise.
describe('list replies are normalised at the API seam', () => {
  const api = vi.fn()

  beforeEach(() => {
    api.mockReset()
    vi.stubGlobal('window', { hermesDesktop: { api } })
  })

  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it.each([{}, null, 'oops', { items: [] }])('reads %j as empty lists', async reply => {
    api.mockResolvedValue(reply)

    await expect(getCronJobs()).resolves.toEqual([])
    await expect(getSkills()).resolves.toEqual([])
    await expect(getToolsets()).resolves.toEqual([])
    expect((await getAutomationBlueprints('default')).blueprints).toEqual([])
    expect((await getProfiles()).profiles).toEqual([])
    expect((await getTerminalBackends()).backends).toEqual([])
  })

  it('passes well-formed lists through unchanged', async () => {
    const jobs = [{ id: 'j1' }]

    api.mockResolvedValueOnce(jobs)
    await expect(getCronJobs()).resolves.toBe(jobs)

    api.mockResolvedValueOnce({ profiles: [{ name: 'default' }], active: 'default' })
    await expect(getProfiles()).resolves.toEqual({ profiles: [{ name: 'default' }], active: 'default' })
  })
})

// Without the Electron preload or the browser-host bootstrap there is no
// bridge; the call used to throw synchronously inside effects (`reading
// 'api'`) and trip the root boundary on /settings. It now rejects, so each
// caller's ordinary error path handles it.
describe('desktopApi without a bridge', () => {
  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it('rejects instead of throwing when window.hermesDesktop is missing', async () => {
    vi.stubGlobal('window', {})

    let promise: Promise<unknown> | undefined

    expect(() => {
      promise = desktopApi({ path: '/api/status' })
    }).not.toThrow()
    await expect(promise).rejects.toThrow(/bridge is unavailable/)
    // The wrappers built on it degrade the same way.
    await expect(getSkills()).rejects.toThrow(/bridge is unavailable/)
    await expect(getCronJobs()).rejects.toThrow(/bridge is unavailable/)
  })
})
