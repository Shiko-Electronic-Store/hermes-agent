import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import { observeViewportResizeFollow, type StickToBottomLock } from './viewport-resize-follow'

// While a child agent streamed, the status tray above the composer gained and
// lost rows, resizing the transcript viewport. use-stick-to-bottom follows only
// its CONTENT, so a shrink left the newest lines under the tray, and a grow made
// the browser clamp scrollTop down — read by the library as the reader
// scrolling up: the lock dropped, the pill appeared, and the view slid until it
// re-locked. Measured in the Playwright harness: 1-9 lock escapes and up to
// 9,814px off the bottom per 24s stream, 0 after the fix.
describe('observeViewportResizeFollow', () => {
  let resize: () => void
  let height: number
  let viewport: HTMLElement
  const disconnect = vi.fn()

  beforeEach(() => {
    height = 600
    viewport = window.document.createElement('div')
    Object.defineProperty(viewport, 'clientHeight', { configurable: true, get: () => height })
    vi.stubGlobal(
      'ResizeObserver',
      class {
        constructor(callback: () => void) {
          resize = callback
        }
        observe() {}
        disconnect = disconnect
      }
    )
  })

  afterEach(() => {
    vi.unstubAllGlobals()
    disconnect.mockClear()
  })

  const lockAt = (overrides: Partial<StickToBottomLock> = {}) => {
    const writes: number[] = []

    const lock = {
      calculatedTargetScrollTop: 1400,
      escapedFromLock: false,
      isAtBottom: true,
      get scrollTop() {
        return writes.at(-1) ?? 1000
      },
      set scrollTop(value: number) {
        writes.push(value)
      },
      ...overrides
    }

    return { lock, writes }
  }

  it('re-pins a following transcript when the viewport shrinks', () => {
    const { lock, writes } = lockAt()
    observeViewportResizeFollow(viewport, lock)

    height = 540
    resize()

    expect(writes).toEqual([1400])
  })

  it('claims the clamp scroll of a growing viewport before the library can read it as an escape', () => {
    const { lock, writes } = lockAt()
    const library = vi.fn(() => writes.length)

    observeViewportResizeFollow(viewport, lock)
    // The library's own (bubble/target) listener, registered after ours.
    viewport.addEventListener('scroll', library)

    height = 660
    viewport.dispatchEvent(new Event('scroll'))

    expect(writes).toEqual([1400])
    // Our capture listener ran first, so the library saw the programmatic write.
    expect(library).toHaveReturnedWith(1)
  })

  it('leaves a reader who scrolled away alone, and ignores ordinary scrolls', () => {
    const escaped = lockAt({ escapedFromLock: true, isAtBottom: false })
    observeViewportResizeFollow(viewport, escaped.lock)

    height = 540
    resize()
    height = 660
    viewport.dispatchEvent(new Event('scroll'))
    expect(escaped.writes).toEqual([])

    const following = lockAt()
    height = 600
    observeViewportResizeFollow(viewport, following.lock)
    viewport.dispatchEvent(new Event('scroll'))
    resize()
    expect(following.writes).toEqual([])
  })

  it('disconnects on dispose', () => {
    const { lock, writes } = lockAt()
    const dispose = observeViewportResizeFollow(viewport, lock)

    dispose()
    height = 700
    viewport.dispatchEvent(new Event('scroll'))

    expect(disconnect).toHaveBeenCalled()
    expect(writes).toEqual([])
  })
})
