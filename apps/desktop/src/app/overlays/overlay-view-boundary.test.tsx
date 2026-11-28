import { cleanup, render, screen } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import { ErrorBoundary } from '@/components/error-boundary'

import { OverlayViewBoundary } from './overlay-view-boundary'

function Bomb(): never {
  throw new Error('nodes is undefined')
}

// Before: a render error in the Star Map / Cron overlay reached the ROOT
// boundary and replaced the whole app with "Something broke in the interface".
describe('OverlayViewBoundary', () => {
  beforeEach(() => {
    vi.spyOn(console, 'error').mockImplementation(() => undefined)
  })

  afterEach(() => {
    cleanup()
    vi.restoreAllMocks()
  })

  it('contains a crashing view inside its overlay and keeps a way out', () => {
    const onClose = vi.fn()
    const outerCaught = vi.fn()

    render(
      <ErrorBoundary fallback={() => <div>root fallback</div>} label="root" onError={outerCaught}>
        <div>shell stays</div>
        <OverlayViewBoundary id="starmap" onClose={onClose}>
          <Bomb />
        </OverlayViewBoundary>
      </ErrorBoundary>
    )

    expect(screen.getByText('shell stays')).toBeTruthy()
    expect(screen.queryByText('root fallback')).toBeNull()
    expect(outerCaught).not.toHaveBeenCalled()
    expect(screen.getByText('nodes is undefined')).toBeTruthy()
    expect(globalThis.document.querySelector('[data-slot="overlay-view-error"]')).not.toBeNull()
  })
})
