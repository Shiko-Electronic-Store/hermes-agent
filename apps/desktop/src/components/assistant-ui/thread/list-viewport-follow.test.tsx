import { AssistantRuntimeProvider, type ThreadMessage, useExternalStoreRuntime } from '@assistant-ui/react'
import { cleanup, render } from '@testing-library/react'
import { afterEach, expect, it, vi } from 'vitest'

import { stubThreadEnvironment, stubThreadViewportSize } from '../test-utils'

import { TranscriptWindowProvider } from './transcript-window'

const follow = vi.hoisted(() => vi.fn(() => () => undefined))

vi.mock('./viewport-resize-follow', () => ({ observeViewportResizeFollow: follow }))

const { Thread } = await import('.')

stubThreadEnvironment()
stubThreadViewportSize()

afterEach(cleanup)

const createdAt = new Date('2026-11-13T00:00:00.000Z')

function Harness() {
  const runtime = useExternalStoreRuntime<ThreadMessage>({
    isRunning: true,
    messages: [
      {
        id: 'u',
        role: 'user',
        content: [{ type: 'text', text: 'task' }],
        attachments: [],
        createdAt,
        metadata: { custom: {} }
      },
      {
        id: 'a',
        role: 'assistant',
        content: [{ type: 'text', text: 'working' }],
        createdAt,
        status: { type: 'running' },
        metadata: { custom: {} }
      }
    ] as unknown as ThreadMessage[],
    onNew: async () => {}
  })

  return (
    <AssistantRuntimeProvider runtime={runtime}>
      <TranscriptWindowProvider value={{ olderAvailable: false, expandWindow: () => {} }}>
        <Thread sessionKey="child" />
      </TranscriptWindowProvider>
    </AssistantRuntimeProvider>
  )
}

// The transcript must keep following when its VIEWPORT resizes (status tray,
// composer), not only when its content grows — see viewport-resize-follow.ts.
it('wires the viewport-resize follow to the transcript scroller and its stick-to-bottom lock', () => {
  const { container } = render(<Harness />)
  const viewport = container.querySelector('[data-slot="aui_thread-viewport"]')

  expect(follow).toHaveBeenCalled()
  const [element, lock] = follow.mock.calls.at(-1) as unknown as [HTMLElement, Record<string, unknown>]

  expect(element).toBe(viewport)
  expect(lock).toHaveProperty('isAtBottom')
  expect(lock).toHaveProperty('escapedFromLock')
  expect('calculatedTargetScrollTop' in lock).toBe(true)
})
