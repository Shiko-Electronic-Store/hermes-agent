import { cleanup, render, screen } from '@testing-library/react'
import { MemoryRouter } from 'react-router'
import { afterEach, beforeAll, describe, expect, it, vi } from 'vitest'

import { StatusbarControls } from '@/app/shell/statusbar-controls'

class TestResizeObserver {
  observe() {}
  unobserve() {}
  disconnect() {}
}

beforeAll(() => {
  vi.stubGlobal('ResizeObserver', TestResizeObserver)
})

afterEach(cleanup)

// Icon-only statusbar items (command center, terminal) carried their name only
// in a hover tooltip, so screen readers announced an unnamed button.
describe('statusbar item accessible names', () => {
  it('names icon-only action, menu and link items from their title', () => {
    render(
      <MemoryRouter>
        <StatusbarControls
          items={[
            { id: 'cmd', icon: <svg />, onSelect: () => undefined, title: 'Open command center', variant: 'action' },
            {
              id: 'menu',
              icon: <svg />,
              menuItems: [{ id: 'a', label: 'A' }],
              title: 'Approval mode',
              variant: 'menu'
            },
            { href: 'https://example.invalid', icon: <svg />, id: 'docs', title: 'Docs', variant: 'link' }
          ]}
        />
      </MemoryRouter>
    )

    expect(screen.getByRole('button', { name: 'Open command center' })).toBeTruthy()
    expect(screen.getByRole('button', { name: 'Approval mode' })).toBeTruthy()
    expect(screen.getByRole('link', { name: 'Docs' })).toBeTruthy()
  })

  it('keeps a visible label as the name instead of overriding it with the title', () => {
    render(
      <MemoryRouter>
        <StatusbarControls
          items={[{ id: 'v', label: 'v1.2.3', onSelect: () => undefined, title: 'Version', variant: 'action' }]}
        />
      </MemoryRouter>
    )

    const button = screen.getByRole('button', { name: 'v1.2.3' })

    expect(button.getAttribute('aria-label')).toBeNull()
  })
})
