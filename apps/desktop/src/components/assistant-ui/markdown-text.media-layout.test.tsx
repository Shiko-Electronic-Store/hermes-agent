import { cleanup, render, screen, waitFor } from '@testing-library/react'
import { afterEach, describe, expect, it } from 'vitest'

import { MarkdownImage, MessageTextContent } from './markdown-text'

// Layout contracts jsdom cannot measure, pinned at the class level. The real
// geometry is covered by the Playwright tool/media audit.
afterEach(cleanup)

describe('framed markdown image alignment', () => {
  it('top-aligns the image in its reserved frame instead of letting the <button> centre it', () => {
    // A <button> centres its content vertically. In a cold 4:3 frame a 16:9
    // frame still drifted 27-60px down, away from its own download button
    // (tool cards and MEDIA: stills alike).
    render(<MarkdownImage alt="still" src="https://example.invalid/frame.png" />)

    const button = screen.getByRole('img', { name: 'still' }).closest('button')!

    expect(button.className).toMatch(/\bflex\b/)
    expect(button.className).toMatch(/\bflex-col\b/)
    expect(button.className).toMatch(/\bitems-start\b/)
    expect(button.className).toMatch(/\bjustify-start\b/)
    expect(button.className).toMatch(/\bh-full\b/)
    expect(button.closest('[data-slot="aui_markdown-image"]')?.className).toMatch(/\bnot-prose\b/)
  })
})

describe('MEDIA: video player box', () => {
  it('reserves a 16:9 box outside prose spacing before the clip has metadata', async () => {
    // preload="none": without a reserved box the player laid out at the
    // 300x150 default and grew to its real height on first play (213px at
    // 1440px), sliding everything below; `.prose video` added a 2em margin.
    const { container } = render(
      <MessageTextContent text={'Cut:\n\nMEDIA:https://example.invalid/storyboard/clip.mp4'} />
    )

    const player = await waitFor(() => {
      const found = container.querySelector('video')

      expect(found).not.toBeNull()

      return found!
    })

    expect(player.className).toMatch(/\baspect-video\b/)
    expect(player.className).toMatch(/\bobject-contain\b/)
    expect(player.closest('span.not-prose')).not.toBeNull()
  })
})
