/** The slice of use-stick-to-bottom's state the viewport follow needs. */
export interface StickToBottomLock {
  readonly escapedFromLock: boolean
  readonly isAtBottom: boolean
  readonly calculatedTargetScrollTop: number
  scrollTop: number
}

/**
 * Keep a bottom-locked transcript pinned when the VIEWPORT (not the content)
 * changes height.
 *
 * use-stick-to-bottom follows only its content's ResizeObserver. When the
 * scroller itself resizes, e.g. the status tray above the composer gains or
 * loses a "Background"/"Queued" row while a child agent streams:
 *   - shrinking left the newest lines under the tray (the lock never re-pinned);
 *   - growing made the browser clamp scrollTop downwards, which the library
 *     read as the reader scrolling UP: it dropped the lock, stopped following,
 *     raised the "N messages" pill, and re-locked a moment later. Together that
 *     is the transcript sliding up and down by itself while nobody touches it.
 * Writing the target through the library's own setter re-pins on a shrink and,
 * on a grow, tags the clamp's scroll position as programmatic, so it is not
 * mistaken for an escape.
 */
export function observeViewportResizeFollow(viewport: HTMLElement, lock: StickToBottomLock): () => void {
  let height = viewport.clientHeight
  const locked = () => lock.isAtBottom && !lock.escapedFromLock

  const repin = () => {
    lock.scrollTop = lock.calculatedTargetScrollTop
  }

  // The clamp's scroll event can be dispatched before this frame's resize
  // delivery. Seen first here (capture, ahead of the library's own listener),
  // a scroll that comes with a taller viewport is the clamp, not the reader.
  const onScroll = () => {
    const next = viewport.clientHeight

    if (next > height && locked()) {
      repin()
    }

    height = next
  }

  const observer = new ResizeObserver(() => {
    const next = viewport.clientHeight

    if (next === height) {
      return
    }

    height = next

    if (locked()) {
      repin()
    }
  })

  viewport.addEventListener('scroll', onScroll, { capture: true, passive: true })
  observer.observe(viewport)

  return () => {
    viewport.removeEventListener('scroll', onScroll, { capture: true })
    observer.disconnect()
  }
}
