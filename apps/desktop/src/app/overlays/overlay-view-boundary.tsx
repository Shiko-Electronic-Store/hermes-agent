import type { ReactNode } from 'react'

import { ErrorBoundary, type ErrorBoundaryFallbackProps } from '@/components/error-boundary'
import { Button } from '@/components/ui/button'
import { ErrorState } from '@/components/ui/error-state'
import { useI18n } from '@/i18n'

import { Panel } from './panel'

interface OverlayViewBoundaryProps {
  children: ReactNode
  /** View key for the console/log tag (`[error-boundary:view:<id>]`). */
  id: string
  onClose: () => void
}

/**
 * The blast wall for a full overlay view (cron, star map, …). Without it a
 * render error in the view bubbles to the ROOT boundary and replaces the whole
 * shell with "Something broke in the interface"; here it stays inside the
 * overlay, which keeps its close button so the user can step back out.
 */
export function OverlayViewBoundary({ children, id, onClose }: OverlayViewBoundaryProps) {
  return (
    <ErrorBoundary fallback={props => <OverlayViewFallback {...props} onClose={onClose} />} label={`view:${id}`}>
      {children}
    </ErrorBoundary>
  )
}

function OverlayViewFallback({ error, onClose, reset }: ErrorBoundaryFallbackProps & { onClose: () => void }) {
  const { t } = useI18n()

  return (
    <Panel onClose={onClose}>
      <div className="grid min-h-0 flex-1 place-items-center p-6" data-slot="overlay-view-error">
        <ErrorState className="w-full max-w-[28rem]" description={error.message} title={t.errors.boundaryTitle}>
          <Button className="justify-self-center" onClick={reset} size="sm" variant="outline">
            {t.common.retry}
          </Button>
        </ErrorState>
      </div>
    </Panel>
  )
}
