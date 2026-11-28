/**
 * Backend list replies are typed as arrays, but a gateway older or newer than
 * this renderer (or one mid-restart answering `{}`) can send anything. A view
 * that calls `.filter`/`.find`/`.length` on that value crashes its whole
 * boundary, so list fetchers normalise at the API seam: a non-array reads as
 * an empty list.
 */
export function listReply<T>(value: unknown): T[] {
  return Array.isArray(value) ? (value as T[]) : []
}
