import { describe, expect, it } from 'vitest'

import { listReply } from './list-reply'

describe('listReply', () => {
  it('passes arrays through and reads anything else as an empty list', () => {
    const rows = [{ id: 1 }]

    expect(listReply(rows)).toBe(rows)

    for (const value of [undefined, null, {}, { items: [] }, 'x', 0]) {
      expect(listReply(value)).toEqual([])
    }
  })
})
