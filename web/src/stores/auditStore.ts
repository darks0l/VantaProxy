import { create } from 'zustand'
import type { AuditEntry } from '../types'

interface AuditFilter {
  userId?: string
  method?: string
  decision?: string
  approvedBy?: string
  policyId?: string
  startTime?: string
  endTime?: string
}

interface AuditStore {
  entries: AuditEntry[]
  filters: AuditFilter
  total: number
  offset: number
  limit: number
  setEntries: (entries: AuditEntry[], total: number, offset: number, limit: number) => void
  addEntry: (entry: AuditEntry) => void
  setFilters: (filters: AuditFilter) => void
  clearFilters: () => void
}

export const useAuditStore = create<AuditStore>((set) => ({
  entries: [],
  filters: {},
  total: 0,
  offset: 0,
  limit: 100,

  setEntries: (entries, total, offset, limit) =>
    set({
      entries: [...entries].sort((a, b) => {
        return new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime()
      }),
      total,
      offset,
      limit,
    }),

  addEntry: (entry) =>
    set((state) => {
      console.log('Store: addEntry called', entry.request_id, entry.timestamp)
      // Check if entry already exists
      if (state.entries.some(e => e.request_id === entry.request_id && e.timestamp === entry.timestamp)) {
        console.log('Store: entry already exists, skipping', entry.request_id)
        return state // Don't add duplicates
      }
      // Add entry and sort by timestamp descending (newest first)
      const allEntries = [entry, ...state.entries]
      const sortedEntries = [...allEntries].sort((a, b) => {
        const timeA = new Date(a.timestamp).getTime()
        const timeB = new Date(b.timestamp).getTime()
        return timeB - timeA  // Descending order (newest first)
      })
      return {
        entries: sortedEntries,
        total: state.total + 1,
      }
    }),

  setFilters: (filters) =>
    set({ filters, offset: 0 }), // Reset offset when filters change

  clearFilters: () =>
    set({ filters: {}, offset: 0 }),
}))
