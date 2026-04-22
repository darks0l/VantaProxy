import { create } from 'zustand'
import type { UserSummary } from '../types'

interface UserStore {
  users: UserSummary[]
  setUsers: (users: UserSummary[]) => void
  addUser: (user: UserSummary) => void
  updateUser: (id: string, updates: Partial<UserSummary>) => void
  removeUser: (id: string) => void
}

export const useUserStore = create<UserStore>((set) => ({
  users: [],

  setUsers: (users) => set({ users }),

  addUser: (user) =>
    set((state) => {
      if (state.users.some((u) => u.id === user.id)) return state
      return { users: [user, ...state.users] }
    }),

  updateUser: (id, updates) =>
    set((state) => ({
      users: state.users.map((u) => (u.id === id ? { ...u, ...updates } : u)),
    })),

  removeUser: (id) =>
    set((state) => ({ users: state.users.filter((u) => u.id !== id) })),
}))
