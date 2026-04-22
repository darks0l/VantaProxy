import { useState, useEffect } from 'react'
import { useNavigate, useLocation } from 'react-router-dom'
import { getPolicies, createPolicy, deletePolicy } from '../api/client'
import { useAuth } from '../contexts/AuthContext'
import type { LLMPolicy, UserSummary } from '../types'
import { format } from 'date-fns'

const btnPrimary = 'px-4 py-2 bg-blue-600 text-white text-sm font-medium rounded-lg hover:bg-blue-700 disabled:opacity-50'

function LivePill({ users }: { users: UserSummary[] }) {
  const live = users.length > 0
  return (
    <div className="relative inline-block group">
      <span className={`inline-flex items-center gap-1.5 px-2 py-0.5 rounded-full text-xs font-medium ${
        live ? 'bg-green-100 text-green-700' : 'bg-gray-100 text-gray-400'
      }`}>
        <span className={`w-1.5 h-1.5 rounded-full ${live ? 'bg-green-500' : 'bg-gray-300'}`} />
        {live ? `Live · ${users.length}` : 'Not assigned'}
      </span>
      {live && (
        <div className="absolute left-0 top-full mt-1 z-20 hidden group-hover:block">
          <div className="bg-gray-900 text-white text-xs rounded-lg px-3 py-2 shadow-lg space-y-0.5 whitespace-nowrap">
            {users.map((u) => (
              <div key={u.id} className="font-mono">{u.id}</div>
            ))}
          </div>
        </div>
      )}
    </div>
  )
}

export function PoliciesPanel() {
  const navigate = useNavigate()
  const location = useLocation()
  const { allUsers } = useAuth()
  const [policies, setPolicies] = useState<LLMPolicy[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [creating, setCreating] = useState(false)
  const [deletingId, setDeletingId] = useState<string | null>(null)
  const [deleteError, setDeleteError] = useState<string | null>(null)

  const load = async () => {
    try {
      setLoading(true)
      setPolicies(await getPolicies())
      setError(null)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load policies')
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => { load() }, [])

  // If navigated here with a suggestion in state (legacy path), ignore it —
  // the suggest flow now creates a draft directly.
  useEffect(() => {
    if (location.state) {
      navigate(location.pathname, { replace: true, state: null })
    }
  }, [])

  const usersByPolicy = allUsers.reduce<Record<string, UserSummary[]>>((acc, u) => {
    if (u.llm_policy_id) acc[u.llm_policy_id] = [...(acc[u.llm_policy_id] ?? []), u]
    return acc
  }, {})

  const handleNewDraft = async () => {
    setCreating(true)
    try {
      const policy = await createPolicy({ name: 'New Policy', status: 'draft' })
      navigate(`/policies/${policy.id}`)
    } catch (err) {
      setDeleteError(err instanceof Error ? err.message : 'Failed to create draft')
    } finally {
      setCreating(false)
    }
  }

  const handleDelete = async (id: string) => {
    setDeletingId(id)
    setDeleteError(null)
    try {
      await deletePolicy(id)
      setPolicies((prev) => prev.filter((p) => p.id !== id))
    } catch (err) {
      setDeleteError(err instanceof Error ? err.message : 'Failed to delete policy')
    } finally {
      setDeletingId(null)
    }
  }

if (loading) {
    return (
      <div className="flex justify-center py-12">
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-600" />
      </div>
    )
  }

  if (error) return <p className="text-red-600 text-sm">{error}</p>

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h2 className="text-lg font-semibold text-gray-800">LLM Policies</h2>
        <button onClick={handleNewDraft} disabled={creating} className={btnPrimary}>{creating ? 'Creating…' : '+ New Policy'}</button>
      </div>

      {deleteError && (
        <div className="bg-red-50 border border-red-200 rounded-lg px-4 py-3 text-sm text-red-700">
          {deleteError}
          <button className="ml-3 text-red-500 hover:text-red-700" onClick={() => setDeleteError(null)}>&times;</button>
        </div>
      )}

      {policies.length === 0 ? (
        <p className="text-gray-500 text-sm bg-white rounded-lg border border-dashed border-gray-200 p-8 text-center">
          No policies found
        </p>
      ) : (
        <div className="bg-white rounded-xl border border-gray-200 overflow-visible">
          <table className="w-full text-sm overflow-visible">
            <thead className="bg-gray-50 border-b border-gray-200">
              <tr>
                <th className="text-left px-4 py-3 font-medium text-gray-600">Name</th>
                <th className="text-left px-4 py-3 font-medium text-gray-600">Prompt</th>
                <th className="text-left px-4 py-3 font-medium text-gray-600">Provider / Model</th>
                <th className="text-left px-4 py-3 font-medium text-gray-600">Forked From</th>
                <th className="text-left px-4 py-3 font-medium text-gray-600">Status</th>
                <th className="text-left px-4 py-3 font-medium text-gray-600">Created</th>
                <th className="px-4 py-3" />
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-100">
              {policies.map((p) => {
                const assigned = usersByPolicy[p.id] ?? []
                const isDeleting = deletingId === p.id
                return (
                  <tr key={p.id} className="hover:bg-gray-50 cursor-pointer" onClick={() => navigate(`/policies/${p.id}`)}>
                    <td className="px-4 py-3 font-medium text-blue-600 hover:underline">
                      {p.name}
                      {p.status === 'draft' && (
                        <span className="ml-2 px-1.5 py-0.5 bg-yellow-100 text-yellow-700 rounded text-xs font-medium">draft</span>
                      )}
                    </td>
                    <td className="px-4 py-3 max-w-xs text-gray-600">
                      <span className="font-mono text-xs">
                        {p.prompt ? `${p.prompt.slice(0, 80)}${p.prompt.length > 80 ? '…' : ''}` : <em className="text-gray-400">—</em>}
                      </span>
                    </td>
                    <td className="px-4 py-3 text-gray-600 text-xs">
                      {p.provider || <em className="text-gray-400">default</em>}
                      {' / '}
                      {p.model || <em className="text-gray-400">default</em>}
                    </td>
                    <td className="px-4 py-3 text-gray-500 text-xs font-mono">
                      {p.forked_from ? p.forked_from.slice(0, 12) + '…' : <em className="text-gray-400">—</em>}
                    </td>
                    <td className="px-4 py-3">
                      <LivePill users={assigned} />
                    </td>
                    <td className="px-4 py-3 text-gray-500 text-xs">
                      {format(new Date(p.created_at), 'MMM dd, yyyy')}
                    </td>
                    <td className="px-4 py-3 text-right" onClick={(e) => e.stopPropagation()}>
                      <button
                        disabled={isDeleting || assigned.length > 0}
                        title={assigned.length > 0 ? 'Unassign users before deleting' : 'Delete policy'}
                        onClick={() => {
                          if (window.confirm(`Delete policy "${p.name}"? This cannot be undone.`)) {
                            handleDelete(p.id)
                          }
                        }}
                        className="text-xs text-red-500 hover:text-red-700 disabled:opacity-30 disabled:cursor-not-allowed"
                      >
                        {isDeleting ? '…' : 'Delete'}
                      </button>
                    </td>
                  </tr>
                )
              })}
            </tbody>
          </table>
        </div>
      )}

    </div>
  )
}
