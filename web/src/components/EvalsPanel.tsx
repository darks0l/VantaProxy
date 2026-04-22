import { useState, useEffect } from 'react'
import { useNavigate, useSearchParams, Link } from 'react-router-dom'
import { getPolicies, createEvalRun, listEvalRuns, getUsers } from '../api/client'
import type { EvalFilter } from '../api/client'
import { parseDatetimeLocal } from '../lib/utils'
import type { LLMPolicy, EvalRun, UserSummary } from '../types'
import { format } from 'date-fns'

const inputClass = 'w-full border border-gray-300 rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500'
const btnPrimary = 'px-4 py-2 bg-blue-600 text-white text-sm font-medium rounded-lg hover:bg-blue-700 disabled:opacity-50'
const btnSecondary = 'px-4 py-2 border border-gray-300 text-gray-700 text-sm font-medium rounded-lg hover:bg-gray-50'

function StatusPill({ status }: { status: EvalRun['status'] }) {
  if (status === 'pending') return <span className="px-2 py-0.5 rounded text-xs font-semibold bg-gray-100 text-gray-700">pending</span>
  if (status === 'running') return (
    <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-xs font-semibold bg-blue-100 text-blue-700">
      <svg className="animate-spin h-3 w-3" viewBox="0 0 24 24" fill="none"><circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"/><path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8v8z"/></svg>
      running
    </span>
  )
  if (status === 'completed') return <span className="px-2 py-0.5 rounded text-xs font-semibold bg-green-100 text-green-700">completed</span>
  if (status === 'canceled') return <span className="px-2 py-0.5 rounded text-xs font-semibold bg-orange-100 text-orange-700">canceled</span>
  return <span className="px-2 py-0.5 rounded text-xs font-semibold bg-red-100 text-red-700">failed</span>
}

function duration(run: EvalRun): string {
  if (!run.completed_at) return '—'
  const ms = new Date(run.completed_at).getTime() - new Date(run.created_at).getTime()
  if (ms < 1000) return `${ms}ms`
  return `${(ms / 1000).toFixed(1)}s`
}

// ---- RunEvalModal ----

const toDatetimeLocal = (d: Date) => {
  const pad = (n: number) => String(n).padStart(2, '0')
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}T${pad(d.getHours())}:${pad(d.getMinutes())}`
}

export interface SavedEvalFilter {
  limit: number
  decision: string
  userId: string
  startTime: string
  endTime: string
}

export function RunEvalModal({
  policyId: initialPolicyId,
  policyName,
  initialFilter,
  onClose,
  onCreated,
}: {
  policyId?: string
  policyName?: string
  initialFilter?: SavedEvalFilter
  onClose: () => void
  onCreated: (runId: string) => void
}) {
  const [policies, setPolicies] = useState<LLMPolicy[]>([])
  const [users, setUsers] = useState<UserSummary[]>([])
  const [policyId, setPolicyId] = useState(initialPolicyId ?? '')
  const [decision, setDecision] = useState(initialFilter?.decision ?? '')
  const [userId, setUserId] = useState(initialFilter?.userId ?? '')
  const [startTime, setStartTime] = useState(initialFilter?.startTime ?? '')
  const [endTime, setEndTime] = useState(initialFilter?.endTime ?? '')
  const [limit, setLimit] = useState(initialFilter?.limit ?? 1000)
  const [unlimited, setUnlimited] = useState(initialFilter ? initialFilter.limit === 0 : false)
  const [submitting, setSubmitting] = useState(false)
  const [err, setErr] = useState<string | null>(null)

  const locked = !!initialPolicyId

  useEffect(() => {
    if (!locked) getPolicies().then(setPolicies).catch(() => {})
    getUsers().then(setUsers).catch(() => {})
  }, [locked])

  const applyRange = (days: number) => {
    const now = new Date()
    const end = new Date(now.getTime() + 60_000)
    const start = new Date(now)
    if (days === 0) start.setHours(0, 0, 0, 0)
    else start.setDate(start.getDate() - days)
    setStartTime(toDatetimeLocal(start))
    setEndTime(toDatetimeLocal(end))
  }

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!policyId) { setErr('Select a policy'); return }
    setSubmitting(true)
    setErr(null)
    try {
      const filter: EvalFilter = unlimited ? {} : { limit }
      if (decision) filter.decision = decision
      if (userId) filter.user_id = userId
      if (startTime) filter.start_time = parseDatetimeLocal(startTime).toISOString()
      if (endTime) filter.end_time = parseDatetimeLocal(endTime).toISOString()
      const run = await createEvalRun(policyId, filter)
      try {
        const saved: SavedEvalFilter = { limit: unlimited ? 0 : limit, decision, userId, startTime, endTime }
        localStorage.setItem(`eval-filter-${run.id}`, JSON.stringify(saved))
      } catch {}
      onCreated(run.id)
    } catch (error) {
      setErr(error instanceof Error ? error.message : 'Failed to create eval run')
      setSubmitting(false)
    }
  }

  const quickRanges = [
    { label: 'Today', days: 0 },
    { label: 'Last 3 days', days: 3 },
    { label: 'Last 7 days', days: 7 },
    { label: 'Last 30 days', days: 30 },
  ]

  return (
    <div className="fixed inset-0 bg-black/40 flex items-center justify-center z-50">
      <div className="bg-white rounded-xl shadow-xl w-full max-w-md p-6 space-y-4">
        <div className="flex items-center justify-between">
          <h3 className="text-lg font-semibold text-gray-900">New Eval Run</h3>
          <button onClick={onClose} className="text-gray-400 hover:text-gray-600 text-xl leading-none">&times;</button>
        </div>
        <form onSubmit={handleSubmit} className="space-y-3">
          <div className="space-y-1">
            <label className="block text-sm font-medium text-gray-700">Policy</label>
            {locked ? (
              <div className="px-3 py-2 bg-gray-50 border border-gray-200 rounded-lg text-sm text-gray-700">{policyName ?? policyId}</div>
            ) : (
              <select className={inputClass} value={policyId} onChange={(e) => setPolicyId(e.target.value)} required>
                <option value="">Select a policy…</option>
                {policies.map((p) => (
                  <option key={p.id} value={p.id}>{p.name}</option>
                ))}
              </select>
            )}
          </div>
          <div className="space-y-1">
            <label className="block text-sm font-medium text-gray-700">Decision filter</label>
            <select className={inputClass} value={decision} onChange={(e) => setDecision(e.target.value)}>
              <option value="">All</option>
              <option value="approved">Approved only</option>
              <option value="denied">Denied only</option>
            </select>
          </div>
          <div className="space-y-1">
            <label className="block text-sm font-medium text-gray-700">User (optional)</label>
            <select className={inputClass} value={userId} onChange={(e) => setUserId(e.target.value)}>
              <option value="">All users</option>
              {users.map((u) => (
                <option key={u.id} value={u.id}>{u.id}</option>
              ))}
            </select>
          </div>
          <div className="space-y-1">
            <label className="block text-sm font-medium text-gray-700">Date range</label>
            <div className="flex flex-wrap gap-1 mb-2">
              {quickRanges.map(({ label, days }) => (
                <button key={label} type="button" onClick={() => applyRange(days)}
                  className="px-2 py-1 text-xs border border-gray-300 rounded hover:bg-gray-100 text-gray-600">
                  {label}
                </button>
              ))}
            </div>
            <div className="grid grid-cols-2 gap-2">
              <input type="datetime-local" className={inputClass} value={startTime} onChange={(e) => setStartTime(e.target.value)} />
              <input type="datetime-local" className={inputClass} value={endTime} onChange={(e) => setEndTime(e.target.value)} />
            </div>
          </div>
          <div className="space-y-1">
            <div className="flex items-center justify-between">
              <label className="block text-sm font-medium text-gray-700">Limit</label>
              <label className="flex items-center gap-1.5 text-xs text-gray-500 cursor-pointer">
                <input type="checkbox" checked={unlimited} onChange={(e) => setUnlimited(e.target.checked)} className="rounded" />
                No limit
              </label>
            </div>
            <input type="number" className={inputClass} value={limit} min={1} disabled={unlimited} onChange={(e) => setLimit(Number(e.target.value))} />
          </div>
          {err && <p className="text-red-600 text-sm">{err}</p>}
          <div className="flex justify-end gap-2 pt-2">
            <button type="button" className={btnSecondary} onClick={onClose}>Cancel</button>
            <button type="submit" className={btnPrimary} disabled={submitting}>{submitting ? 'Creating…' : 'Run Eval'}</button>
          </div>
        </form>
      </div>
    </div>
  )
}

// ---- EvalsPanel ----

export function EvalsPanel() {
  const navigate = useNavigate()
  const [searchParams] = useSearchParams()
  const policyId = searchParams.get('policy_id') ?? undefined

  const [runs, setRuns] = useState<EvalRun[]>([])
  const [policies, setPolicies] = useState<LLMPolicy[]>([])
  const [loading, setLoading] = useState(true)
  const [showModal, setShowModal] = useState(false)

  const policyName = (id: string) => policies.find((p) => p.id === id)?.name ?? id

  useEffect(() => {
    getPolicies().then(setPolicies).catch(() => {})
  }, [])

  useEffect(() => {
    setLoading(true)
    listEvalRuns(policyId, 50, 0)
      .then(setRuns)
      .catch(() => {})
      .finally(() => setLoading(false))
  }, [policyId])

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-xl font-semibold text-gray-900">Eval Runs</h2>
          {policyId && <p className="text-sm text-gray-500 mt-0.5">Filtered by policy: {policyName(policyId)}</p>}
        </div>
        <button className={btnPrimary} onClick={() => setShowModal(true)}>New Eval</button>
      </div>

      <div className="bg-white rounded-xl border border-gray-200 overflow-hidden">
        {loading ? (
          <div className="flex justify-center py-12">
            <div className="animate-spin rounded-full h-6 w-6 border-b-2 border-blue-600" />
          </div>
        ) : runs.length === 0 ? (
          <div className="py-12 text-center text-gray-400 text-sm">No eval runs yet.</div>
        ) : (
          <table className="w-full text-sm">
            <thead className="bg-gray-50 border-b border-gray-200">
              <tr>
                <th className="text-left px-4 py-3 font-medium text-gray-600">Created</th>
                <th className="text-left px-4 py-3 font-medium text-gray-600">Policy</th>
                <th className="text-left px-4 py-3 font-medium text-gray-600">Status</th>
                <th className="text-right px-4 py-3 font-medium text-gray-600">Total</th>
                <th className="text-right px-4 py-3 font-medium text-gray-600">Agreed</th>
                <th className="text-right px-4 py-3 font-medium text-gray-600">Disagreed</th>
                <th className="text-right px-4 py-3 font-medium text-gray-600">Errored</th>
                <th className="text-right px-4 py-3 font-medium text-gray-600">Duration</th>
                <th className="px-4 py-3" />
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-100">
              {runs.map((run) => (
                <tr
                  key={run.id}
                  className="hover:bg-gray-50 cursor-pointer"
                  onClick={() => navigate(`/evals/${run.id}`)}
                >
                  <td className="px-4 py-3 text-gray-700 whitespace-nowrap">{format(new Date(run.created_at), 'MMM dd HH:mm')}</td>
                  <td className="px-4 py-3 text-gray-700 max-w-[180px] truncate">
                    {policies.some((p) => p.id === run.policy_id) ? (
                      <Link
                        to={`/policies/${run.policy_id}`}
                        className="hover:underline text-blue-600"
                        onClick={(e) => e.stopPropagation()}
                      >
                        {policyName(run.policy_id)}
                      </Link>
                    ) : (
                      <span className="text-gray-600">
                        {run.policy_name || run.policy_id}
                        <span className="ml-1.5 px-1.5 py-0.5 rounded text-xs font-semibold bg-gray-100 text-gray-500">deleted</span>
                      </span>
                    )}
                  </td>
                  <td className="px-4 py-3"><StatusPill status={run.status} /></td>
                  <td className="px-4 py-3 text-right text-gray-700">{run.total}</td>
                  <td className="px-4 py-3 text-right text-green-600 font-medium">{run.agreed}</td>
                  <td className="px-4 py-3 text-right text-red-600 font-medium">{run.disagreed}</td>
                  <td className="px-4 py-3 text-right text-gray-500">{run.errored}</td>
                  <td className="px-4 py-3 text-right text-gray-500">{duration(run)}</td>
                  <td className="px-4 py-3 text-right text-gray-400">→</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      {showModal && (
        <RunEvalModal
          policyId={policyId}
          onClose={() => setShowModal(false)}
          onCreated={(runId) => navigate(`/evals/${runId}`)}
        />
      )}
    </div>
  )
}
