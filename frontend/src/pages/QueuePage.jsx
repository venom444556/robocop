import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { useSearchParams, Link } from 'react-router-dom'
import {
  Clock,
  CheckCircle,
  AlertCircle,
  Loader2,
  FileText,
  Link as LinkIcon,
  File,
  RefreshCw,
  Trash2,
  Search,
  RotateCcw,
  Filter
} from 'lucide-react'
import { format } from 'date-fns'
import { submissionsApi } from '../api/client'
import client from '../api/client'

const statusConfig = {
  pending: { icon: Clock, color: 'text-gray-500', bg: 'bg-gray-100', darkBg: 'dark:bg-gray-700', darkColor: 'dark:text-gray-300', label: 'Pending' },
  analyzing: { icon: Loader2, color: 'text-primary-500', bg: 'bg-primary-100', darkBg: 'dark:bg-primary-900', darkColor: 'dark:text-primary-300', label: 'Analyzing', animate: true },
  enriching: { icon: Loader2, color: 'text-warning-500', bg: 'bg-warning-100', darkBg: 'dark:bg-warning-900', darkColor: 'dark:text-warning-300', label: 'Enriching', animate: true },
  reasoning: { icon: Loader2, color: 'text-purple-500', bg: 'bg-purple-100', darkBg: 'dark:bg-purple-900', darkColor: 'dark:text-purple-300', label: 'Reasoning', animate: true },
  complete: { icon: CheckCircle, color: 'text-success-500', bg: 'bg-success-100', darkBg: 'dark:bg-success-900', darkColor: 'dark:text-success-300', label: 'Complete' },
  failed: { icon: AlertCircle, color: 'text-danger-500', bg: 'bg-danger-100', darkBg: 'dark:bg-danger-900', darkColor: 'dark:text-danger-300', label: 'Failed' },
}

const typeIcons = {
  file: File,
  url: LinkIcon,
  sandbox_report: FileText,
}

const statusFilters = [
  { key: 'all', label: 'All' },
  { key: 'pending', label: 'Pending' },
  { key: 'analyzing', label: 'Analyzing' },
  { key: 'enriching', label: 'Enriching' },
  { key: 'reasoning', label: 'Reasoning' },
  { key: 'complete', label: 'Complete' },
  { key: 'failed', label: 'Failed' },
]

function StatusBadge({ status }) {
  const config = statusConfig[status] || statusConfig.pending
  const Icon = config.icon

  return (
    <span className={`badge ${config.bg} ${config.darkBg} ${config.color} ${config.darkColor}`}>
      <Icon className={`h-3 w-3 mr-1 ${config.animate ? 'animate-spin' : ''}`} />
      {config.label}
    </span>
  )
}

function QueuePage() {
  const [searchParams] = useSearchParams()
  const highlightId = searchParams.get('highlight')
  const queryClient = useQueryClient()

  const [searchQuery, setSearchQuery] = useState('')
  const [statusFilter, setStatusFilter] = useState('all')
  const [deleteConfirmId, setDeleteConfirmId] = useState(null)

  const { data: submissions, isLoading, error, refetch } = useQuery({
    queryKey: ['submissions'],
    queryFn: () => submissionsApi.list({ limit: 50 }),
    refetchInterval: 5000,
  })

  const deleteMutation = useMutation({
    mutationFn: (id) => client.delete(`/api/management/submissions/${id}`),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['submissions'] })
      setDeleteConfirmId(null)
    },
  })

  const reanalyzeMutation = useMutation({
    mutationFn: (id) => client.post(`/api/management/submissions/${id}/reanalyze`),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['submissions'] })
    },
  })

  const filteredSubmissions = submissions?.filter((submission) => {
    // Apply search filter
    if (searchQuery) {
      const query = searchQuery.toLowerCase()
      const filename = (submission.filename || '').toLowerCase()
      const url = (submission.original_url || '').toLowerCase()
      if (!filename.includes(query) && !url.includes(query)) {
        return false
      }
    }

    // Apply status filter
    if (statusFilter !== 'all' && submission.status !== statusFilter) {
      return false
    }

    return true
  })

  const handleDelete = (id) => {
    deleteMutation.mutate(id)
  }

  const handleReanalyze = (id) => {
    reanalyzeMutation.mutate(id)
  }

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-64">
        <Loader2 className="h-8 w-8 animate-spin text-primary-500" />
      </div>
    )
  }

  if (error) {
    return (
      <div className="card text-center dark:bg-gray-800 dark:border-gray-700">
        <AlertCircle className="h-12 w-12 text-danger-500 mx-auto mb-4" />
        <h3 className="text-lg font-medium text-gray-900 dark:text-gray-100 mb-2">Failed to load queue</h3>
        <p className="text-gray-600 dark:text-gray-400 mb-4">{error.message}</p>
        <button onClick={() => refetch()} className="btn btn-primary">
          Retry
        </button>
      </div>
    )
  }

  return (
    <div>
      {/* Header */}
      <div className="flex items-center justify-between mb-6">
        <h1 className="text-2xl font-bold text-gray-900 dark:text-gray-100">Analysis Queue</h1>
        <button
          onClick={() => refetch()}
          className="btn btn-secondary flex items-center dark:bg-gray-700 dark:text-gray-200 dark:hover:bg-gray-600 dark:border-gray-600"
        >
          <RefreshCw className="h-4 w-4 mr-2" />
          Refresh
        </button>
      </div>

      {/* Search and Filters */}
      <div className="mb-4 space-y-3">
        {/* Search bar */}
        <div className="relative">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-gray-400 dark:text-gray-500" />
          <input
            type="text"
            placeholder="Search by filename or URL..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="w-full pl-10 pr-4 py-2 border border-gray-300 dark:border-gray-600 rounded-lg text-sm text-gray-900 dark:text-gray-100 bg-white dark:bg-gray-800 placeholder-gray-400 dark:placeholder-gray-500 focus:outline-none focus:ring-2 focus:ring-primary-500 focus:border-primary-500 dark:focus:ring-primary-400 dark:focus:border-primary-400"
          />
        </div>

        {/* Status filter buttons */}
        <div className="flex items-center gap-2 flex-wrap">
          <Filter className="h-4 w-4 text-gray-400 dark:text-gray-500 mr-1" />
          {statusFilters.map((filter) => (
            <button
              key={filter.key}
              onClick={() => setStatusFilter(filter.key)}
              className={`px-3 py-1 text-xs font-medium rounded-full border transition-colors ${
                statusFilter === filter.key
                  ? 'bg-primary-100 dark:bg-primary-900 text-primary-700 dark:text-primary-300 border-primary-300 dark:border-primary-700'
                  : 'bg-white dark:bg-gray-800 text-gray-600 dark:text-gray-400 border-gray-300 dark:border-gray-600 hover:bg-gray-50 dark:hover:bg-gray-700'
              }`}
            >
              {filter.label}
            </button>
          ))}
        </div>
      </div>

      {/* Delete confirmation dialog */}
      {deleteConfirmId !== null && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50">
          <div className="bg-white dark:bg-gray-800 rounded-lg shadow-xl p-6 max-w-sm mx-4 border border-gray-200 dark:border-gray-700">
            <div className="flex items-center mb-4">
              <AlertCircle className="h-6 w-6 text-danger-500 mr-3" />
              <h3 className="text-lg font-semibold text-gray-900 dark:text-gray-100">Confirm Delete</h3>
            </div>
            <p className="text-gray-600 dark:text-gray-400 mb-6">
              Are you sure you want to delete submission <span className="font-mono font-medium text-gray-900 dark:text-gray-100">#{deleteConfirmId}</span>? This action cannot be undone.
            </p>
            <div className="flex justify-end gap-3">
              <button
                onClick={() => setDeleteConfirmId(null)}
                className="px-4 py-2 text-sm font-medium text-gray-700 dark:text-gray-300 bg-white dark:bg-gray-700 border border-gray-300 dark:border-gray-600 rounded-lg hover:bg-gray-50 dark:hover:bg-gray-600 transition-colors"
                disabled={deleteMutation.isPending}
              >
                Cancel
              </button>
              <button
                onClick={() => handleDelete(deleteConfirmId)}
                className="px-4 py-2 text-sm font-medium text-white bg-danger-600 border border-transparent rounded-lg hover:bg-danger-700 dark:bg-danger-500 dark:hover:bg-danger-600 transition-colors flex items-center"
                disabled={deleteMutation.isPending}
              >
                {deleteMutation.isPending ? (
                  <Loader2 className="h-4 w-4 animate-spin mr-2" />
                ) : (
                  <Trash2 className="h-4 w-4 mr-2" />
                )}
                Delete
              </button>
            </div>
          </div>
        </div>
      )}

      {submissions?.length === 0 ? (
        <div className="card text-center py-12 dark:bg-gray-800 dark:border-gray-700">
          <FileText className="h-12 w-12 text-gray-400 dark:text-gray-500 mx-auto mb-4" />
          <h3 className="text-lg font-medium text-gray-900 dark:text-gray-100 mb-2">No submissions yet</h3>
          <p className="text-gray-600 dark:text-gray-400 mb-4">Submit a file, URL, or sandbox report to get started.</p>
          <Link to="/" className="btn btn-primary inline-flex">
            Submit Analysis
          </Link>
        </div>
      ) : filteredSubmissions?.length === 0 ? (
        <div className="card text-center py-12 dark:bg-gray-800 dark:border-gray-700">
          <Search className="h-12 w-12 text-gray-400 dark:text-gray-500 mx-auto mb-4" />
          <h3 className="text-lg font-medium text-gray-900 dark:text-gray-100 mb-2">No matching submissions</h3>
          <p className="text-gray-600 dark:text-gray-400 mb-4">Try adjusting your search query or status filter.</p>
          <button
            onClick={() => { setSearchQuery(''); setStatusFilter('all') }}
            className="btn btn-secondary inline-flex dark:bg-gray-700 dark:text-gray-200 dark:hover:bg-gray-600 dark:border-gray-600"
          >
            Clear Filters
          </button>
        </div>
      ) : (
        <div className="card overflow-hidden p-0 dark:bg-gray-800 dark:border-gray-700">
          <table className="w-full">
            <thead className="bg-gray-50 dark:bg-gray-900 border-b border-gray-200 dark:border-gray-700">
              <tr>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                  ID
                </th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                  Type
                </th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                  Name/URL
                </th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                  Status
                </th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                  Submitted
                </th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                  Actions
                </th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-200 dark:divide-gray-700">
              {filteredSubmissions?.map((submission) => {
                const TypeIcon = typeIcons[submission.type] || File
                const isHighlighted = highlightId === String(submission.id)
                const canReanalyze = submission.status === 'complete' || submission.status === 'failed'

                return (
                  <tr
                    key={submission.id}
                    className={`group hover:bg-gray-50 dark:hover:bg-gray-700/50 transition-colors ${
                      isHighlighted ? 'bg-primary-50 dark:bg-primary-900/30' : 'dark:bg-gray-800'
                    }`}
                  >
                    <td className="px-6 py-4 whitespace-nowrap">
                      <span className="font-mono text-sm text-gray-900 dark:text-gray-100">
                        #{submission.id}
                      </span>
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap">
                      <div className="flex items-center">
                        <TypeIcon className="h-4 w-4 text-gray-400 dark:text-gray-500 mr-2" />
                        <span className="text-sm text-gray-600 dark:text-gray-400 capitalize">
                          {submission.type.replace('_', ' ')}
                        </span>
                      </div>
                    </td>
                    <td className="px-6 py-4">
                      <div className="max-w-xs truncate text-sm text-gray-900 dark:text-gray-100">
                        {submission.filename || submission.original_url || '-'}
                      </div>
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap">
                      <StatusBadge status={submission.status} />
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500 dark:text-gray-400">
                      {format(new Date(submission.created_at), 'MMM d, yyyy HH:mm')}
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap">
                      <div className="flex items-center gap-2">
                        {submission.status === 'complete' && (
                          <Link
                            to={`/reports/${submission.id}`}
                            className="text-primary-600 dark:text-primary-400 hover:text-primary-700 dark:hover:text-primary-300 text-sm font-medium"
                          >
                            View Report
                          </Link>
                        )}

                        {canReanalyze && (
                          <button
                            onClick={() => handleReanalyze(submission.id)}
                            disabled={reanalyzeMutation.isPending}
                            title="Reanalyze"
                            className="p-1.5 text-gray-400 dark:text-gray-500 hover:text-primary-600 dark:hover:text-primary-400 hover:bg-primary-50 dark:hover:bg-primary-900/30 rounded-md transition-colors opacity-0 group-hover:opacity-100 focus:opacity-100"
                          >
                            {reanalyzeMutation.isPending ? (
                              <Loader2 className="h-4 w-4 animate-spin" />
                            ) : (
                              <RotateCcw className="h-4 w-4" />
                            )}
                          </button>
                        )}

                        {!canReanalyze && submission.status !== 'complete' && (
                          <span className="text-gray-400 dark:text-gray-600 text-sm">-</span>
                        )}

                        <button
                          onClick={() => setDeleteConfirmId(submission.id)}
                          title="Delete submission"
                          className="p-1.5 text-gray-400 dark:text-gray-500 hover:text-danger-600 dark:hover:text-danger-400 hover:bg-danger-50 dark:hover:bg-danger-900/30 rounded-md transition-colors opacity-0 group-hover:opacity-100 focus:opacity-100"
                        >
                          <Trash2 className="h-4 w-4" />
                        </button>
                      </div>
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

export default QueuePage
