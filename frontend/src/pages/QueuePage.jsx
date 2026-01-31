import { useQuery } from '@tanstack/react-query'
import { useSearchParams, Link } from 'react-router-dom'
import {
  Clock,
  CheckCircle,
  AlertCircle,
  Loader2,
  FileText,
  Link as LinkIcon,
  File,
  RefreshCw
} from 'lucide-react'
import { format } from 'date-fns'
import { submissionsApi } from '../api/client'

const statusConfig = {
  pending: { icon: Clock, color: 'text-gray-500', bg: 'bg-gray-100', label: 'Pending' },
  analyzing: { icon: Loader2, color: 'text-primary-500', bg: 'bg-primary-100', label: 'Analyzing', animate: true },
  enriching: { icon: Loader2, color: 'text-warning-500', bg: 'bg-warning-100', label: 'Enriching', animate: true },
  reasoning: { icon: Loader2, color: 'text-purple-500', bg: 'bg-purple-100', label: 'Reasoning', animate: true },
  complete: { icon: CheckCircle, color: 'text-success-500', bg: 'bg-success-100', label: 'Complete' },
  failed: { icon: AlertCircle, color: 'text-danger-500', bg: 'bg-danger-100', label: 'Failed' },
}

const typeIcons = {
  file: File,
  url: LinkIcon,
  sandbox_report: FileText,
}

function StatusBadge({ status }) {
  const config = statusConfig[status] || statusConfig.pending
  const Icon = config.icon

  return (
    <span className={`badge ${config.bg} ${config.color}`}>
      <Icon className={`h-3 w-3 mr-1 ${config.animate ? 'animate-spin' : ''}`} />
      {config.label}
    </span>
  )
}

function QueuePage() {
  const [searchParams] = useSearchParams()
  const highlightId = searchParams.get('highlight')

  const { data: submissions, isLoading, error, refetch } = useQuery({
    queryKey: ['submissions'],
    queryFn: () => submissionsApi.list({ limit: 50 }),
    refetchInterval: 5000, // Refresh every 5 seconds
  })

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-64">
        <Loader2 className="h-8 w-8 animate-spin text-primary-500" />
      </div>
    )
  }

  if (error) {
    return (
      <div className="card text-center">
        <AlertCircle className="h-12 w-12 text-danger-500 mx-auto mb-4" />
        <h3 className="text-lg font-medium text-gray-900 mb-2">Failed to load queue</h3>
        <p className="text-gray-600 mb-4">{error.message}</p>
        <button onClick={() => refetch()} className="btn btn-primary">
          Retry
        </button>
      </div>
    )
  }

  return (
    <div>
      <div className="flex items-center justify-between mb-6">
        <h1 className="text-2xl font-bold text-gray-900">Analysis Queue</h1>
        <button
          onClick={() => refetch()}
          className="btn btn-secondary flex items-center"
        >
          <RefreshCw className="h-4 w-4 mr-2" />
          Refresh
        </button>
      </div>

      {submissions?.length === 0 ? (
        <div className="card text-center py-12">
          <FileText className="h-12 w-12 text-gray-400 mx-auto mb-4" />
          <h3 className="text-lg font-medium text-gray-900 mb-2">No submissions yet</h3>
          <p className="text-gray-600 mb-4">Submit a file, URL, or sandbox report to get started.</p>
          <Link to="/" className="btn btn-primary inline-flex">
            Submit Analysis
          </Link>
        </div>
      ) : (
        <div className="card overflow-hidden p-0">
          <table className="w-full">
            <thead className="bg-gray-50 border-b border-gray-200">
              <tr>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                  ID
                </th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                  Type
                </th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                  Name/URL
                </th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                  Status
                </th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                  Submitted
                </th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                  Actions
                </th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-200">
              {submissions?.map((submission) => {
                const TypeIcon = typeIcons[submission.type] || File
                const isHighlighted = highlightId === String(submission.id)

                return (
                  <tr
                    key={submission.id}
                    className={`hover:bg-gray-50 transition-colors ${
                      isHighlighted ? 'bg-primary-50' : ''
                    }`}
                  >
                    <td className="px-6 py-4 whitespace-nowrap">
                      <span className="font-mono text-sm text-gray-900">
                        #{submission.id}
                      </span>
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap">
                      <div className="flex items-center">
                        <TypeIcon className="h-4 w-4 text-gray-400 mr-2" />
                        <span className="text-sm text-gray-600 capitalize">
                          {submission.type.replace('_', ' ')}
                        </span>
                      </div>
                    </td>
                    <td className="px-6 py-4">
                      <div className="max-w-xs truncate text-sm text-gray-900">
                        {submission.filename || submission.original_url || '-'}
                      </div>
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap">
                      <StatusBadge status={submission.status} />
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                      {format(new Date(submission.created_at), 'MMM d, yyyy HH:mm')}
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap">
                      {submission.status === 'complete' ? (
                        <Link
                          to={`/reports/${submission.id}`}
                          className="text-primary-600 hover:text-primary-700 text-sm font-medium"
                        >
                          View Report
                        </Link>
                      ) : (
                        <span className="text-gray-400 text-sm">-</span>
                      )}
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
