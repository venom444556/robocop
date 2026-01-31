import { useQuery } from '@tanstack/react-query'
import { Link } from 'react-router-dom'
import {
  FileText,
  Download,
  Eye,
  Loader2,
  AlertCircle,
  Calendar,
  Hash
} from 'lucide-react'
import { format } from 'date-fns'
import { reportsApi, submissionsApi } from '../api/client'

function ReportsPage() {
  const { data: submissions, isLoading, error } = useQuery({
    queryKey: ['completedSubmissions'],
    queryFn: () => submissionsApi.list({ status: 'complete', limit: 50 }),
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
        <h3 className="text-lg font-medium text-gray-900 mb-2">Failed to load reports</h3>
        <p className="text-gray-600">{error.message}</p>
      </div>
    )
  }

  return (
    <div>
      <div className="flex items-center justify-between mb-6">
        <h1 className="text-2xl font-bold text-gray-900">Analysis Reports</h1>
        <div className="flex items-center space-x-2">
          <span className="text-sm text-gray-500">
            {submissions?.length || 0} reports available
          </span>
        </div>
      </div>

      {submissions?.length === 0 ? (
        <div className="card text-center py-12">
          <FileText className="h-12 w-12 text-gray-400 mx-auto mb-4" />
          <h3 className="text-lg font-medium text-gray-900 mb-2">No reports yet</h3>
          <p className="text-gray-600 mb-4">
            Completed analyses will appear here with their full reports.
          </p>
          <Link to="/" className="btn btn-primary inline-flex">
            Submit Analysis
          </Link>
        </div>
      ) : (
        <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3">
          {submissions?.map((submission) => (
            <ReportCard key={submission.id} submission={submission} />
          ))}
        </div>
      )}
    </div>
  )
}

function ReportCard({ submission }) {
  return (
    <div className="card hover:shadow-md transition-shadow">
      <div className="flex items-start justify-between mb-4">
        <div className="flex items-center">
          <div className="bg-primary-100 rounded-lg p-2 mr-3">
            <FileText className="h-5 w-5 text-primary-600" />
          </div>
          <div>
            <h3 className="font-medium text-gray-900">Report #{submission.id}</h3>
            <p className="text-sm text-gray-500 capitalize">
              {submission.type.replace('_', ' ')}
            </p>
          </div>
        </div>
      </div>

      <div className="space-y-2 mb-4">
        {submission.filename && (
          <div className="flex items-center text-sm">
            <Hash className="h-4 w-4 text-gray-400 mr-2" />
            <span className="text-gray-600 truncate" title={submission.filename}>
              {submission.filename}
            </span>
          </div>
        )}
        {submission.original_url && (
          <div className="flex items-center text-sm">
            <Hash className="h-4 w-4 text-gray-400 mr-2" />
            <span className="text-gray-600 truncate" title={submission.original_url}>
              {submission.original_url}
            </span>
          </div>
        )}
        <div className="flex items-center text-sm">
          <Calendar className="h-4 w-4 text-gray-400 mr-2" />
          <span className="text-gray-600">
            {format(new Date(submission.created_at), 'MMM d, yyyy HH:mm')}
          </span>
        </div>
      </div>

      <div className="flex space-x-2">
        <Link
          to={`/reports/${submission.id}`}
          className="btn btn-primary flex-1 flex items-center justify-center text-sm"
        >
          <Eye className="h-4 w-4 mr-1" />
          View
        </Link>
        <button
          onClick={() => window.open(`/api/reports/${submission.id}/json`, '_blank')}
          className="btn btn-secondary flex items-center justify-center text-sm"
        >
          <Download className="h-4 w-4" />
        </button>
      </div>
    </div>
  )
}

export default ReportsPage
