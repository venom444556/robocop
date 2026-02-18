import { useState, useMemo } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Link } from 'react-router-dom'
import {
  FileText,
  Download,
  Eye,
  Loader2,
  AlertCircle,
  Calendar,
  Hash,
  Search,
  SlidersHorizontal
} from 'lucide-react'
import { format } from 'date-fns'
import { submissionsApi } from '../api/client'

const SEVERITY_LEVELS = ['All', 'Critical', 'High', 'Medium', 'Low']

const SEVERITY_COLORS = {
  critical: {
    badge: 'bg-red-100 text-red-800 dark:bg-red-900/40 dark:text-red-300',
    dot: 'bg-red-500',
  },
  high: {
    badge: 'bg-orange-100 text-orange-800 dark:bg-orange-900/40 dark:text-orange-300',
    dot: 'bg-orange-500',
  },
  medium: {
    badge: 'bg-yellow-100 text-yellow-800 dark:bg-yellow-900/40 dark:text-yellow-300',
    dot: 'bg-yellow-500',
  },
  low: {
    badge: 'bg-green-100 text-green-800 dark:bg-green-900/40 dark:text-green-300',
    dot: 'bg-green-500',
  },
}

const SORT_OPTIONS = [
  { value: 'newest', label: 'Newest First' },
  { value: 'oldest', label: 'Oldest First' },
  { value: 'severity', label: 'By Severity' },
]

const SEVERITY_ORDER = { critical: 0, high: 1, medium: 2, low: 3 }

function ReportsPage() {
  const [searchQuery, setSearchQuery] = useState('')
  const [sortBy, setSortBy] = useState('newest')
  const [severityFilter, setSeverityFilter] = useState('All')

  const { data: submissions, isLoading, error } = useQuery({
    queryKey: ['completedSubmissions'],
    queryFn: () => submissionsApi.list({ status: 'complete', limit: 50 }),
  })

  const filteredAndSorted = useMemo(() => {
    if (!submissions) return []

    let results = [...submissions]

    // Filter by search query
    if (searchQuery.trim()) {
      const query = searchQuery.toLowerCase()
      results = results.filter((s) => {
        const filename = (s.filename || '').toLowerCase()
        const url = (s.original_url || '').toLowerCase()
        const id = String(s.id)
        return filename.includes(query) || url.includes(query) || id.includes(query)
      })
    }

    // Filter by severity
    if (severityFilter !== 'All') {
      results = results.filter(
        (s) => s.severity && s.severity.toLowerCase() === severityFilter.toLowerCase()
      )
    }

    // Sort
    if (sortBy === 'newest') {
      results.sort((a, b) => new Date(b.created_at) - new Date(a.created_at))
    } else if (sortBy === 'oldest') {
      results.sort((a, b) => new Date(a.created_at) - new Date(b.created_at))
    } else if (sortBy === 'severity') {
      results.sort((a, b) => {
        const sevA = SEVERITY_ORDER[a.severity?.toLowerCase()] ?? 99
        const sevB = SEVERITY_ORDER[b.severity?.toLowerCase()] ?? 99
        return sevA - sevB
      })
    }

    return results
  }, [submissions, searchQuery, sortBy, severityFilter])

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-64">
        <Loader2 className="h-8 w-8 animate-spin text-primary-500" />
      </div>
    )
  }

  if (error) {
    return (
      <div className="card bg-white dark:bg-gray-800 text-center border border-gray-200 dark:border-gray-700">
        <AlertCircle className="h-12 w-12 text-danger-500 mx-auto mb-4" />
        <h3 className="text-lg font-medium text-gray-900 dark:text-gray-100 mb-2">
          Failed to load reports
        </h3>
        <p className="text-gray-600 dark:text-gray-400">{error.message}</p>
      </div>
    )
  }

  return (
    <div>
      {/* Header */}
      <div className="flex items-center justify-between mb-6">
        <h1 className="text-2xl font-bold text-gray-900 dark:text-gray-100">
          Analysis Reports
        </h1>
        <div className="flex items-center space-x-2">
          <span className="text-sm text-gray-500 dark:text-gray-400">
            {filteredAndSorted.length} of {submissions?.length || 0} reports
          </span>
        </div>
      </div>

      {/* Search and Filter Bar */}
      <div className="mb-6 space-y-4">
        {/* Search and Sort Row */}
        <div className="flex flex-col sm:flex-row gap-3">
          {/* Search Input */}
          <div className="relative flex-1">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-gray-400 dark:text-gray-500" />
            <input
              type="text"
              placeholder="Search by filename, URL, or ID..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="w-full pl-10 pr-4 py-2 border border-gray-300 dark:border-gray-600 rounded-lg
                bg-white dark:bg-gray-800 text-gray-900 dark:text-gray-100
                placeholder-gray-400 dark:placeholder-gray-500
                focus:outline-none focus:ring-2 focus:ring-primary-500 focus:border-primary-500
                dark:focus:ring-primary-400 dark:focus:border-primary-400
                transition-colors"
            />
          </div>

          {/* Sort Dropdown */}
          <div className="relative flex items-center">
            <SlidersHorizontal className="absolute left-3 h-4 w-4 text-gray-400 dark:text-gray-500 pointer-events-none" />
            <select
              value={sortBy}
              onChange={(e) => setSortBy(e.target.value)}
              className="pl-10 pr-8 py-2 border border-gray-300 dark:border-gray-600 rounded-lg
                bg-white dark:bg-gray-800 text-gray-900 dark:text-gray-100
                focus:outline-none focus:ring-2 focus:ring-primary-500 focus:border-primary-500
                dark:focus:ring-primary-400 dark:focus:border-primary-400
                appearance-none cursor-pointer transition-colors"
            >
              {SORT_OPTIONS.map((option) => (
                <option key={option.value} value={option.value}>
                  {option.label}
                </option>
              ))}
            </select>
          </div>
        </div>

        {/* Severity Filter Chips */}
        <div className="flex flex-wrap gap-2">
          {SEVERITY_LEVELS.map((level) => {
            const isActive = severityFilter === level
            const colorKey = level.toLowerCase()
            const dotColor = SEVERITY_COLORS[colorKey]?.dot

            return (
              <button
                key={level}
                onClick={() => setSeverityFilter(level)}
                className={`inline-flex items-center px-3 py-1.5 rounded-full text-sm font-medium
                  border transition-colors cursor-pointer
                  ${
                    isActive
                      ? level === 'All'
                        ? 'bg-primary-100 text-primary-800 border-primary-300 dark:bg-primary-900/40 dark:text-primary-300 dark:border-primary-700'
                        : `${SEVERITY_COLORS[colorKey]?.badge} border-transparent`
                      : 'bg-gray-100 text-gray-600 border-gray-200 hover:bg-gray-200 dark:bg-gray-700 dark:text-gray-300 dark:border-gray-600 dark:hover:bg-gray-600'
                  }`}
              >
                {level !== 'All' && dotColor && (
                  <span className={`w-2 h-2 rounded-full ${dotColor} mr-1.5`} />
                )}
                {level}
              </button>
            )
          })}
        </div>
      </div>

      {/* Results */}
      {submissions?.length === 0 ? (
        <div className="card bg-white dark:bg-gray-800 text-center py-12 border border-gray-200 dark:border-gray-700">
          <FileText className="h-12 w-12 text-gray-400 dark:text-gray-500 mx-auto mb-4" />
          <h3 className="text-lg font-medium text-gray-900 dark:text-gray-100 mb-2">
            No reports yet
          </h3>
          <p className="text-gray-600 dark:text-gray-400 mb-4">
            Completed analyses will appear here with their full reports.
          </p>
          <Link to="/" className="btn btn-primary inline-flex">
            Submit Analysis
          </Link>
        </div>
      ) : filteredAndSorted.length === 0 ? (
        <div className="card bg-white dark:bg-gray-800 text-center py-12 border border-gray-200 dark:border-gray-700">
          <Search className="h-12 w-12 text-gray-400 dark:text-gray-500 mx-auto mb-4" />
          <h3 className="text-lg font-medium text-gray-900 dark:text-gray-100 mb-2">
            No matching reports
          </h3>
          <p className="text-gray-600 dark:text-gray-400 mb-4">
            Try adjusting your search query or filters.
          </p>
          <button
            onClick={() => {
              setSearchQuery('')
              setSeverityFilter('All')
            }}
            className="text-primary-600 dark:text-primary-400 hover:text-primary-700 dark:hover:text-primary-300 font-medium transition-colors"
          >
            Clear all filters
          </button>
        </div>
      ) : (
        <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3">
          {filteredAndSorted.map((submission) => (
            <ReportCard key={submission.id} submission={submission} />
          ))}
        </div>
      )}
    </div>
  )
}

function SeverityBadge({ severity }) {
  if (!severity) return null

  const key = severity.toLowerCase()
  const colors = SEVERITY_COLORS[key]

  if (!colors) return null

  return (
    <span
      className={`inline-flex items-center px-2 py-0.5 rounded-full text-xs font-semibold ${colors.badge}`}
    >
      <span className={`w-1.5 h-1.5 rounded-full ${colors.dot} mr-1`} />
      {severity.charAt(0).toUpperCase() + severity.slice(1).toLowerCase()}
    </span>
  )
}

function ReportCard({ submission }) {
  return (
    <div
      className="card bg-white dark:bg-gray-800 border border-gray-200 dark:border-gray-700
        hover:shadow-md dark:hover:shadow-lg dark:hover:shadow-black/20 transition-shadow rounded-lg p-4"
    >
      <div className="flex items-start justify-between mb-4">
        <div className="flex items-center">
          <div className="bg-primary-100 dark:bg-primary-900/40 rounded-lg p-2 mr-3">
            <FileText className="h-5 w-5 text-primary-600 dark:text-primary-400" />
          </div>
          <div>
            <h3 className="font-medium text-gray-900 dark:text-gray-100">
              Report #{submission.id}
            </h3>
            <p className="text-sm text-gray-500 dark:text-gray-400 capitalize">
              {submission.type.replace('_', ' ')}
            </p>
          </div>
        </div>
        <SeverityBadge severity={submission.severity} />
      </div>

      <div className="space-y-2 mb-4">
        {submission.filename && (
          <div className="flex items-center text-sm">
            <Hash className="h-4 w-4 text-gray-400 dark:text-gray-500 mr-2 flex-shrink-0" />
            <span
              className="text-gray-600 dark:text-gray-300 truncate"
              title={submission.filename}
            >
              {submission.filename}
            </span>
          </div>
        )}
        {submission.original_url && (
          <div className="flex items-center text-sm">
            <Hash className="h-4 w-4 text-gray-400 dark:text-gray-500 mr-2 flex-shrink-0" />
            <span
              className="text-gray-600 dark:text-gray-300 truncate"
              title={submission.original_url}
            >
              {submission.original_url}
            </span>
          </div>
        )}
        <div className="flex items-center text-sm">
          <Calendar className="h-4 w-4 text-gray-400 dark:text-gray-500 mr-2 flex-shrink-0" />
          <span className="text-gray-600 dark:text-gray-300">
            {format(new Date(submission.created_at), 'MMM d, yyyy HH:mm')}
          </span>
        </div>
      </div>

      <div className="flex space-x-2">
        <Link
          to={`/reports/${submission.id}`}
          className="btn btn-primary flex-1 flex items-center justify-center text-sm
            dark:bg-primary-600 dark:hover:bg-primary-700 dark:text-white transition-colors"
        >
          <Eye className="h-4 w-4 mr-1" />
          View
        </Link>
        <button
          onClick={() => window.open(`/api/reports/${submission.id}/json`, '_blank')}
          className="btn btn-secondary flex items-center justify-center text-sm
            dark:bg-gray-700 dark:hover:bg-gray-600 dark:text-gray-200
            dark:border-gray-600 transition-colors"
        >
          <Download className="h-4 w-4" />
        </button>
      </div>
    </div>
  )
}

export default ReportsPage
