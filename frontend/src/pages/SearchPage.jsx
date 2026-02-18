import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Link } from 'react-router-dom'
import {
  Search,
  Hash,
  Globe,
  Server,
  Mail,
  FileText,
  Loader2,
  AlertCircle,
  ArrowRight,
  ExternalLink,
  GitCompare,
  Filter,
} from 'lucide-react'
import { format } from 'date-fns'
import client from '../api/client'

const typeIcons = {
  ip: Server,
  domain: Globe,
  url: Globe,
  hash_md5: Hash,
  hash_sha1: Hash,
  hash_sha256: Hash,
  email: Mail,
  filename: FileText,
}

function SearchPage() {
  const [query, setQuery] = useState('')
  const [searchQuery, setSearchQuery] = useState('')
  const [typeFilter, setTypeFilter] = useState('')
  const [selectedIOC, setSelectedIOC] = useState(null)
  const [compareMode, setCompareMode] = useState(false)
  const [compareIds, setCompareIds] = useState([null, null])

  // IOC search
  const { data: searchResults, isLoading: searching } = useQuery({
    queryKey: ['ioc-search', searchQuery, typeFilter],
    queryFn: async () => {
      const params = new URLSearchParams({ q: searchQuery, limit: '50' })
      if (typeFilter) params.append('type', typeFilter)
      const response = await client.get(`/search/iocs?${params}`)
      return response.data
    },
    enabled: searchQuery.length >= 2,
  })

  // IOC correlation
  const { data: correlation, isLoading: correlating } = useQuery({
    queryKey: ['ioc-correlate', selectedIOC],
    queryFn: async () => {
      const response = await client.get(`/search/iocs/${encodeURIComponent(selectedIOC)}/correlate`)
      return response.data
    },
    enabled: !!selectedIOC,
  })

  // Submission comparison
  const { data: comparison, isLoading: comparing } = useQuery({
    queryKey: ['compare', compareIds[0], compareIds[1]],
    queryFn: async () => {
      const response = await client.get(`/search/submissions/compare?id1=${compareIds[0]}&id2=${compareIds[1]}`)
      return response.data
    },
    enabled: !!compareIds[0] && !!compareIds[1],
  })

  const handleSearch = (e) => {
    e.preventDefault()
    setSearchQuery(query)
    setSelectedIOC(null)
  }

  return (
    <div>
      <div className="flex items-center justify-between mb-6">
        <h1 className="text-2xl font-bold text-gray-900 dark:text-white">Search & Correlate</h1>
        <button
          onClick={() => { setCompareMode(!compareMode); setSelectedIOC(null) }}
          className={`btn ${compareMode ? 'btn-primary' : 'btn-secondary'} flex items-center text-sm`}
        >
          <GitCompare className="h-4 w-4 mr-2" />
          {compareMode ? 'Exit Compare' : 'Compare Submissions'}
        </button>
      </div>

      {/* Compare Mode */}
      {compareMode && (
        <div className="card mb-6">
          <h3 className="text-sm font-semibold text-gray-700 dark:text-gray-300 mb-3">Compare Two Submissions</h3>
          <div className="flex items-center gap-3">
            <input
              type="number"
              placeholder="Submission ID #1"
              className="input flex-1"
              value={compareIds[0] || ''}
              onChange={(e) => setCompareIds([e.target.value || null, compareIds[1]])}
            />
            <span className="text-gray-400 font-bold">vs</span>
            <input
              type="number"
              placeholder="Submission ID #2"
              className="input flex-1"
              value={compareIds[1] || ''}
              onChange={(e) => setCompareIds([compareIds[0], e.target.value || null])}
            />
          </div>

          {comparing && (
            <div className="flex justify-center py-6">
              <Loader2 className="h-6 w-6 animate-spin text-primary-500" />
            </div>
          )}

          {comparison && (
            <div className="mt-4 space-y-4">
              {/* Similarity score */}
              <div className="flex items-center gap-3">
                <span className="text-sm font-medium text-gray-600 dark:text-gray-400">Similarity:</span>
                <div className="flex-1 bg-gray-200 dark:bg-gray-700 rounded-full h-3">
                  <div
                    className="h-3 rounded-full bg-primary-500 transition-all"
                    style={{ width: `${Math.round((comparison.similarity_score || 0) * 100)}%` }}
                  />
                </div>
                <span className="text-sm font-bold text-gray-900 dark:text-white">
                  {Math.round((comparison.similarity_score || 0) * 100)}%
                </span>
              </div>

              <div className="grid grid-cols-3 gap-4 text-center">
                <div className="p-3 bg-green-50 dark:bg-green-900/20 rounded-lg">
                  <p className="text-2xl font-bold text-green-600">{comparison.shared_iocs?.length || 0}</p>
                  <p className="text-xs text-green-700 dark:text-green-400">Shared IOCs</p>
                </div>
                <div className="p-3 bg-blue-50 dark:bg-blue-900/20 rounded-lg">
                  <p className="text-2xl font-bold text-blue-600">{comparison.unique_to_1?.length || 0}</p>
                  <p className="text-xs text-blue-700 dark:text-blue-400">Only in #{compareIds[0]}</p>
                </div>
                <div className="p-3 bg-purple-50 dark:bg-purple-900/20 rounded-lg">
                  <p className="text-2xl font-bold text-purple-600">{comparison.unique_to_2?.length || 0}</p>
                  <p className="text-xs text-purple-700 dark:text-purple-400">Only in #{compareIds[1]}</p>
                </div>
              </div>

              {comparison.shared_iocs?.length > 0 && (
                <div>
                  <p className="text-xs font-medium text-gray-500 dark:text-gray-400 mb-2 uppercase">Shared Indicators</p>
                  <div className="flex flex-wrap gap-1.5">
                    {comparison.shared_iocs.slice(0, 20).map((ioc, idx) => (
                      <span key={idx} className="px-2 py-1 bg-green-100 dark:bg-green-900/30 text-green-700 dark:text-green-300 rounded text-xs font-mono">
                        {ioc.value?.substring(0, 40)}
                      </span>
                    ))}
                    {comparison.shared_iocs.length > 20 && (
                      <span className="px-2 py-1 bg-gray-100 dark:bg-gray-700 text-gray-500 rounded text-xs">
                        +{comparison.shared_iocs.length - 20} more
                      </span>
                    )}
                  </div>
                </div>
              )}

              {comparison.shared_techniques?.length > 0 && (
                <div>
                  <p className="text-xs font-medium text-gray-500 dark:text-gray-400 mb-2 uppercase">Shared MITRE Techniques</p>
                  <div className="flex flex-wrap gap-1.5">
                    {comparison.shared_techniques.map((tech, idx) => (
                      <span key={idx} className="px-2 py-1 bg-purple-100 dark:bg-purple-900/30 text-purple-700 dark:text-purple-300 rounded text-xs">
                        {tech.technique_id}: {tech.name}
                      </span>
                    ))}
                  </div>
                </div>
              )}
            </div>
          )}
        </div>
      )}

      {/* Search Bar */}
      <form onSubmit={handleSearch} className="mb-6">
        <div className="flex gap-2">
          <div className="relative flex-1">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-5 w-5 text-gray-400" />
            <input
              type="text"
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              placeholder="Search IOCs: IP address, domain, hash, URL, email..."
              className="input pl-10"
            />
          </div>
          <select
            value={typeFilter}
            onChange={(e) => setTypeFilter(e.target.value)}
            className="input w-40"
          >
            <option value="">All Types</option>
            <option value="ip">IP</option>
            <option value="domain">Domain</option>
            <option value="url">URL</option>
            <option value="hash_sha256">SHA256</option>
            <option value="hash_md5">MD5</option>
            <option value="email">Email</option>
            <option value="filename">Filename</option>
          </select>
          <button type="submit" className="btn btn-primary">
            <Search className="h-4 w-4" />
          </button>
        </div>
      </form>

      <div className="grid gap-6 lg:grid-cols-3">
        {/* Search Results */}
        <div className={selectedIOC ? 'lg:col-span-1' : 'lg:col-span-3'}>
          {searching && (
            <div className="flex justify-center py-12">
              <Loader2 className="h-6 w-6 animate-spin text-primary-500" />
            </div>
          )}

          {searchResults && (
            <div className="card">
              <div className="flex items-center justify-between mb-3">
                <h3 className="text-sm font-semibold text-gray-700 dark:text-gray-300">
                  Results ({searchResults.total_count || searchResults.results?.length || 0})
                </h3>
              </div>
              {searchResults.results?.length === 0 && (
                <p className="text-sm text-gray-500 text-center py-8">No IOCs found matching "{searchQuery}"</p>
              )}
              <div className="space-y-1">
                {(searchResults.results || []).map((ioc, idx) => {
                  const Icon = typeIcons[ioc.type] || Hash
                  return (
                    <button
                      key={idx}
                      onClick={() => setSelectedIOC(ioc.value)}
                      className={`w-full flex items-center gap-2 py-2 px-3 rounded-lg text-left hover:bg-gray-50 dark:hover:bg-gray-800 transition-colors ${
                        selectedIOC === ioc.value ? 'bg-primary-50 dark:bg-primary-900/20 border border-primary-200' : ''
                      }`}
                    >
                      <Icon className="h-4 w-4 text-gray-400 shrink-0" />
                      <div className="min-w-0 flex-1">
                        <p className="font-mono text-xs text-gray-800 dark:text-gray-200 truncate">{ioc.value}</p>
                        <p className="text-xs text-gray-500">
                          {ioc.type} &middot; #{ioc.submission_id} &middot; {ioc.submission_filename || 'URL submission'}
                        </p>
                      </div>
                      <ArrowRight className="h-3 w-3 text-gray-300 shrink-0" />
                    </button>
                  )
                })}
              </div>
            </div>
          )}

          {!searchResults && !searching && searchQuery.length === 0 && (
            <div className="card text-center py-12">
              <Search className="h-12 w-12 text-gray-300 mx-auto mb-4" />
              <h3 className="text-lg font-medium text-gray-700 dark:text-gray-300 mb-2">Search for IOCs</h3>
              <p className="text-sm text-gray-500">
                Search by IP, domain, hash, URL, or email to find correlations across submissions.
              </p>
            </div>
          )}
        </div>

        {/* Correlation Panel */}
        {selectedIOC && (
          <div className="lg:col-span-2">
            {correlating && (
              <div className="card flex justify-center py-12">
                <Loader2 className="h-6 w-6 animate-spin text-primary-500" />
              </div>
            )}

            {correlation && (
              <div className="space-y-4">
                {/* IOC Summary */}
                <div className="card">
                  <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-2 font-mono break-all">
                    {correlation.ioc_value}
                  </h3>
                  <div className="flex gap-4 text-sm text-gray-600 dark:text-gray-400">
                    <span>Type: <strong>{correlation.ioc_type}</strong></span>
                    <span>Seen: <strong>{correlation.total_appearances}x</strong></span>
                    {correlation.first_seen && (
                      <span>First: <strong>{format(new Date(correlation.first_seen), 'MMM d, yyyy')}</strong></span>
                    )}
                    {correlation.last_seen && (
                      <span>Last: <strong>{format(new Date(correlation.last_seen), 'MMM d, yyyy')}</strong></span>
                    )}
                  </div>
                </div>

                {/* Submissions containing this IOC */}
                <div className="card">
                  <h4 className="text-sm font-semibold text-gray-700 dark:text-gray-300 mb-3">
                    Submissions ({correlation.submissions?.length || 0})
                  </h4>
                  <div className="space-y-2">
                    {correlation.submissions?.map((sub, idx) => (
                      <Link
                        key={idx}
                        to={`/reports/${sub.id}`}
                        className="flex items-center justify-between py-2 px-3 bg-gray-50 dark:bg-gray-800 rounded-lg hover:bg-gray-100 dark:hover:bg-gray-700"
                      >
                        <div>
                          <span className="text-sm font-medium text-gray-900 dark:text-white">#{sub.id}</span>
                          <span className="text-xs text-gray-500 ml-2">{sub.filename || sub.type}</span>
                        </div>
                        <div className="flex items-center gap-2">
                          {sub.severity && (
                            <span className={`px-2 py-0.5 rounded text-xs font-semibold ${
                              sub.severity === 'critical' ? 'bg-red-100 text-red-700' :
                              sub.severity === 'high' ? 'bg-orange-100 text-orange-700' :
                              'bg-gray-100 text-gray-600'
                            }`}>
                              {sub.severity}
                            </span>
                          )}
                          <ExternalLink className="h-3 w-3 text-gray-400" />
                        </div>
                      </Link>
                    ))}
                  </div>
                </div>

                {/* Related IOCs */}
                {correlation.related_iocs?.length > 0 && (
                  <div className="card">
                    <h4 className="text-sm font-semibold text-gray-700 dark:text-gray-300 mb-3">
                      Related IOCs (co-occurring)
                    </h4>
                    <div className="space-y-1">
                      {correlation.related_iocs.slice(0, 15).map((related, idx) => (
                        <button
                          key={idx}
                          onClick={() => { setSelectedIOC(related.value); setQuery(related.value); setSearchQuery(related.value) }}
                          className="w-full flex items-center justify-between py-1.5 px-2 rounded hover:bg-gray-50 dark:hover:bg-gray-800 text-left"
                        >
                          <span className="font-mono text-xs text-gray-700 dark:text-gray-300 truncate">{related.value}</span>
                          <div className="flex items-center gap-2 shrink-0">
                            <span className="badge badge-info text-xs">{related.type}</span>
                            <span className="text-xs text-gray-400">{related.co_occurrence_count}x</span>
                          </div>
                        </button>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  )
}

export default SearchPage
