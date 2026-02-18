import { useQuery } from '@tanstack/react-query'
import { Link } from 'react-router-dom'
import {
  Shield,
  AlertTriangle,
  Hash,
  FileText,
  Activity,
  TrendingUp,
  Target,
  Search,
  Loader2,
  AlertCircle,
  ArrowRight,
  BarChart3,
} from 'lucide-react'
import { format, subDays } from 'date-fns'
import { analysisApi, submissionsApi } from '../api/client'
import client from '../api/client'

const severityColors = {
  critical: 'bg-red-500',
  high: 'bg-orange-500',
  medium: 'bg-yellow-500',
  low: 'bg-green-500',
  informational: 'bg-blue-500',
}

const severityTextColors = {
  critical: 'text-red-600',
  high: 'text-orange-600',
  medium: 'text-yellow-600',
  low: 'text-green-600',
  informational: 'text-blue-600',
}

const tacticOrder = [
  'Reconnaissance', 'Resource Development', 'Initial Access', 'Execution',
  'Persistence', 'Privilege Escalation', 'Defense Evasion', 'Credential Access',
  'Discovery', 'Lateral Movement', 'Collection', 'Command and Control',
  'Exfiltration', 'Impact',
]

function DashboardPage() {
  const { data: stats, isLoading, error } = useQuery({
    queryKey: ['dashboard-stats'],
    queryFn: async () => {
      const response = await client.get('/dashboard/stats')
      return response.data
    },
    refetchInterval: 30000,
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
        <h3 className="text-lg font-medium text-gray-900 dark:text-white mb-2">Failed to load dashboard</h3>
        <p className="text-gray-600 dark:text-gray-400">{error.message}</p>
      </div>
    )
  }

  const maxDailyCount = Math.max(...(stats?.submissions_last_7_days?.map(d => d.count) || [1]), 1)
  const maxTechniqueCount = Math.max(...(stats?.mitre_heatmap?.map(t => t.count) || [1]), 1)

  return (
    <div>
      <div className="flex items-center justify-between mb-6">
        <h1 className="text-2xl font-bold text-gray-900 dark:text-white">Threat Dashboard</h1>
        <Link to="/" className="btn btn-primary flex items-center text-sm">
          <FileText className="h-4 w-4 mr-2" />
          New Submission
        </Link>
      </div>

      {/* Stat Cards */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4 mb-6">
        <StatCard
          icon={FileText}
          label="Total Submissions"
          value={stats?.total_submissions || 0}
          sub={`${stats?.total_complete || 0} complete`}
          color="text-primary-600"
          bg="bg-primary-100 dark:bg-primary-900/30"
        />
        <StatCard
          icon={AlertTriangle}
          label="Critical/High"
          value={(stats?.submissions_by_severity?.critical || 0) + (stats?.submissions_by_severity?.high || 0)}
          sub="need attention"
          color="text-red-600"
          bg="bg-red-100 dark:bg-red-900/30"
        />
        <StatCard
          icon={Hash}
          label="Total IOCs"
          value={stats?.total_iocs || 0}
          sub={`${stats?.total_unique_iocs || 0} unique`}
          color="text-purple-600"
          bg="bg-purple-100 dark:bg-purple-900/30"
        />
        <StatCard
          icon={Activity}
          label="Active Analyses"
          value={stats?.total_analyzing || 0}
          sub={`${stats?.total_failed || 0} failed`}
          color="text-warning-600"
          bg="bg-warning-100 dark:bg-warning-900/30"
        />
      </div>

      <div className="grid gap-6 lg:grid-cols-2">
        {/* Submissions Over Time */}
        <div className="card">
          <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-4 flex items-center">
            <TrendingUp className="h-5 w-5 mr-2 text-primary-500" />
            Submissions (Last 7 Days)
          </h3>
          <div className="flex items-end gap-2 h-40">
            {stats?.submissions_last_7_days?.map((day, idx) => (
              <div key={idx} className="flex-1 flex flex-col items-center">
                <span className="text-xs font-medium text-gray-600 dark:text-gray-400 mb-1">{day.count}</span>
                <div
                  className="w-full bg-primary-500 rounded-t-sm transition-all min-h-[4px]"
                  style={{ height: `${Math.max((day.count / maxDailyCount) * 120, 4)}px` }}
                />
                <span className="text-xs text-gray-500 mt-2">
                  {format(new Date(day.date), 'EEE')}
                </span>
              </div>
            ))}
          </div>
        </div>

        {/* Severity Distribution */}
        <div className="card">
          <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-4 flex items-center">
            <BarChart3 className="h-5 w-5 mr-2 text-red-500" />
            Severity Distribution
          </h3>
          <div className="space-y-3">
            {['critical', 'high', 'medium', 'low', 'informational'].map(level => {
              const count = stats?.submissions_by_severity?.[level] || 0
              const total = stats?.total_complete || 1
              const pct = Math.round((count / total) * 100)
              return (
                <div key={level} className="flex items-center gap-3">
                  <span className="text-xs font-medium text-gray-600 dark:text-gray-400 w-24 capitalize">{level}</span>
                  <div className="flex-1 bg-gray-200 dark:bg-gray-700 rounded-full h-3">
                    <div
                      className={`h-3 rounded-full ${severityColors[level]} transition-all`}
                      style={{ width: `${Math.max(pct, count > 0 ? 3 : 0)}%` }}
                    />
                  </div>
                  <span className="text-sm font-medium text-gray-700 dark:text-gray-300 w-12 text-right">{count}</span>
                </div>
              )
            })}
          </div>
        </div>

        {/* Top IOCs */}
        <div className="card">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-lg font-semibold text-gray-900 dark:text-white flex items-center">
              <Hash className="h-5 w-5 mr-2 text-purple-500" />
              Top IOCs
            </h3>
            <Link to="/search" className="text-xs text-primary-600 hover:underline flex items-center">
              Search all <ArrowRight className="h-3 w-3 ml-1" />
            </Link>
          </div>
          {stats?.top_iocs?.length > 0 ? (
            <div className="space-y-2">
              {stats.top_iocs.slice(0, 8).map((ioc, idx) => (
                <div key={idx} className="flex items-center justify-between py-1.5 border-b border-gray-100 dark:border-gray-700 last:border-0">
                  <div className="flex items-center gap-2 min-w-0">
                    <span className="badge badge-info text-xs shrink-0">{ioc.type}</span>
                    <span className="font-mono text-xs text-gray-700 dark:text-gray-300 truncate">{ioc.value}</span>
                  </div>
                  <span className="text-xs font-medium text-gray-500 shrink-0 ml-2">{ioc.count}x</span>
                </div>
              ))}
            </div>
          ) : (
            <p className="text-sm text-gray-500 text-center py-6">No IOCs tracked yet</p>
          )}
        </div>

        {/* Recent Threat Hunt Findings */}
        <div className="card">
          <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-4 flex items-center">
            <Search className="h-5 w-5 mr-2 text-orange-500" />
            Recent Findings
          </h3>
          {stats?.recent_findings?.length > 0 ? (
            <div className="space-y-2">
              {stats.recent_findings.slice(0, 6).map((finding, idx) => (
                <Link
                  key={idx}
                  to={`/reports/${finding.submission_id}`}
                  className="flex items-center justify-between py-1.5 border-b border-gray-100 dark:border-gray-700 last:border-0 hover:bg-gray-50 dark:hover:bg-gray-800 -mx-2 px-2 rounded"
                >
                  <div className="min-w-0">
                    <p className="text-sm font-medium text-gray-800 dark:text-gray-200 truncate">{finding.title}</p>
                    <p className="text-xs text-gray-500">#{finding.submission_id}</p>
                  </div>
                  <span className={`px-2 py-0.5 rounded text-xs font-semibold shrink-0 ml-2 ${
                    finding.severity === 'critical' ? 'bg-red-600 text-white' :
                    finding.severity === 'high' ? 'bg-orange-500 text-white' :
                    finding.severity === 'medium' ? 'bg-yellow-500 text-white' :
                    'bg-gray-200 text-gray-700'
                  }`}>
                    {finding.severity}
                  </span>
                </Link>
              ))}
            </div>
          ) : (
            <p className="text-sm text-gray-500 text-center py-6">No findings yet</p>
          )}
        </div>

        {/* MITRE ATT&CK Heatmap */}
        <div className="card lg:col-span-2">
          <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-4 flex items-center">
            <Target className="h-5 w-5 mr-2 text-purple-500" />
            MITRE ATT&CK Heatmap
          </h3>
          {stats?.mitre_heatmap?.length > 0 ? (
            <div>
              {/* Group by tactic */}
              {tacticOrder.map(tactic => {
                const techniques = stats.mitre_heatmap.filter(t => t.tactic === tactic)
                if (techniques.length === 0) return null
                return (
                  <div key={tactic} className="mb-3">
                    <p className="text-xs font-medium text-gray-500 dark:text-gray-400 mb-1.5 uppercase">{tactic}</p>
                    <div className="flex flex-wrap gap-1.5">
                      {techniques.map((tech, idx) => {
                        const intensity = Math.min(tech.count / maxTechniqueCount, 1)
                        const r = Math.round(139 + (220 - 139) * (1 - intensity))
                        const g = Math.round(92 + (220 - 92) * (1 - intensity))
                        const b = Math.round(246 + (220 - 246) * (1 - intensity))
                        return (
                          <span
                            key={idx}
                            className="px-2 py-1 rounded text-xs font-medium text-white"
                            style={{ backgroundColor: `rgb(${r}, ${g}, ${b})` }}
                            title={`${tech.technique_id}: ${tech.technique_name} (${tech.count} occurrences)`}
                          >
                            {tech.technique_id}
                            <span className="ml-1 opacity-75">({tech.count})</span>
                          </span>
                        )
                      })}
                    </div>
                  </div>
                )
              })}
              {/* Techniques with unknown/missing tactic */}
              {stats.mitre_heatmap.filter(t => !tacticOrder.includes(t.tactic)).length > 0 && (
                <div className="mb-3">
                  <p className="text-xs font-medium text-gray-500 dark:text-gray-400 mb-1.5 uppercase">Other</p>
                  <div className="flex flex-wrap gap-1.5">
                    {stats.mitre_heatmap.filter(t => !tacticOrder.includes(t.tactic)).map((tech, idx) => (
                      <span
                        key={idx}
                        className="px-2 py-1 rounded text-xs font-medium bg-gray-500 text-white"
                        title={`${tech.technique_id}: ${tech.technique_name} (${tech.count})`}
                      >
                        {tech.technique_id} ({tech.count})
                      </span>
                    ))}
                  </div>
                </div>
              )}
            </div>
          ) : (
            <p className="text-sm text-gray-500 text-center py-8">No MITRE techniques tracked yet. Submit samples to build your heatmap.</p>
          )}
        </div>
      </div>
    </div>
  )
}

function StatCard({ icon: Icon, label, value, sub, color, bg }) {
  return (
    <div className="card flex items-start gap-3">
      <div className={`p-2.5 rounded-lg ${bg}`}>
        <Icon className={`h-5 w-5 ${color}`} />
      </div>
      <div>
        <p className="text-2xl font-bold text-gray-900 dark:text-white">{value}</p>
        <p className="text-xs font-medium text-gray-500 dark:text-gray-400">{label}</p>
        {sub && <p className="text-xs text-gray-400 dark:text-gray-500">{sub}</p>}
      </div>
    </div>
  )
}

export default DashboardPage
