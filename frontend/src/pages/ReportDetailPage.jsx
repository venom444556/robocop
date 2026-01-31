import { useParams, Link } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import {
  ArrowLeft,
  Download,
  AlertTriangle,
  Shield,
  Globe,
  Hash,
  Loader2,
  AlertCircle,
  CheckCircle,
  ExternalLink
} from 'lucide-react'
import { format } from 'date-fns'
import { analysisApi, reportsApi, submissionsApi } from '../api/client'

const riskColors = {
  critical: 'text-red-600 bg-red-100',
  high: 'text-orange-600 bg-orange-100',
  medium: 'text-yellow-600 bg-yellow-100',
  low: 'text-green-600 bg-green-100',
  minimal: 'text-gray-600 bg-gray-100',
}

function ReportDetailPage() {
  const { id } = useParams()

  const { data: submission, isLoading: loadingSubmission } = useQuery({
    queryKey: ['submission', id],
    queryFn: () => submissionsApi.get(id),
  })

  const { data: analysis, isLoading: loadingAnalysis } = useQuery({
    queryKey: ['analysis', id],
    queryFn: () => analysisApi.getResults(id),
    enabled: !!submission,
  })

  const isLoading = loadingSubmission || loadingAnalysis

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-64">
        <Loader2 className="h-8 w-8 animate-spin text-primary-500" />
      </div>
    )
  }

  if (!submission) {
    return (
      <div className="card text-center">
        <AlertCircle className="h-12 w-12 text-danger-500 mx-auto mb-4" />
        <h3 className="text-lg font-medium text-gray-900 mb-2">Report not found</h3>
        <Link to="/reports" className="btn btn-primary">
          Back to Reports
        </Link>
      </div>
    )
  }

  // Extract analysis data
  const scriptAnalysis = analysis?.analysis_results?.find(r => r.analyzer === 'script_analyzer')
  const urlAnalysis = analysis?.analysis_results?.find(r => r.analyzer === 'url_analyzer')
  const sandboxAnalysis = analysis?.analysis_results?.find(r => r.analyzer === 'sandbox_parser')
  const decodingResult = analysis?.analysis_results?.find(r => r.analyzer === 'script_decoder')

  const riskLevel = scriptAnalysis?.results_json?.risk_level ||
                   sandboxAnalysis?.results_json?.verdict ||
                   'unknown'

  return (
    <div>
      {/* Header */}
      <div className="flex items-center justify-between mb-6">
        <div className="flex items-center">
          <Link to="/reports" className="mr-4 text-gray-400 hover:text-gray-600">
            <ArrowLeft className="h-5 w-5" />
          </Link>
          <div>
            <h1 className="text-2xl font-bold text-gray-900">
              Analysis Report #{id}
            </h1>
            <p className="text-gray-500">
              {format(new Date(submission.created_at), 'MMMM d, yyyy HH:mm')}
            </p>
          </div>
        </div>
        <div className="flex space-x-2">
          <button
            onClick={() => window.open(`/api/reports/${id}/html`, '_blank')}
            className="btn btn-secondary flex items-center"
          >
            <ExternalLink className="h-4 w-4 mr-2" />
            HTML
          </button>
          <button
            onClick={() => window.open(`/api/reports/${id}/json`, '_blank')}
            className="btn btn-primary flex items-center"
          >
            <Download className="h-4 w-4 mr-2" />
            JSON
          </button>
        </div>
      </div>

      {/* Summary Card */}
      <div className="card mb-6">
        <div className="flex items-start justify-between">
          <div>
            <h2 className="text-lg font-semibold text-gray-900 mb-2">Summary</h2>
            <div className="space-y-2">
              <p className="text-sm">
                <span className="text-gray-500">Type:</span>{' '}
                <span className="font-medium capitalize">{submission.type.replace('_', ' ')}</span>
              </p>
              {submission.filename && (
                <p className="text-sm">
                  <span className="text-gray-500">Filename:</span>{' '}
                  <span className="font-medium font-mono">{submission.filename}</span>
                </p>
              )}
              {submission.original_url && (
                <p className="text-sm">
                  <span className="text-gray-500">URL:</span>{' '}
                  <span className="font-medium font-mono text-xs">{submission.original_url}</span>
                </p>
              )}
              {submission.file_hash_sha256 && (
                <p className="text-sm">
                  <span className="text-gray-500">SHA256:</span>{' '}
                  <span className="font-mono text-xs">{submission.file_hash_sha256}</span>
                </p>
              )}
            </div>
          </div>
          <div className={`px-4 py-2 rounded-lg ${riskColors[riskLevel] || riskColors.minimal}`}>
            <div className="flex items-center">
              <AlertTriangle className="h-5 w-5 mr-2" />
              <span className="font-semibold capitalize">{riskLevel} Risk</span>
            </div>
          </div>
        </div>
      </div>

      {/* Analysis Results */}
      <div className="grid gap-6 lg:grid-cols-2">
        {/* Script Analysis */}
        {scriptAnalysis && (
          <div className="card">
            <h3 className="text-lg font-semibold text-gray-900 mb-4 flex items-center">
              <Shield className="h-5 w-5 mr-2 text-primary-500" />
              Script Analysis
            </h3>
            <div className="space-y-4">
              <div>
                <p className="text-sm text-gray-500">Script Type</p>
                <p className="font-medium capitalize">{scriptAnalysis.results_json.script_type}</p>
              </div>
              <div>
                <p className="text-sm text-gray-500">Risk Score</p>
                <div className="flex items-center">
                  <div className="flex-1 bg-gray-200 rounded-full h-2 mr-3">
                    <div
                      className={`h-2 rounded-full ${
                        scriptAnalysis.results_json.risk_score >= 80 ? 'bg-red-500' :
                        scriptAnalysis.results_json.risk_score >= 60 ? 'bg-orange-500' :
                        scriptAnalysis.results_json.risk_score >= 40 ? 'bg-yellow-500' :
                        'bg-green-500'
                      }`}
                      style={{ width: `${scriptAnalysis.results_json.risk_score}%` }}
                    />
                  </div>
                  <span className="font-medium">{scriptAnalysis.results_json.risk_score}/100</span>
                </div>
              </div>
              {scriptAnalysis.results_json.summary && (
                <div>
                  <p className="text-sm text-gray-500">Summary</p>
                  <p className="text-sm">{scriptAnalysis.results_json.summary}</p>
                </div>
              )}
            </div>
          </div>
        )}

        {/* MITRE ATT&CK */}
        {scriptAnalysis?.results_json?.mitre_techniques?.length > 0 && (
          <div className="card">
            <h3 className="text-lg font-semibold text-gray-900 mb-4">
              MITRE ATT&CK Techniques
            </h3>
            <div className="flex flex-wrap gap-2">
              {scriptAnalysis.results_json.mitre_techniques.map((technique, idx) => (
                <a
                  key={idx}
                  href={`https://attack.mitre.org/techniques/${technique.id}/`}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="inline-flex items-center px-3 py-1 rounded-full text-xs font-medium bg-purple-100 text-purple-700 hover:bg-purple-200"
                >
                  {technique.id}: {technique.name}
                </a>
              ))}
            </div>
          </div>
        )}

        {/* IOCs */}
        {analysis?.iocs?.length > 0 && (
          <div className="card lg:col-span-2">
            <h3 className="text-lg font-semibold text-gray-900 mb-4 flex items-center">
              <Hash className="h-5 w-5 mr-2 text-primary-500" />
              Indicators of Compromise ({analysis.iocs.length})
            </h3>
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b">
                    <th className="text-left py-2 px-3 text-gray-500 font-medium">Type</th>
                    <th className="text-left py-2 px-3 text-gray-500 font-medium">Value</th>
                    <th className="text-left py-2 px-3 text-gray-500 font-medium">Context</th>
                  </tr>
                </thead>
                <tbody>
                  {analysis.iocs.slice(0, 20).map((ioc, idx) => (
                    <tr key={idx} className="border-b border-gray-100">
                      <td className="py-2 px-3">
                        <span className="badge badge-info capitalize">{ioc.type}</span>
                      </td>
                      <td className="py-2 px-3 font-mono text-xs break-all">{ioc.value}</td>
                      <td className="py-2 px-3 text-gray-500">{ioc.context || '-'}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
              {analysis.iocs.length > 20 && (
                <p className="text-sm text-gray-500 mt-2 text-center">
                  Showing 20 of {analysis.iocs.length} IOCs. Download report for full list.
                </p>
              )}
            </div>
          </div>
        )}

        {/* URL Analysis */}
        {urlAnalysis && (
          <div className="card">
            <h3 className="text-lg font-semibold text-gray-900 mb-4 flex items-center">
              <Globe className="h-5 w-5 mr-2 text-primary-500" />
              URL Analysis
            </h3>
            <div className="space-y-3">
              <div>
                <p className="text-sm text-gray-500">Original URL</p>
                <p className="font-mono text-xs break-all">{urlAnalysis.results_json.original_url}</p>
              </div>
              {urlAnalysis.results_json.effective_url !== urlAnalysis.results_json.original_url && (
                <div>
                  <p className="text-sm text-gray-500">Effective URL</p>
                  <p className="font-mono text-xs break-all">{urlAnalysis.results_json.effective_url}</p>
                </div>
              )}
              {urlAnalysis.results_json.is_script && (
                <div className="flex items-center text-success-600">
                  <CheckCircle className="h-4 w-4 mr-2" />
                  Script content fetched and analyzed
                </div>
              )}
            </div>
          </div>
        )}

        {/* Decoding Results */}
        {decodingResult?.results_json?.decoded && (
          <div className="card">
            <h3 className="text-lg font-semibold text-gray-900 mb-4">
              Decoding Results
            </h3>
            <div className="space-y-3">
              <p className="text-sm">
                <span className="text-gray-500">Encoding Layers:</span>{' '}
                <span className="font-medium">{decodingResult.results_json.recursion_depth}</span>
              </p>
              <div>
                <p className="text-sm text-gray-500 mb-1">Techniques Found:</p>
                <div className="flex flex-wrap gap-1">
                  {decodingResult.results_json.techniques_found?.map((tech, idx) => (
                    <span key={idx} className="badge badge-warning">{tech}</span>
                  ))}
                </div>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  )
}

export default ReportDetailPage
