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
  ExternalLink,
  Search,
  FileText,
  Target,
  ChevronDown,
  ChevronRight,
} from 'lucide-react'
import { format } from 'date-fns'
import { useState } from 'react'
import { analysisApi, reportsApi, submissionsApi } from '../api/client'
import SeverityBadge from '../components/SeverityBadge'

const riskColors = {
  critical: 'text-red-600 bg-red-100',
  high: 'text-orange-600 bg-orange-100',
  medium: 'text-yellow-600 bg-yellow-100',
  low: 'text-green-600 bg-green-100',
  informational: 'text-blue-600 bg-blue-100',
  minimal: 'text-gray-600 bg-gray-100',
}

const severityColors = {
  critical: 'bg-red-600 text-white',
  high: 'bg-orange-500 text-white',
  medium: 'bg-yellow-500 text-white',
  low: 'bg-green-500 text-white',
  informational: 'bg-blue-500 text-white',
}

const confidenceColors = {
  high: 'text-green-700 bg-green-100',
  medium: 'text-yellow-700 bg-yellow-100',
  low: 'text-red-700 bg-red-100',
}

const tlpColors = {
  'TLP:WHITE': 'bg-gray-100 text-gray-800 border-gray-300',
  'TLP:GREEN': 'bg-green-100 text-green-800 border-green-400',
  'TLP:AMBER': 'bg-amber-100 text-amber-800 border-amber-400',
  'TLP:RED': 'bg-red-100 text-red-800 border-red-400',
}

const priorityColors = {
  P1: 'bg-red-100 text-red-700 border-red-300',
  P2: 'bg-orange-100 text-orange-700 border-orange-300',
  P3: 'bg-yellow-100 text-yellow-700 border-yellow-300',
  P4: 'bg-gray-100 text-gray-700 border-gray-300',
}

function ReportDetailPage() {
  const { id } = useParams()
  const [expandedPriorities, setExpandedPriorities] = useState({ P1: true, P2: true, P3: false, P4: false })

  const { data: submission, isLoading: loadingSubmission } = useQuery({
    queryKey: ['submission', id],
    queryFn: () => submissionsApi.get(id),
  })

  const { data: analysis, isLoading: loadingAnalysis } = useQuery({
    queryKey: ['analysis', id],
    queryFn: () => analysisApi.getResults(id),
    enabled: !!submission,
  })

  const { data: mitreValidation } = useQuery({
    queryKey: ['mitre-validation', id],
    queryFn: () => analysisApi.getMitreValidation(id),
    enabled: !!analysis,
  })

  const { data: investigationPlan } = useQuery({
    queryKey: ['investigation-plan', id],
    queryFn: () => analysisApi.getInvestigationPlan(id),
    enabled: !!analysis,
  })

  const { data: threatHunt } = useQuery({
    queryKey: ['threat-hunt', id],
    queryFn: () => analysisApi.getThreatHunt(id),
    enabled: !!analysis,
  })

  const isLoading = loadingSubmission || loadingAnalysis

  const togglePriority = (priority) => {
    setExpandedPriorities(prev => ({ ...prev, [priority]: !prev[priority] }))
  }

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
  const nvdEnrichment = analysis?.analysis_results?.find(r => r.analyzer === 'nvd_enrichment')

  const riskLevel = scriptAnalysis?.results_json?.risk_level ||
                   sandboxAnalysis?.results_json?.verdict ||
                   'unknown'

  const severity = analysis?.severity || submission?.severity
  const tlpMarking = analysis?.tlp_marking || submission?.tlp_marking || 'TLP:AMBER'
  const confidenceScore = analysis?.confidence_score || submission?.confidence_score

  // MITRE validation data
  const mitreData = mitreValidation?.mitre_validation || mitreValidation
  const validatedTechniques = mitreData?.validated || []
  const suppositionTechniques = mitreData?.supposition || []
  const mitreStats = mitreData?.stats || {}

  // Threat hunt data
  const huntFindings = threatHunt?.threat_hunt?.findings || threatHunt?.findings || []
  const huntSummary = threatHunt?.threat_hunt?.hunt_summary || threatHunt?.hunt_summary

  // Investigation plan data
  const planData = investigationPlan?.investigation_plan || investigationPlan?.plan_json || {}
  const investigationSteps = planData?.investigation_steps || []
  const containmentActions = planData?.containment_actions || []
  const eradicationProcedures = planData?.eradication_procedures || []
  const recoverySteps = planData?.recovery_steps || []

  // CVE data
  const cveData = nvdEnrichment?.results_json?.cve_data || []

  // Group investigation steps by priority
  const stepsByPriority = investigationSteps.reduce((acc, step) => {
    const p = step.priority || 'P3'
    if (!acc[p]) acc[p] = []
    acc[p].push(step)
    return acc
  }, {})

  return (
    <div>
      {/* Header */}
      <div className="flex items-center justify-between mb-6">
        <div className="flex items-center">
          <Link to="/reports" className="mr-4 text-gray-400 hover:text-gray-600" aria-label="Back to reports">
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

      {/* TLP & Severity Banner */}
      {(severity || tlpMarking) && (
        <div className="flex items-center gap-3 mb-6">
          {severity && (
            <SeverityBadge severity={severity} />
          )}
          {tlpMarking && (
            <span className={`px-3 py-1 rounded-md text-sm font-semibold border ${tlpColors[tlpMarking] || 'bg-gray-100 text-gray-800 border-gray-300'}`}>
              {tlpMarking}
            </span>
          )}
          {confidenceScore != null && (
            <span className={`px-3 py-1 rounded-md text-sm font-medium ${
              confidenceScore >= 0.7 ? 'bg-green-100 text-green-700' :
              confidenceScore >= 0.4 ? 'bg-yellow-100 text-yellow-700' :
              'bg-red-100 text-red-700'
            }`}>
              Confidence: {Math.round(confidenceScore * 100)}%
            </span>
          )}
        </div>
      )}

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

        {/* MITRE ATT&CK - Enhanced with validation badges */}
        {(validatedTechniques.length > 0 || suppositionTechniques.length > 0 ||
          scriptAnalysis?.results_json?.mitre_techniques?.length > 0) && (
          <div className="card">
            <h3 className="text-lg font-semibold text-gray-900 mb-4 flex items-center">
              <Target className="h-5 w-5 mr-2 text-purple-500" />
              MITRE ATT&CK Techniques
              {mitreStats.validation_rate != null && (
                <span className="ml-2 text-xs font-normal text-gray-500">
                  ({mitreStats.validation_rate}% validated)
                </span>
              )}
            </h3>

            {/* Validated techniques */}
            {validatedTechniques.length > 0 && (
              <div className="mb-3">
                <p className="text-xs text-gray-500 mb-2 font-medium uppercase">Validated</p>
                <div className="flex flex-wrap gap-2">
                  {validatedTechniques.map((technique, idx) => (
                    <a
                      key={idx}
                      href={`https://attack.mitre.org/techniques/${technique.id?.replace('.', '/')}/`}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="inline-flex items-center px-3 py-1 rounded-full text-xs font-medium bg-green-100 text-green-700 hover:bg-green-200 border border-green-300"
                    >
                      <CheckCircle className="h-3 w-3 mr-1" />
                      {technique.id}: {technique.official_name || technique.name}
                    </a>
                  ))}
                </div>
              </div>
            )}

            {/* Supposition techniques */}
            {suppositionTechniques.length > 0 && (
              <div className="mb-3">
                <p className="text-xs text-gray-500 mb-2 font-medium uppercase">Unverified (LLM Supposition)</p>
                <div className="flex flex-wrap gap-2">
                  {suppositionTechniques.map((technique, idx) => (
                    <span
                      key={idx}
                      className="inline-flex items-center px-3 py-1 rounded-full text-xs font-medium bg-yellow-100 text-yellow-700 border border-yellow-300"
                    >
                      <AlertTriangle className="h-3 w-3 mr-1" />
                      {technique.id}: {technique.name}
                    </span>
                  ))}
                </div>
              </div>
            )}

            {/* Fallback: original MITRE techniques (when validation data not available) */}
            {validatedTechniques.length === 0 && suppositionTechniques.length === 0 &&
             scriptAnalysis?.results_json?.mitre_techniques?.length > 0 && (
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
            )}
          </div>
        )}

        {/* Threat Hunt Findings */}
        {huntFindings.length > 0 && (
          <div className="card lg:col-span-2">
            <h3 className="text-lg font-semibold text-gray-900 mb-4 flex items-center">
              <Search className="h-5 w-5 mr-2 text-primary-500" />
              Threat Hunt Findings ({huntFindings.length})
            </h3>
            {huntSummary && (
              <p className="text-sm text-gray-600 mb-4">{huntSummary}</p>
            )}
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b">
                    <th className="text-left py-2 px-3 text-gray-500 font-medium">ID</th>
                    <th className="text-left py-2 px-3 text-gray-500 font-medium">Finding</th>
                    <th className="text-left py-2 px-3 text-gray-500 font-medium">Severity</th>
                    <th className="text-left py-2 px-3 text-gray-500 font-medium">Confidence</th>
                    <th className="text-left py-2 px-3 text-gray-500 font-medium">Evidence</th>
                    <th className="text-left py-2 px-3 text-gray-500 font-medium">Action</th>
                  </tr>
                </thead>
                <tbody>
                  {huntFindings.map((finding, idx) => (
                    <tr key={idx} className="border-b border-gray-100">
                      <td className="py-2 px-3 font-mono text-xs">{finding.id}</td>
                      <td className="py-2 px-3">
                        <p className="font-medium">{finding.title}</p>
                        {finding.description && (
                          <p className="text-xs text-gray-500 mt-1 line-clamp-2">{finding.description}</p>
                        )}
                      </td>
                      <td className="py-2 px-3">
                        <SeverityBadge severity={finding.severity} size="sm" />
                      </td>
                      <td className="py-2 px-3">
                        <span className={`px-2 py-0.5 rounded text-xs font-medium ${
                          confidenceColors[finding.confidence?.toLowerCase()] || 'bg-gray-100 text-gray-600'
                        }`}>
                          {finding.confidence}
                        </span>
                        {finding.confidence_reasoning && (
                          <p className="text-xs text-gray-400 mt-1">{finding.confidence_reasoning}</p>
                        )}
                      </td>
                      <td className="py-2 px-3">
                        {finding.evidence?.slice(0, 3).map((e, eidx) => (
                          <p key={eidx} className="text-xs font-mono text-gray-600">
                            [{e.type}] {e.value?.substring(0, 40)}{e.value?.length > 40 ? '...' : ''}
                          </p>
                        ))}
                        {finding.evidence?.length > 3 && (
                          <p className="text-xs text-gray-400">+{finding.evidence.length - 3} more</p>
                        )}
                      </td>
                      <td className="py-2 px-3">
                        <span className={`px-2 py-0.5 rounded text-xs font-medium capitalize ${
                          finding.recommendation === 'contain' ? 'bg-red-100 text-red-700' :
                          finding.recommendation === 'investigate' ? 'bg-orange-100 text-orange-700' :
                          finding.recommendation === 'monitor' ? 'bg-blue-100 text-blue-700' :
                          'bg-gray-100 text-gray-600'
                        }`}>
                          {finding.recommendation}
                        </span>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
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

        {/* Investigation Plan */}
        {investigationSteps.length > 0 && (
          <div className="card lg:col-span-2">
            <h3 className="text-lg font-semibold text-gray-900 mb-4 flex items-center">
              <FileText className="h-5 w-5 mr-2 text-primary-500" />
              Investigation & Response Plan
            </h3>

            {/* Investigation steps grouped by priority */}
            {['P1', 'P2', 'P3', 'P4'].map(priority => {
              const steps = stepsByPriority[priority]
              if (!steps || steps.length === 0) return null
              const isExpanded = expandedPriorities[priority]

              return (
                <div key={priority} className="mb-4">
                  <button
                    onClick={() => togglePriority(priority)}
                    className={`flex items-center w-full px-3 py-2 rounded-lg border text-sm font-semibold ${priorityColors[priority]}`}
                  >
                    {isExpanded ? <ChevronDown className="h-4 w-4 mr-2" /> : <ChevronRight className="h-4 w-4 mr-2" />}
                    {priority} — {priority === 'P1' ? 'Immediate' : priority === 'P2' ? 'Urgent (24h)' : priority === 'P3' ? 'Standard (72h)' : 'Low Priority'}
                    <span className="ml-2 text-xs font-normal">({steps.length} steps)</span>
                  </button>
                  {isExpanded && (
                    <div className="mt-2 ml-4 space-y-2">
                      {steps.map((step, idx) => (
                        <div key={idx} className="border-l-2 border-gray-200 pl-3 py-1">
                          <p className="text-sm font-medium">{step.action}</p>
                          {step.rationale && (
                            <p className="text-xs text-gray-500 mt-0.5">{step.rationale}</p>
                          )}
                          {step.tools?.length > 0 && (
                            <div className="flex gap-1 mt-1">
                              {step.tools.map((tool, tidx) => (
                                <span key={tidx} className="text-xs bg-gray-100 text-gray-600 px-1.5 py-0.5 rounded">{tool}</span>
                              ))}
                            </div>
                          )}
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              )
            })}

            {/* Containment actions */}
            {containmentActions.length > 0 && (
              <div className="mt-4">
                <h4 className="text-sm font-semibold text-gray-700 mb-2">Containment Actions</h4>
                <div className="space-y-2">
                  {containmentActions.map((action, idx) => (
                    <div key={idx} className="flex items-start gap-2 text-sm">
                      <span className={`px-1.5 py-0.5 rounded text-xs font-medium shrink-0 ${priorityColors[action.priority] || 'bg-gray-100 text-gray-600'}`}>
                        {action.priority}
                      </span>
                      <span>{action.action}</span>
                      {action.scope && (
                        <span className="text-xs bg-blue-50 text-blue-600 px-1.5 py-0.5 rounded shrink-0">{action.scope}</span>
                      )}
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Eradication & recovery */}
            {(eradicationProcedures.length > 0 || recoverySteps.length > 0) && (
              <div className="mt-4">
                <h4 className="text-sm font-semibold text-gray-700 mb-2">Eradication & Recovery</h4>
                <div className="space-y-1">
                  {eradicationProcedures.map((step, idx) => (
                    <p key={`e-${idx}`} className="text-sm text-gray-600">
                      <span className="font-medium">E{idx + 1}.</span> {step.action}
                    </p>
                  ))}
                  {recoverySteps.map((step, idx) => (
                    <p key={`r-${idx}`} className="text-sm text-gray-600">
                      <span className="font-medium">R{idx + 1}.</span> {step.action}
                    </p>
                  ))}
                </div>
              </div>
            )}

            {planData?.analyst_notes && (
              <div className="mt-4 p-3 bg-blue-50 rounded-lg">
                <p className="text-xs font-medium text-blue-700 mb-1">Analyst Notes</p>
                <p className="text-sm text-blue-800">{planData.analyst_notes}</p>
              </div>
            )}
          </div>
        )}

        {/* CVE Intelligence */}
        {cveData.length > 0 && (
          <div className="card lg:col-span-2">
            <h3 className="text-lg font-semibold text-gray-900 mb-4 flex items-center">
              <AlertCircle className="h-5 w-5 mr-2 text-red-500" />
              CVE Intelligence ({cveData.length})
            </h3>
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b">
                    <th className="text-left py-2 px-3 text-gray-500 font-medium">CVE ID</th>
                    <th className="text-left py-2 px-3 text-gray-500 font-medium">CVSS</th>
                    <th className="text-left py-2 px-3 text-gray-500 font-medium">Description</th>
                    <th className="text-left py-2 px-3 text-gray-500 font-medium">Published</th>
                  </tr>
                </thead>
                <tbody>
                  {cveData.slice(0, 15).map((cve, idx) => (
                    <tr key={idx} className="border-b border-gray-100">
                      <td className="py-2 px-3">
                        <a
                          href={`https://nvd.nist.gov/vuln/detail/${cve.cve_id}`}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="font-mono text-xs text-primary-600 hover:underline"
                        >
                          {cve.cve_id}
                        </a>
                      </td>
                      <td className="py-2 px-3">
                        {cve.cvss_v3_score != null && (
                          <span className={`px-2 py-0.5 rounded text-xs font-semibold ${
                            cve.cvss_v3_score >= 9.0 ? 'bg-red-600 text-white' :
                            cve.cvss_v3_score >= 7.0 ? 'bg-orange-500 text-white' :
                            cve.cvss_v3_score >= 4.0 ? 'bg-yellow-500 text-white' :
                            'bg-green-500 text-white'
                          }`}>
                            {cve.cvss_v3_score}
                          </span>
                        )}
                      </td>
                      <td className="py-2 px-3 text-gray-600 text-xs max-w-md">
                        <p className="line-clamp-2">{cve.description}</p>
                      </td>
                      <td className="py-2 px-3 text-gray-500 text-xs whitespace-nowrap">
                        {cve.published ? format(new Date(cve.published), 'MMM d, yyyy') : '-'}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
              {cveData.length > 15 && (
                <p className="text-sm text-gray-500 mt-2 text-center">
                  Showing 15 of {cveData.length} CVEs. Download report for full list.
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
