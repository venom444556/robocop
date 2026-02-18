import axios from 'axios'

const API_BASE_URL = import.meta.env.VITE_API_URL || '/api'

const client = axios.create({
  baseURL: API_BASE_URL,
  headers: {
    'Content-Type': 'application/json',
  },
})

// Request interceptor for API key
client.interceptors.request.use((config) => {
  const apiKey = localStorage.getItem('api_key')
  if (apiKey) {
    config.headers['X-API-Key'] = apiKey
  }
  return config
})

// Response interceptor for error handling
client.interceptors.response.use(
  (response) => response,
  (error) => {
    if (error.response?.status === 401) {
      // Handle unauthorized
      console.error('Unauthorized request')
    }
    return Promise.reject(error)
  }
)

// Submissions API
export const submissionsApi = {
  submitFile: async (file) => {
    const formData = new FormData()
    formData.append('file', file)
    const response = await client.post('/submissions/file', formData, {
      headers: { 'Content-Type': 'multipart/form-data' },
    })
    return response.data
  },

  submitUrl: async (url) => {
    const response = await client.post('/submissions/url', { url })
    return response.data
  },

  submitSandboxReport: async (reportSource, reportData) => {
    const response = await client.post('/submissions/sandbox-report', {
      report_source: reportSource,
      report_data: reportData,
    })
    return response.data
  },

  list: async (params = {}) => {
    const response = await client.get('/submissions/', { params })
    return response.data
  },

  get: async (id) => {
    const response = await client.get(`/submissions/${id}`)
    return response.data
  },
}

// Analysis API
export const analysisApi = {
  getResults: async (submissionId) => {
    const response = await client.get(`/analysis/${submissionId}/results`)
    return response.data
  },

  getStatus: async (submissionId) => {
    const response = await client.get(`/analysis/${submissionId}/status`)
    return response.data
  },

  trigger: async (submissionId) => {
    const response = await client.post(`/analysis/${submissionId}/trigger`)
    return response.data
  },

  getMitreValidation: async (submissionId) => {
    const response = await client.get(`/analysis/${submissionId}/mitre-validation`)
    return response.data
  },

  getInvestigationPlan: async (submissionId) => {
    const response = await client.get(`/analysis/${submissionId}/investigation-plan`)
    return response.data
  },

  getThreatHunt: async (submissionId) => {
    const response = await client.get(`/analysis/${submissionId}/threat-hunt`)
    return response.data
  },
}

// Reports API
export const reportsApi = {
  generate: async (submissionId, format = 'json') => {
    const response = await client.post(`/reports/${submissionId}/generate`, { format })
    return response.data
  },

  list: async (submissionId) => {
    const response = await client.get(`/reports/${submissionId}`)
    return response.data
  },

  get: async (submissionId, format) => {
    const response = await client.get(`/reports/${submissionId}/${format}`)
    return response.data
  },

  listAll: async (params = {}) => {
    const response = await client.get('/reports/', { params })
    return response.data
  },
}

// Management API
export const managementApi = {
  deleteSubmission: async (submissionId) => {
    const response = await client.delete(`/management/submissions/${submissionId}`)
    return response.data
  },

  reanalyze: async (submissionId) => {
    const response = await client.post(`/management/submissions/${submissionId}/reanalyze`)
    return response.data
  },

  healthDetailed: async () => {
    const response = await client.get('/management/health/detailed')
    return response.data
  },

  cleanup: async (olderThanDays = 90) => {
    const response = await client.post('/management/cleanup', { older_than_days: olderThanDays })
    return response.data
  },
}

// Dashboard API
export const dashboardApi = {
  getStats: async () => {
    const response = await client.get('/dashboard/stats')
    return response.data
  },
}

// Search API
export const searchApi = {
  searchIOCs: async (params) => {
    const response = await client.get('/search/iocs', { params })
    return response.data
  },

  correlateIOC: async (iocValue) => {
    const response = await client.get(`/search/iocs/${encodeURIComponent(iocValue)}/correlate`)
    return response.data
  },

  compareSubmissions: async (id1, id2) => {
    const response = await client.get('/search/submissions/compare', { params: { id1, id2 } })
    return response.data
  },

  globalSearch: async (query) => {
    const response = await client.get('/search/global-search', { params: { q: query } })
    return response.data
  },
}

// YARA Rules API
export const yaraRulesApi = {
  list: async (params = {}) => {
    const response = await client.get('/yara-rules/', { params })
    return response.data
  },

  get: async (ruleId) => {
    const response = await client.get(`/yara-rules/${ruleId}`)
    return response.data
  },

  create: async (data) => {
    const response = await client.post('/yara-rules/', data)
    return response.data
  },

  update: async (ruleId, data) => {
    const response = await client.put(`/yara-rules/${ruleId}`, data)
    return response.data
  },

  delete: async (ruleId) => {
    const response = await client.delete(`/yara-rules/${ruleId}`)
    return response.data
  },

  import: async (content) => {
    const response = await client.post('/yara-rules/import', { content })
    return response.data
  },

  export: async () => {
    const response = await client.get('/yara-rules/export', { responseType: 'blob' })
    return response.data
  },
}

// WebSocket helper
export const createAnalysisFeedSocket = () => {
  const wsProtocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:'
  const wsHost = import.meta.env.VITE_WS_URL || `${wsProtocol}//${window.location.host}`
  return new WebSocket(`${wsHost}/ws/analysis-feed`)
}

export default client
