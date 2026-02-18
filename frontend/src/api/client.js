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

export default client
