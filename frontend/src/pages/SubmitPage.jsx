import { useState, useCallback } from 'react'
import { useNavigate } from 'react-router-dom'
import { useMutation } from '@tanstack/react-query'
import {
  Upload,
  Link,
  FileText,
  CheckCircle,
  AlertCircle,
  Loader2
} from 'lucide-react'
import { submissionsApi } from '../api/client'

function SubmitPage() {
  const navigate = useNavigate()
  const [activeTab, setActiveTab] = useState('file')
  const [dragActive, setDragActive] = useState(false)
  const [selectedFile, setSelectedFile] = useState(null)
  const [url, setUrl] = useState('')
  const [sandboxSource, setSandboxSource] = useState('anyrun')
  const [sandboxJson, setSandboxJson] = useState('')

  // File submission mutation
  const fileSubmitMutation = useMutation({
    mutationFn: (file) => submissionsApi.submitFile(file),
    onSuccess: (data) => {
      navigate(`/queue?highlight=${data.id}`)
    },
  })

  // URL submission mutation
  const urlSubmitMutation = useMutation({
    mutationFn: (url) => submissionsApi.submitUrl(url),
    onSuccess: (data) => {
      navigate(`/queue?highlight=${data.id}`)
    },
  })

  // Sandbox report submission mutation
  const sandboxSubmitMutation = useMutation({
    mutationFn: ({ source, data }) => submissionsApi.submitSandboxReport(source, data),
    onSuccess: (data) => {
      navigate(`/queue?highlight=${data.id}`)
    },
  })

  const handleDrag = useCallback((e) => {
    e.preventDefault()
    e.stopPropagation()
    if (e.type === 'dragenter' || e.type === 'dragover') {
      setDragActive(true)
    } else if (e.type === 'dragleave') {
      setDragActive(false)
    }
  }, [])

  const handleDrop = useCallback((e) => {
    e.preventDefault()
    e.stopPropagation()
    setDragActive(false)

    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      setSelectedFile(e.dataTransfer.files[0])
    }
  }, [])

  const handleFileSelect = (e) => {
    if (e.target.files && e.target.files[0]) {
      setSelectedFile(e.target.files[0])
    }
  }

  const handleFileSubmit = () => {
    if (selectedFile) {
      fileSubmitMutation.mutate(selectedFile)
    }
  }

  const handleUrlSubmit = (e) => {
    e.preventDefault()
    if (url.trim()) {
      urlSubmitMutation.mutate(url.trim())
    }
  }

  const handleSandboxSubmit = (e) => {
    e.preventDefault()
    try {
      const parsedJson = JSON.parse(sandboxJson)
      sandboxSubmitMutation.mutate({ source: sandboxSource, data: parsedJson })
    } catch (err) {
      alert('Invalid JSON format')
    }
  }

  const isLoading = fileSubmitMutation.isPending || urlSubmitMutation.isPending || sandboxSubmitMutation.isPending
  const error = fileSubmitMutation.error || urlSubmitMutation.error || sandboxSubmitMutation.error

  return (
    <div className="max-w-3xl mx-auto">
      <h1 className="text-2xl font-bold text-gray-900 mb-6">Submit for Analysis</h1>

      {/* Tab Navigation */}
      <div className="flex space-x-1 mb-6 bg-gray-100 p-1 rounded-lg">
        <button
          onClick={() => setActiveTab('file')}
          className={`flex-1 flex items-center justify-center py-2 px-4 rounded-md text-sm font-medium transition-colors ${
            activeTab === 'file'
              ? 'bg-white text-primary-700 shadow-sm'
              : 'text-gray-600 hover:text-gray-900'
          }`}
        >
          <Upload className="h-4 w-4 mr-2" />
          File Upload
        </button>
        <button
          onClick={() => setActiveTab('url')}
          className={`flex-1 flex items-center justify-center py-2 px-4 rounded-md text-sm font-medium transition-colors ${
            activeTab === 'url'
              ? 'bg-white text-primary-700 shadow-sm'
              : 'text-gray-600 hover:text-gray-900'
          }`}
        >
          <Link className="h-4 w-4 mr-2" />
          URL
        </button>
        <button
          onClick={() => setActiveTab('sandbox')}
          className={`flex-1 flex items-center justify-center py-2 px-4 rounded-md text-sm font-medium transition-colors ${
            activeTab === 'sandbox'
              ? 'bg-white text-primary-700 shadow-sm'
              : 'text-gray-600 hover:text-gray-900'
          }`}
        >
          <FileText className="h-4 w-4 mr-2" />
          Sandbox Report
        </button>
      </div>

      {/* Error Display */}
      {error && (
        <div className="mb-6 p-4 bg-danger-50 border border-danger-200 rounded-lg flex items-center">
          <AlertCircle className="h-5 w-5 text-danger-600 mr-3" />
          <span className="text-danger-700">{error.message || 'An error occurred'}</span>
        </div>
      )}

      {/* File Upload Tab */}
      {activeTab === 'file' && (
        <div className="card">
          <div
            className={`border-2 border-dashed rounded-lg p-8 text-center transition-colors ${
              dragActive
                ? 'border-primary-500 bg-primary-50'
                : 'border-gray-300 hover:border-gray-400'
            }`}
            onDragEnter={handleDrag}
            onDragLeave={handleDrag}
            onDragOver={handleDrag}
            onDrop={handleDrop}
          >
            <input
              type="file"
              id="file-upload"
              className="hidden"
              onChange={handleFileSelect}
            />
            <label htmlFor="file-upload" className="cursor-pointer">
              <Upload className="h-12 w-12 text-gray-400 mx-auto mb-4" />
              <p className="text-lg font-medium text-gray-700 mb-2">
                Drop your file here or click to browse
              </p>
              <p className="text-sm text-gray-500">
                Supports scripts (PS1, JS, VBS, BAT, PY), documents, executables
              </p>
            </label>
          </div>

          {selectedFile && (
            <div className="mt-4 p-4 bg-gray-50 rounded-lg flex items-center justify-between">
              <div className="flex items-center">
                <CheckCircle className="h-5 w-5 text-success-500 mr-3" />
                <div>
                  <p className="font-medium text-gray-900">{selectedFile.name}</p>
                  <p className="text-sm text-gray-500">
                    {(selectedFile.size / 1024).toFixed(2)} KB
                  </p>
                </div>
              </div>
              <button
                onClick={() => setSelectedFile(null)}
                className="text-gray-400 hover:text-gray-600"
              >
                Remove
              </button>
            </div>
          )}

          <button
            onClick={handleFileSubmit}
            disabled={!selectedFile || isLoading}
            className="btn btn-primary w-full mt-6 flex items-center justify-center"
          >
            {isLoading ? (
              <Loader2 className="h-5 w-5 animate-spin mr-2" />
            ) : (
              <Upload className="h-5 w-5 mr-2" />
            )}
            {isLoading ? 'Submitting...' : 'Submit for Analysis'}
          </button>
        </div>
      )}

      {/* URL Tab */}
      {activeTab === 'url' && (
        <div className="card">
          <form onSubmit={handleUrlSubmit}>
            <label className="block text-sm font-medium text-gray-700 mb-2">
              URL to Analyze
            </label>
            <input
              type="url"
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              placeholder="https://example.com/suspicious-file.ps1"
              className="input mb-4"
              required
            />
            <p className="text-sm text-gray-500 mb-6">
              The URL will be expanded if shortened, categorized, and any scripts will be automatically fetched and analyzed.
            </p>
            <button
              type="submit"
              disabled={!url.trim() || isLoading}
              className="btn btn-primary w-full flex items-center justify-center"
            >
              {isLoading ? (
                <Loader2 className="h-5 w-5 animate-spin mr-2" />
              ) : (
                <Link className="h-5 w-5 mr-2" />
              )}
              {isLoading ? 'Submitting...' : 'Analyze URL'}
            </button>
          </form>
        </div>
      )}

      {/* Sandbox Report Tab */}
      {activeTab === 'sandbox' && (
        <div className="card">
          <form onSubmit={handleSandboxSubmit}>
            <label className="block text-sm font-medium text-gray-700 mb-2">
              Report Source
            </label>
            <select
              value={sandboxSource}
              onChange={(e) => setSandboxSource(e.target.value)}
              className="input mb-4"
            >
              <option value="anyrun">Any.Run</option>
              <option value="joesandbox">Joe Sandbox</option>
              <option value="generic">Generic JSON</option>
            </select>

            <label className="block text-sm font-medium text-gray-700 mb-2">
              Report JSON
            </label>
            <textarea
              value={sandboxJson}
              onChange={(e) => setSandboxJson(e.target.value)}
              placeholder="Paste the sandbox report JSON here..."
              className="input font-mono text-sm h-64 mb-4"
              required
            />

            <button
              type="submit"
              disabled={!sandboxJson.trim() || isLoading}
              className="btn btn-primary w-full flex items-center justify-center"
            >
              {isLoading ? (
                <Loader2 className="h-5 w-5 animate-spin mr-2" />
              ) : (
                <FileText className="h-5 w-5 mr-2" />
              )}
              {isLoading ? 'Submitting...' : 'Upload Report'}
            </button>
          </form>
        </div>
      )}
    </div>
  )
}

export default SubmitPage
