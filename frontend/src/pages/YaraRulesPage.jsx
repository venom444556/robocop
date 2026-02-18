import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import {
  BookOpen,
  Plus,
  Download,
  Upload,
  Search,
  Trash2,
  Edit3,
  ToggleLeft,
  ToggleRight,
  X,
  Code,
  Loader2,
  AlertCircle,
} from 'lucide-react'
import { format } from 'date-fns'
import client from '../api/client'

const CATEGORIES = ['Malware', 'Ransomware', 'Exploit', 'APT', 'Custom']

const categoryColors = {
  Malware: 'bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-400',
  Ransomware: 'bg-orange-100 text-orange-700 dark:bg-orange-900/30 dark:text-orange-400',
  Exploit: 'bg-yellow-100 text-yellow-700 dark:bg-yellow-900/30 dark:text-yellow-400',
  APT: 'bg-purple-100 text-purple-700 dark:bg-purple-900/30 dark:text-purple-400',
  Custom: 'bg-blue-100 text-blue-700 dark:bg-blue-900/30 dark:text-blue-400',
}

const emptyForm = {
  name: '',
  description: '',
  category: 'Malware',
  rule_content: '',
  author: '',
  source: '',
  tags: '',
  enabled: true,
}

function YaraRulesPage() {
  const queryClient = useQueryClient()

  // UI state
  const [searchTerm, setSearchTerm] = useState('')
  const [categoryFilter, setCategoryFilter] = useState('')
  const [showRuleModal, setShowRuleModal] = useState(false)
  const [showImportModal, setShowImportModal] = useState(false)
  const [editingRule, setEditingRule] = useState(null)
  const [formData, setFormData] = useState(emptyForm)
  const [importContent, setImportContent] = useState('')
  const [deleteConfirmId, setDeleteConfirmId] = useState(null)

  // Fetch rules
  const { data, isLoading, error, refetch } = useQuery({
    queryKey: ['yara-rules', searchTerm, categoryFilter],
    queryFn: async () => {
      const params = { limit: 100, offset: 0 }
      if (searchTerm) params.search = searchTerm
      if (categoryFilter) params.category = categoryFilter
      const response = await client.get('/yara-rules/', { params })
      return response.data
    },
  })

  const rules = data?.rules || []
  const totalCount = data?.total_count || 0

  // Create rule mutation
  const createMutation = useMutation({
    mutationFn: async (payload) => {
      const response = await client.post('/yara-rules/', payload)
      return response.data
    },
    onSuccess: () => {
      queryClient.invalidateQueries(['yara-rules'])
      closeRuleModal()
    },
  })

  // Update rule mutation
  const updateMutation = useMutation({
    mutationFn: async ({ id, payload }) => {
      const response = await client.put(`/yara-rules/${id}`, payload)
      return response.data
    },
    onSuccess: () => {
      queryClient.invalidateQueries(['yara-rules'])
      closeRuleModal()
    },
  })

  // Delete rule mutation
  const deleteMutation = useMutation({
    mutationFn: async (id) => {
      const response = await client.delete(`/yara-rules/${id}`)
      return response.data
    },
    onSuccess: () => {
      queryClient.invalidateQueries(['yara-rules'])
      setDeleteConfirmId(null)
    },
  })

  // Toggle enabled mutation
  const toggleMutation = useMutation({
    mutationFn: async ({ id, enabled }) => {
      const response = await client.put(`/yara-rules/${id}`, { enabled })
      return response.data
    },
    onSuccess: () => {
      queryClient.invalidateQueries(['yara-rules'])
    },
  })

  // Import mutation
  const importMutation = useMutation({
    mutationFn: async (content) => {
      const response = await client.post('/yara-rules/import', { content })
      return response.data
    },
    onSuccess: () => {
      queryClient.invalidateQueries(['yara-rules'])
      setImportContent('')
      setShowImportModal(false)
    },
  })

  // Export handler
  const handleExport = async () => {
    try {
      const response = await client.get('/yara-rules/export', {
        responseType: 'blob',
      })
      const blob = new Blob([response.data], { type: 'text/plain' })
      const url = window.URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = `yara-rules-export-${format(new Date(), 'yyyy-MM-dd')}.yar`
      document.body.appendChild(a)
      a.click()
      window.URL.revokeObjectURL(url)
      document.body.removeChild(a)
    } catch (err) {
      console.error('Export failed:', err)
    }
  }

  // Modal helpers
  const openNewRule = () => {
    setEditingRule(null)
    setFormData(emptyForm)
    setShowRuleModal(true)
  }

  const openEditRule = (rule) => {
    setEditingRule(rule)
    setFormData({
      name: rule.name || '',
      description: rule.description || '',
      category: rule.category || 'Malware',
      rule_content: rule.rule_content || '',
      author: rule.author || '',
      source: rule.source || '',
      tags: Array.isArray(rule.tags) ? rule.tags.join(', ') : (rule.tags || ''),
      enabled: rule.enabled !== undefined ? rule.enabled : true,
    })
    setShowRuleModal(true)
  }

  const closeRuleModal = () => {
    setShowRuleModal(false)
    setEditingRule(null)
    setFormData(emptyForm)
  }

  const handleFormSubmit = (e) => {
    e.preventDefault()
    const payload = {
      ...formData,
      tags: formData.tags
        ? formData.tags.split(',').map((t) => t.trim()).filter(Boolean)
        : [],
    }

    if (editingRule) {
      updateMutation.mutate({ id: editingRule.id, payload })
    } else {
      createMutation.mutate(payload)
    }
  }

  const handleSearchSubmit = (e) => {
    e.preventDefault()
  }

  const isSaving = createMutation.isLoading || updateMutation.isLoading

  // Loading state
  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-64">
        <Loader2 className="h-8 w-8 animate-spin text-primary-500" />
      </div>
    )
  }

  // Error state
  if (error) {
    return (
      <div className="card text-center">
        <AlertCircle className="h-12 w-12 text-danger-500 mx-auto mb-4" />
        <h3 className="text-lg font-medium text-gray-900 dark:text-white mb-2">
          Failed to load YARA rules
        </h3>
        <p className="text-gray-600 dark:text-gray-400 mb-4">{error.message}</p>
        <button onClick={() => refetch()} className="btn btn-primary">
          Retry
        </button>
      </div>
    )
  }

  return (
    <div>
      {/* Header */}
      <div className="flex items-center justify-between mb-6">
        <div className="flex items-center">
          <BookOpen className="h-7 w-7 text-primary-500 mr-3" />
          <h1 className="text-2xl font-bold text-gray-900 dark:text-white">
            YARA Rule Library
          </h1>
          <span className="ml-3 text-sm text-gray-500 dark:text-gray-400">
            {totalCount} rule{totalCount !== 1 ? 's' : ''}
          </span>
        </div>
        <div className="flex items-center space-x-2">
          <button
            onClick={() => setShowImportModal(true)}
            className="btn btn-secondary flex items-center text-sm"
          >
            <Upload className="h-4 w-4 mr-2" />
            Import
          </button>
          <button
            onClick={handleExport}
            className="btn btn-secondary flex items-center text-sm"
          >
            <Download className="h-4 w-4 mr-2" />
            Export All
          </button>
          <button
            onClick={openNewRule}
            className="btn btn-primary flex items-center text-sm"
          >
            <Plus className="h-4 w-4 mr-2" />
            New Rule
          </button>
        </div>
      </div>

      {/* Search & Filter Bar */}
      <form onSubmit={handleSearchSubmit} className="mb-6">
        <div className="flex gap-2">
          <div className="relative flex-1">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-5 w-5 text-gray-400" />
            <input
              type="text"
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              placeholder="Search rules by name, description, or content..."
              className="input pl-10"
            />
          </div>
          <select
            value={categoryFilter}
            onChange={(e) => setCategoryFilter(e.target.value)}
            className="input w-44"
          >
            <option value="">All Categories</option>
            {CATEGORIES.map((cat) => (
              <option key={cat} value={cat}>
                {cat}
              </option>
            ))}
          </select>
        </div>
      </form>

      {/* Rules List */}
      {rules.length === 0 ? (
        <div className="card text-center py-12">
          <Code className="h-12 w-12 text-gray-400 dark:text-gray-600 mx-auto mb-4" />
          <h3 className="text-lg font-medium text-gray-900 dark:text-white mb-2">
            {searchTerm || categoryFilter
              ? 'No rules match your search'
              : 'No YARA rules yet'}
          </h3>
          <p className="text-gray-600 dark:text-gray-400 mb-4">
            {searchTerm || categoryFilter
              ? 'Try adjusting your search or filter criteria.'
              : 'Create your first rule or import existing rules to get started.'}
          </p>
          {!searchTerm && !categoryFilter && (
            <div className="flex items-center justify-center space-x-3">
              <button onClick={openNewRule} className="btn btn-primary inline-flex items-center">
                <Plus className="h-4 w-4 mr-2" />
                New Rule
              </button>
              <button
                onClick={() => setShowImportModal(true)}
                className="btn btn-secondary inline-flex items-center"
              >
                <Upload className="h-4 w-4 mr-2" />
                Import Rules
              </button>
            </div>
          )}
        </div>
      ) : (
        <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3">
          {rules.map((rule) => (
            <RuleCard
              key={rule.id}
              rule={rule}
              onEdit={() => openEditRule(rule)}
              onDelete={() => setDeleteConfirmId(rule.id)}
              onToggle={(enabled) =>
                toggleMutation.mutate({ id: rule.id, enabled })
              }
            />
          ))}
        </div>
      )}

      {/* Create/Edit Rule Modal */}
      {showRuleModal && (
        <div className="fixed inset-0 z-50 overflow-y-auto">
          <div className="flex items-center justify-center min-h-screen px-4 pt-4 pb-20">
            <div
              className="fixed inset-0 bg-black/50 transition-opacity"
              onClick={closeRuleModal}
            />
            <div className="relative bg-white dark:bg-gray-900 rounded-xl shadow-xl max-w-3xl w-full mx-auto z-10">
              {/* Modal Header */}
              <div className="flex items-center justify-between px-6 py-4 border-b border-gray-200 dark:border-gray-700">
                <h2 className="text-lg font-semibold text-gray-900 dark:text-white flex items-center">
                  <Code className="h-5 w-5 mr-2 text-primary-500" />
                  {editingRule ? 'Edit Rule' : 'New YARA Rule'}
                </h2>
                <button
                  onClick={closeRuleModal}
                  className="text-gray-400 hover:text-gray-600 dark:hover:text-gray-300"
                >
                  <X className="h-5 w-5" />
                </button>
              </div>

              {/* Modal Body */}
              <form onSubmit={handleFormSubmit}>
                <div className="px-6 py-4 space-y-4 max-h-[70vh] overflow-y-auto">
                  {/* Name & Category row */}
                  <div className="grid grid-cols-2 gap-4">
                    <div>
                      <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                        Rule Name <span className="text-danger-500">*</span>
                      </label>
                      <input
                        type="text"
                        required
                        value={formData.name}
                        onChange={(e) =>
                          setFormData({ ...formData, name: e.target.value })
                        }
                        placeholder="e.g. Detect_Cobalt_Strike_Beacon"
                        className="input"
                      />
                    </div>
                    <div>
                      <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                        Category <span className="text-danger-500">*</span>
                      </label>
                      <select
                        value={formData.category}
                        onChange={(e) =>
                          setFormData({ ...formData, category: e.target.value })
                        }
                        className="input"
                      >
                        {CATEGORIES.map((cat) => (
                          <option key={cat} value={cat}>
                            {cat}
                          </option>
                        ))}
                      </select>
                    </div>
                  </div>

                  {/* Description */}
                  <div>
                    <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                      Description
                    </label>
                    <input
                      type="text"
                      value={formData.description}
                      onChange={(e) =>
                        setFormData({ ...formData, description: e.target.value })
                      }
                      placeholder="Brief description of what this rule detects..."
                      className="input"
                    />
                  </div>

                  {/* Author & Source row */}
                  <div className="grid grid-cols-2 gap-4">
                    <div>
                      <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                        Author
                      </label>
                      <input
                        type="text"
                        value={formData.author}
                        onChange={(e) =>
                          setFormData({ ...formData, author: e.target.value })
                        }
                        placeholder="Author name"
                        className="input"
                      />
                    </div>
                    <div>
                      <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                        Source
                      </label>
                      <input
                        type="text"
                        value={formData.source}
                        onChange={(e) =>
                          setFormData({ ...formData, source: e.target.value })
                        }
                        placeholder="e.g. internal, community, VirusTotal"
                        className="input"
                      />
                    </div>
                  </div>

                  {/* Tags */}
                  <div>
                    <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                      Tags
                    </label>
                    <input
                      type="text"
                      value={formData.tags}
                      onChange={(e) =>
                        setFormData({ ...formData, tags: e.target.value })
                      }
                      placeholder="Comma-separated tags, e.g. trojan, backdoor, c2"
                      className="input"
                    />
                    <p className="text-xs text-gray-500 dark:text-gray-400 mt-1">
                      Separate tags with commas
                    </p>
                  </div>

                  {/* Rule Content */}
                  <div>
                    <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                      Rule Content <span className="text-danger-500">*</span>
                    </label>
                    <textarea
                      required
                      rows={14}
                      value={formData.rule_content}
                      onChange={(e) =>
                        setFormData({ ...formData, rule_content: e.target.value })
                      }
                      placeholder={`rule example_rule {\n    meta:\n        description = "Example YARA rule"\n        author = "Analyst"\n    strings:\n        $s1 = "malicious_string"\n    condition:\n        $s1\n}`}
                      className="input font-mono text-sm leading-relaxed"
                      style={{ tabSize: 4 }}
                    />
                  </div>

                  {/* Enabled toggle */}
                  <div className="flex items-center justify-between py-2">
                    <div>
                      <span className="text-sm font-medium text-gray-700 dark:text-gray-300">
                        Enabled
                      </span>
                      <p className="text-xs text-gray-500 dark:text-gray-400">
                        Enabled rules are included in scans and exports
                      </p>
                    </div>
                    <button
                      type="button"
                      onClick={() =>
                        setFormData({ ...formData, enabled: !formData.enabled })
                      }
                      className={`relative inline-flex h-6 w-11 items-center rounded-full transition-colors ${
                        formData.enabled
                          ? 'bg-primary-500'
                          : 'bg-gray-300 dark:bg-gray-600'
                      }`}
                    >
                      <span
                        className={`inline-block h-4 w-4 transform rounded-full bg-white transition-transform ${
                          formData.enabled ? 'translate-x-6' : 'translate-x-1'
                        }`}
                      />
                    </button>
                  </div>

                  {/* Error display */}
                  {(createMutation.isError || updateMutation.isError) && (
                    <div className="p-3 bg-danger-50 dark:bg-danger-900/20 border border-danger-200 dark:border-danger-800 rounded-lg flex items-start">
                      <AlertCircle className="h-4 w-4 text-danger-500 mr-2 mt-0.5 flex-shrink-0" />
                      <span className="text-sm text-danger-700 dark:text-danger-400">
                        {createMutation.error?.response?.data?.detail ||
                          updateMutation.error?.response?.data?.detail ||
                          'Failed to save rule. Please check your input and try again.'}
                      </span>
                    </div>
                  )}
                </div>

                {/* Modal Footer */}
                <div className="flex items-center justify-end space-x-3 px-6 py-4 border-t border-gray-200 dark:border-gray-700">
                  <button
                    type="button"
                    onClick={closeRuleModal}
                    className="btn btn-secondary"
                  >
                    Cancel
                  </button>
                  <button
                    type="submit"
                    disabled={isSaving}
                    className="btn btn-primary flex items-center"
                  >
                    {isSaving && (
                      <Loader2 className="h-4 w-4 mr-2 animate-spin" />
                    )}
                    {editingRule ? 'Update Rule' : 'Create Rule'}
                  </button>
                </div>
              </form>
            </div>
          </div>
        </div>
      )}

      {/* Import Modal */}
      {showImportModal && (
        <div className="fixed inset-0 z-50 overflow-y-auto">
          <div className="flex items-center justify-center min-h-screen px-4 pt-4 pb-20">
            <div
              className="fixed inset-0 bg-black/50 transition-opacity"
              onClick={() => setShowImportModal(false)}
            />
            <div className="relative bg-white dark:bg-gray-900 rounded-xl shadow-xl max-w-2xl w-full mx-auto z-10">
              {/* Modal Header */}
              <div className="flex items-center justify-between px-6 py-4 border-b border-gray-200 dark:border-gray-700">
                <h2 className="text-lg font-semibold text-gray-900 dark:text-white flex items-center">
                  <Upload className="h-5 w-5 mr-2 text-primary-500" />
                  Import YARA Rules
                </h2>
                <button
                  onClick={() => setShowImportModal(false)}
                  className="text-gray-400 hover:text-gray-600 dark:hover:text-gray-300"
                >
                  <X className="h-5 w-5" />
                </button>
              </div>

              {/* Modal Body */}
              <div className="px-6 py-4 space-y-4">
                <p className="text-sm text-gray-600 dark:text-gray-400">
                  Paste one or more YARA rules below. Each rule will be parsed and
                  added to the library individually.
                </p>
                <textarea
                  rows={16}
                  value={importContent}
                  onChange={(e) => setImportContent(e.target.value)}
                  placeholder={`rule example_import {\n    meta:\n        description = "Imported YARA rule"\n    strings:\n        $a = "suspicious"\n    condition:\n        $a\n}\n\nrule another_rule {\n    ...\n}`}
                  className="input font-mono text-sm leading-relaxed w-full"
                  style={{ tabSize: 4 }}
                />

                {importMutation.isError && (
                  <div className="p-3 bg-danger-50 dark:bg-danger-900/20 border border-danger-200 dark:border-danger-800 rounded-lg flex items-start">
                    <AlertCircle className="h-4 w-4 text-danger-500 mr-2 mt-0.5 flex-shrink-0" />
                    <span className="text-sm text-danger-700 dark:text-danger-400">
                      {importMutation.error?.response?.data?.detail ||
                        'Import failed. Please check the YARA syntax and try again.'}
                    </span>
                  </div>
                )}

                {importMutation.isSuccess && (
                  <div className="p-3 bg-success-50 dark:bg-success-900/20 border border-success-200 dark:border-success-800 rounded-lg flex items-start">
                    <AlertCircle className="h-4 w-4 text-success-500 mr-2 mt-0.5 flex-shrink-0" />
                    <span className="text-sm text-success-700 dark:text-success-400">
                      Rules imported successfully.
                    </span>
                  </div>
                )}
              </div>

              {/* Modal Footer */}
              <div className="flex items-center justify-end space-x-3 px-6 py-4 border-t border-gray-200 dark:border-gray-700">
                <button
                  type="button"
                  onClick={() => setShowImportModal(false)}
                  className="btn btn-secondary"
                >
                  Cancel
                </button>
                <button
                  onClick={() => importMutation.mutate(importContent)}
                  disabled={!importContent.trim() || importMutation.isLoading}
                  className="btn btn-primary flex items-center"
                >
                  {importMutation.isLoading && (
                    <Loader2 className="h-4 w-4 mr-2 animate-spin" />
                  )}
                  <Upload className="h-4 w-4 mr-2" />
                  Import Rules
                </button>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Delete Confirmation Modal */}
      {deleteConfirmId !== null && (
        <div className="fixed inset-0 z-50 overflow-y-auto">
          <div className="flex items-center justify-center min-h-screen px-4">
            <div
              className="fixed inset-0 bg-black/50 transition-opacity"
              onClick={() => setDeleteConfirmId(null)}
            />
            <div className="relative bg-white dark:bg-gray-900 rounded-xl shadow-xl max-w-md w-full mx-auto z-10 p-6">
              <div className="flex items-center mb-4">
                <div className="bg-danger-100 dark:bg-danger-900/30 rounded-full p-2 mr-3">
                  <Trash2 className="h-5 w-5 text-danger-600 dark:text-danger-400" />
                </div>
                <h3 className="text-lg font-semibold text-gray-900 dark:text-white">
                  Delete Rule
                </h3>
              </div>
              <p className="text-sm text-gray-600 dark:text-gray-400 mb-6">
                Are you sure you want to delete this YARA rule? This action cannot
                be undone.
              </p>
              <div className="flex items-center justify-end space-x-3">
                <button
                  onClick={() => setDeleteConfirmId(null)}
                  className="btn btn-secondary"
                >
                  Cancel
                </button>
                <button
                  onClick={() => deleteMutation.mutate(deleteConfirmId)}
                  disabled={deleteMutation.isLoading}
                  className="btn btn-danger flex items-center"
                >
                  {deleteMutation.isLoading && (
                    <Loader2 className="h-4 w-4 mr-2 animate-spin" />
                  )}
                  <Trash2 className="h-4 w-4 mr-2" />
                  Delete
                </button>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}

function RuleCard({ rule, onEdit, onDelete, onToggle }) {
  const categoryClass =
    categoryColors[rule.category] || 'bg-gray-100 text-gray-700 dark:bg-gray-800 dark:text-gray-300'

  return (
    <div className="card hover:shadow-md transition-shadow">
      {/* Card Header */}
      <div className="flex items-start justify-between mb-3">
        <div className="flex-1 min-w-0 mr-3">
          <div className="flex items-center gap-2 mb-1">
            <h3 className="font-semibold text-gray-900 dark:text-white truncate text-sm">
              {rule.name}
            </h3>
            <span
              className={`px-2 py-0.5 rounded-full text-xs font-medium flex-shrink-0 ${categoryClass}`}
            >
              {rule.category}
            </span>
          </div>
          {rule.description && (
            <p className="text-sm text-gray-600 dark:text-gray-400 line-clamp-2">
              {rule.description}
            </p>
          )}
        </div>

        {/* Enabled toggle */}
        <button
          onClick={() => onToggle(!rule.enabled)}
          className="flex-shrink-0"
          title={rule.enabled ? 'Disable rule' : 'Enable rule'}
        >
          {rule.enabled ? (
            <ToggleRight className="h-6 w-6 text-primary-500" />
          ) : (
            <ToggleLeft className="h-6 w-6 text-gray-400 dark:text-gray-600" />
          )}
        </button>
      </div>

      {/* Tags */}
      {rule.tags && rule.tags.length > 0 && (
        <div className="flex flex-wrap gap-1 mb-3">
          {(Array.isArray(rule.tags) ? rule.tags : [rule.tags]).map((tag, idx) => (
            <span
              key={idx}
              className="px-1.5 py-0.5 bg-gray-100 dark:bg-gray-800 text-gray-600 dark:text-gray-400 rounded text-xs"
            >
              {tag}
            </span>
          ))}
        </div>
      )}

      {/* Meta Info */}
      <div className="flex items-center text-xs text-gray-500 dark:text-gray-400 space-x-3 mb-3">
        {rule.author && (
          <span className="truncate">
            By {rule.author}
          </span>
        )}
        {rule.created_at && (
          <span className="flex-shrink-0">
            {format(new Date(rule.created_at), 'MMM d, yyyy')}
          </span>
        )}
      </div>

      {/* Rule content preview */}
      {rule.rule_content && (
        <div className="bg-gray-50 dark:bg-gray-800 rounded-lg p-2 mb-3 overflow-hidden">
          <pre className="text-xs font-mono text-gray-600 dark:text-gray-400 truncate whitespace-pre overflow-hidden max-h-10 leading-tight">
            {rule.rule_content.substring(0, 120)}
            {rule.rule_content.length > 120 ? '...' : ''}
          </pre>
        </div>
      )}

      {/* Actions */}
      <div className="flex items-center space-x-2 pt-2 border-t border-gray-100 dark:border-gray-800">
        <button
          onClick={onEdit}
          className="btn btn-secondary flex-1 flex items-center justify-center text-sm py-1.5"
        >
          <Edit3 className="h-3.5 w-3.5 mr-1.5" />
          Edit
        </button>
        <button
          onClick={onDelete}
          className="btn btn-danger flex items-center justify-center text-sm py-1.5 px-3"
        >
          <Trash2 className="h-3.5 w-3.5" />
        </button>
      </div>
    </div>
  )
}

export default YaraRulesPage
