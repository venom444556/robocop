import { useState, useEffect } from 'react'
import {
  Key,
  Save,
  CheckCircle,
  AlertCircle,
  Eye,
  EyeOff
} from 'lucide-react'

function SettingsPage() {
  const [apiKeys, setApiKeys] = useState({
    platform_api_key: '',
    virustotal_api_key: '',
    shodan_api_key: '',
    anthropic_api_key: '',
  })
  const [showKeys, setShowKeys] = useState({})
  const [saved, setSaved] = useState(false)

  useEffect(() => {
    // Load saved API keys from localStorage
    const savedKeys = localStorage.getItem('api_keys')
    if (savedKeys) {
      setApiKeys(JSON.parse(savedKeys))
    }
    // Also load platform API key
    const platformKey = localStorage.getItem('api_key')
    if (platformKey) {
      setApiKeys(prev => ({ ...prev, platform_api_key: platformKey }))
    }
  }, [])

  const handleSave = () => {
    // Save to localStorage
    localStorage.setItem('api_keys', JSON.stringify(apiKeys))
    localStorage.setItem('api_key', apiKeys.platform_api_key)
    setSaved(true)
    setTimeout(() => setSaved(false), 3000)
  }

  const toggleShowKey = (key) => {
    setShowKeys(prev => ({ ...prev, [key]: !prev[key] }))
  }

  const apiKeyFields = [
    {
      key: 'platform_api_key',
      label: 'Platform API Key',
      description: 'API key for authenticating with the analysis platform',
      required: true,
    },
    {
      key: 'virustotal_api_key',
      label: 'VirusTotal API Key',
      description: 'Free tier: 4 requests/minute. Get one at virustotal.com',
      required: false,
    },
    {
      key: 'shodan_api_key',
      label: 'Shodan API Key',
      description: 'Free tier available. Get one at shodan.io',
      required: false,
    },
    {
      key: 'anthropic_api_key',
      label: 'Anthropic API Key',
      description: 'Required for Claude reasoning. Get one at console.anthropic.com',
      required: false,
    },
  ]

  return (
    <div className="max-w-2xl mx-auto">
      <h1 className="text-2xl font-bold text-gray-900 mb-6">Settings</h1>

      {/* Success Message */}
      {saved && (
        <div className="mb-6 p-4 bg-success-50 border border-success-200 rounded-lg flex items-center">
          <CheckCircle className="h-5 w-5 text-success-600 mr-3" />
          <span className="text-success-700">Settings saved successfully</span>
        </div>
      )}

      {/* API Keys Section */}
      <div className="card">
        <h2 className="text-lg font-semibold text-gray-900 mb-4 flex items-center">
          <Key className="h-5 w-5 mr-2 text-primary-500" />
          API Keys
        </h2>
        <p className="text-sm text-gray-600 mb-6">
          Configure API keys for external services. Keys are stored locally in your browser.
        </p>

        <div className="space-y-6">
          {apiKeyFields.map((field) => (
            <div key={field.key}>
              <label className="block text-sm font-medium text-gray-700 mb-1">
                {field.label}
                {field.required && <span className="text-danger-500 ml-1">*</span>}
              </label>
              <div className="relative">
                <input
                  type={showKeys[field.key] ? 'text' : 'password'}
                  value={apiKeys[field.key] || ''}
                  onChange={(e) => setApiKeys(prev => ({ ...prev, [field.key]: e.target.value }))}
                  placeholder="Enter API key..."
                  className="input pr-10"
                />
                <button
                  type="button"
                  onClick={() => toggleShowKey(field.key)}
                  className="absolute right-3 top-1/2 -translate-y-1/2 text-gray-400 hover:text-gray-600"
                >
                  {showKeys[field.key] ? (
                    <EyeOff className="h-4 w-4" />
                  ) : (
                    <Eye className="h-4 w-4" />
                  )}
                </button>
              </div>
              <p className="text-xs text-gray-500 mt-1">{field.description}</p>
            </div>
          ))}
        </div>

        <button
          onClick={handleSave}
          className="btn btn-primary w-full mt-6 flex items-center justify-center"
        >
          <Save className="h-4 w-4 mr-2" />
          Save Settings
        </button>
      </div>

      {/* Info Section */}
      <div className="card mt-6">
        <h2 className="text-lg font-semibold text-gray-900 mb-4">About</h2>
        <div className="space-y-2 text-sm text-gray-600">
          <p>
            <strong>Malware Analysis Platform</strong> - A static analysis platform
            using Claude AI for reasoning, intelligence enrichment, and report generation.
          </p>
          <p>
            Features include script analysis and decoding, URL expansion and categorization,
            sandbox report parsing, and MITRE ATT&CK mapping.
          </p>
        </div>
      </div>

      {/* Warning */}
      <div className="mt-6 p-4 bg-warning-50 border border-warning-200 rounded-lg flex items-start">
        <AlertCircle className="h-5 w-5 text-warning-600 mr-3 mt-0.5 flex-shrink-0" />
        <div className="text-sm text-warning-700">
          <p className="font-medium">Security Notice</p>
          <p>
            API keys are stored in your browser's local storage. For production use,
            configure keys on the server via environment variables.
          </p>
        </div>
      </div>
    </div>
  )
}

export default SettingsPage
