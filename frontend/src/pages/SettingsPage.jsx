import { useState, useEffect } from 'react'
import {
  Key,
  Save,
  CheckCircle,
  AlertCircle,
  Eye,
  EyeOff,
  Shield,
  Globe,
  Info,
  ExternalLink
} from 'lucide-react'

function SettingsPage() {
  const [apiKeys, setApiKeys] = useState({
    platform_api_key: '',
    anthropic_api_key: '',
    virustotal_api_key: '',
    shodan_api_key: '',
    urlhaus_auth_key: '',
    google_safebrowsing_api_key: '',
    ipqualityscore_api_key: '',
    checkphish_api_key: '',
    greynoise_api_key: '',
    abuseipdb_api_key: '',
    urlscan_api_key: '',
    alienvault_otx_api_key: '',
    malwarebazaar_api_key: '',
    nvd_api_key: '',
  })
  const [showKeys, setShowKeys] = useState({})
  const [saved, setSaved] = useState(false)
  const [enrichmentExpanded, setEnrichmentExpanded] = useState(true)

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

  const coreFields = [
    {
      key: 'platform_api_key',
      label: 'Platform API Key',
      description: 'Must match the API_KEY set in your server .env file (32+ chars in production)',
      required: true,
    },
    {
      key: 'anthropic_api_key',
      label: 'Anthropic API Key',
      description: 'Required for Claude AI reasoning agents',
      link: 'https://console.anthropic.com/',
      required: true,
    },
  ]

  const enrichmentFields = [
    {
      key: 'virustotal_api_key',
      label: 'VirusTotal',
      description: 'File/URL reputation and detection counts — 4 req/min free tier',
      link: 'https://www.virustotal.com/gui/join-us',
    },
    {
      key: 'shodan_api_key',
      label: 'Shodan',
      description: 'IP intelligence, open ports, and services',
      link: 'https://account.shodan.io/register',
    },
    {
      key: 'urlhaus_auth_key',
      label: 'URLhaus',
      description: 'Malware URL database by abuse.ch — free, no key required for basic lookups',
      link: 'https://urlhaus.abuse.ch/api/',
    },
    {
      key: 'google_safebrowsing_api_key',
      label: 'Google Safe Browsing',
      description: 'Phishing and malware site detection',
      link: 'https://developers.google.com/safe-browsing',
    },
    {
      key: 'ipqualityscore_api_key',
      label: 'IPQualityScore',
      description: 'IP/URL fraud and risk scoring',
      link: 'https://www.ipqualityscore.com/create-account',
    },
    {
      key: 'checkphish_api_key',
      label: 'CheckPhish',
      description: 'URL phishing categorization',
      link: 'https://checkphish.bolster.ai/',
    },
    {
      key: 'greynoise_api_key',
      label: 'GreyNoise',
      description: 'IP noise vs. targeted threat classification',
      link: 'https://www.greynoise.io/plans',
    },
    {
      key: 'abuseipdb_api_key',
      label: 'AbuseIPDB',
      description: 'Community IP abuse reputation database',
      link: 'https://www.abuseipdb.com/register',
    },
    {
      key: 'urlscan_api_key',
      label: 'urlscan.io',
      description: 'URL visual analysis, DOM inspection, and tech stack',
      link: 'https://urlscan.io/user/signup',
    },
    {
      key: 'alienvault_otx_api_key',
      label: 'AlienVault OTX',
      description: 'Pulse-based community threat intelligence',
      link: 'https://otx.alienvault.com/api',
    },
    {
      key: 'malwarebazaar_api_key',
      label: 'MalwareBazaar',
      description: 'Malware sample intelligence by abuse.ch',
      link: 'https://bazaar.abuse.ch/api/',
    },
    {
      key: 'nvd_api_key',
      label: 'NVD (NIST)',
      description: 'CVE vulnerability lookups — works without key but rate-limited',
      link: 'https://nvd.nist.gov/developers/request-an-api-key',
    },
  ]

  const ApiKeyInput = ({ field }) => (
    <div key={field.key}>
      <label className="block text-sm font-medium text-gray-300 mb-1">
        {field.label}
        {field.required && <span className="text-red-400 ml-1">*</span>}
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
          aria-label={showKeys[field.key] ? 'Hide API key' : 'Show API key'}
        >
          {showKeys[field.key] ? (
            <EyeOff className="h-4 w-4" />
          ) : (
            <Eye className="h-4 w-4" />
          )}
        </button>
      </div>
      <p className="text-xs text-gray-500 mt-1">
        {field.description}
        {field.link && (
          <>
            {' · '}
            <a href={field.link} target="_blank" rel="noopener noreferrer" className="text-cyan-400 hover:text-cyan-300 inline-flex items-center gap-0.5">
              Get key <ExternalLink className="h-3 w-3" />
            </a>
          </>
        )}
      </p>
    </div>
  )

  return (
    <div className="max-w-2xl mx-auto">
      <h1 className="text-2xl font-bold text-gray-100 mb-6">Settings</h1>

      {/* Success Message */}
      {saved && (
        <div className="mb-6 p-4 bg-emerald-900/30 border border-emerald-700 rounded-lg flex items-center">
          <CheckCircle className="h-5 w-5 text-emerald-400 mr-3" />
          <span className="text-emerald-300">Settings saved successfully</span>
        </div>
      )}

      {/* Core Keys Section */}
      <div className="card">
        <h2 className="text-lg font-semibold text-gray-100 mb-1 flex items-center">
          <Shield className="h-5 w-5 mr-2 text-cyan-400" />
          Core Configuration
        </h2>
        <p className="text-sm text-gray-400 mb-6">
          Required keys for platform authentication and AI reasoning.
        </p>

        <div className="space-y-5">
          {coreFields.map((field) => (
            <ApiKeyInput key={field.key} field={field} />
          ))}
        </div>
      </div>

      {/* Enrichment Keys Section */}
      <div className="card mt-6">
        <button
          onClick={() => setEnrichmentExpanded(!enrichmentExpanded)}
          className="w-full flex items-center justify-between"
        >
          <h2 className="text-lg font-semibold text-gray-100 flex items-center">
            <Globe className="h-5 w-5 mr-2 text-cyan-400" />
            Threat Intelligence Sources ({enrichmentFields.length})
          </h2>
          <span className={`text-gray-400 transition-transform ${enrichmentExpanded ? 'rotate-180' : ''}`}>
            ▾
          </span>
        </button>
        <p className="text-sm text-gray-400 mt-1 mb-2">
          All sources offer free tiers. WHOIS lookups require no API key.
        </p>

        {enrichmentExpanded && (
          <div className="space-y-5 mt-4 pt-4 border-t border-gray-700">
            {enrichmentFields.map((field) => (
              <ApiKeyInput key={field.key} field={field} />
            ))}
          </div>
        )}
      </div>

      {/* Save Button */}
      <button
        onClick={handleSave}
        className="btn btn-primary w-full mt-6 flex items-center justify-center"
      >
        <Save className="h-4 w-4 mr-2" />
        Save Settings
      </button>

      {/* About Section */}
      <div className="card mt-6">
        <h2 className="text-lg font-semibold text-gray-100 mb-4 flex items-center">
          <Info className="h-5 w-5 mr-2 text-cyan-400" />
          About
        </h2>
        <div className="space-y-3 text-sm text-gray-400">
          <p>
            <strong className="text-gray-200">RoboCop</strong> — Reasoning-Orchestration Bot for Cyber Operations Protection.
            An AI-powered malware analysis platform combining 6 Claude AI agents, 14 threat intelligence sources,
            and automated n8n workflows.
          </p>
          <p>
            Features include multi-layer script decoding, IOC extraction and enrichment, MITRE ATT&CK mapping,
            YARA rule management, and professional report generation.
          </p>
          <div className="pt-3 border-t border-gray-700 text-xs text-gray-500">
            <p>Built by <strong className="text-gray-400">Sheldon Spence</strong></p>
            <p className="mt-1">MIT License · v1.0.0</p>
          </div>
        </div>
      </div>

      {/* Security Notice */}
      <div className="mt-6 mb-8 p-4 bg-amber-900/20 border border-amber-700/50 rounded-lg flex items-start">
        <AlertCircle className="h-5 w-5 text-amber-400 mr-3 mt-0.5 flex-shrink-0" />
        <div className="text-sm text-amber-300/80">
          <p className="font-medium text-amber-300">Security Notice</p>
          <p>
            API keys entered here are stored in your browser's local storage for convenience.
            For production deployments, configure all keys server-side via environment variables in <code className="text-amber-400">.env</code>.
          </p>
        </div>
      </div>
    </div>
  )
}

export default SettingsPage
