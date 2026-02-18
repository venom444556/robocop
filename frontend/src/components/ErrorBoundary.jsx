import { Component } from 'react'
import { AlertCircle, RefreshCw, Home } from 'lucide-react'

export default class ErrorBoundary extends Component {
  constructor(props) {
    super(props)
    this.state = { hasError: false, error: null, errorInfo: null, errorId: null }
  }

  static getDerivedStateFromError(error) {
    const errorId = `ERR-${Date.now().toString(36).toUpperCase()}`
    return { hasError: true, error, errorId }
  }

  componentDidCatch(error, errorInfo) {
    this.setState({ errorInfo })
    console.error(`[${this.state.errorId}] Uncaught error:`, error, errorInfo)
  }

  render() {
    if (!this.state.hasError) {
      return this.props.children
    }

    const { error, errorInfo, errorId } = this.state

    return (
      <div className="p-6 max-w-2xl mx-auto">
        <div className="bg-white dark:bg-gray-800 rounded-lg shadow-md border-l-4 border-red-500 p-6">
          <div className="flex items-start gap-3 mb-4">
            <AlertCircle className="h-6 w-6 text-red-500 flex-shrink-0 mt-0.5" />
            <div>
              <h2 className="text-lg font-semibold text-gray-900 dark:text-white">
                Something went wrong
              </h2>
              <p className="text-sm text-gray-500 dark:text-gray-400 mt-1">
                An unexpected error occurred. You can try reloading or return to the dashboard.
              </p>
              <p className="text-xs text-gray-400 dark:text-gray-500 mt-2 font-mono">
                Error ID: {errorId}
              </p>
            </div>
          </div>

          <details className="mb-6">
            <summary className="text-sm font-medium text-gray-600 dark:text-gray-300 cursor-pointer hover:text-gray-900 dark:hover:text-white">
              Technical details
            </summary>
            <div className="mt-2 p-3 bg-gray-50 dark:bg-gray-900 rounded border border-gray-200 dark:border-gray-700 overflow-auto max-h-64">
              <p className="text-sm font-mono text-red-600 dark:text-red-400 mb-2">
                {error?.toString()}
              </p>
              {errorInfo?.componentStack && (
                <pre className="text-xs font-mono text-gray-500 dark:text-gray-400 whitespace-pre-wrap">
                  {errorInfo.componentStack}
                </pre>
              )}
            </div>
          </details>

          <div className="flex gap-3">
            <button
              onClick={() => window.location.reload()}
              className="btn btn-primary flex items-center gap-2"
            >
              <RefreshCw className="h-4 w-4" />
              Reload Application
            </button>
            <button
              onClick={() => { window.location.href = '/dashboard' }}
              className="btn btn-secondary flex items-center gap-2"
            >
              <Home className="h-4 w-4" />
              Return to Dashboard
            </button>
          </div>
        </div>
      </div>
    )
  }
}
