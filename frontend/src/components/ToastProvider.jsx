import { createContext, useContext, useState, useCallback, useEffect, useRef } from 'react'
import { createPortal } from 'react-dom'
import { AlertCircle, CheckCircle, AlertTriangle, Info, X } from 'lucide-react'

const ToastContext = createContext(null)

const TOAST_CONFIG = {
  error:   { icon: AlertCircle,    border: 'border-red-500',    bg: 'bg-red-50 dark:bg-red-950',    text: 'text-red-800 dark:text-red-200',    iconColor: 'text-red-500',    duration: 7000 },
  success: { icon: CheckCircle,    border: 'border-green-500',  bg: 'bg-green-50 dark:bg-green-950',  text: 'text-green-800 dark:text-green-200',  iconColor: 'text-green-500',  duration: 5000 },
  warning: { icon: AlertTriangle,  border: 'border-amber-500',  bg: 'bg-amber-50 dark:bg-amber-950',  text: 'text-amber-800 dark:text-amber-200',  iconColor: 'text-amber-500',  duration: 5000 },
  info:    { icon: Info,           border: 'border-blue-500',   bg: 'bg-blue-50 dark:bg-blue-950',   text: 'text-blue-800 dark:text-blue-200',   iconColor: 'text-blue-500',   duration: 5000 },
}

let toastIdCounter = 0

function Toast({ toast, onDismiss }) {
  const config = TOAST_CONFIG[toast.type] || TOAST_CONFIG.info
  const Icon = config.icon

  useEffect(() => {
    if (toast.duration === 0) return
    const timer = setTimeout(() => onDismiss(toast.id), toast.duration)
    return () => clearTimeout(timer)
  }, [toast.id, toast.duration, onDismiss])

  return (
    <div
      role="alert"
      className={`flex items-start gap-3 p-4 rounded-lg border-l-4 shadow-lg max-w-sm w-full transition-all duration-300 ${config.border} ${config.bg} ${config.text}`}
    >
      <Icon className={`h-5 w-5 flex-shrink-0 mt-0.5 ${config.iconColor}`} />
      <p className="flex-1 text-sm font-medium">{toast.message}</p>
      <button
        onClick={() => onDismiss(toast.id)}
        className="flex-shrink-0 p-0.5 rounded hover:bg-black/10 dark:hover:bg-white/10 transition-colors"
        aria-label="Dismiss notification"
      >
        <X className="h-4 w-4" />
      </button>
    </div>
  )
}

export function ToastProvider({ children }) {
  const [toasts, setToasts] = useState([])
  const toastsRef = useRef(toasts)
  toastsRef.current = toasts

  const addToast = useCallback((message, type = 'info', duration) => {
    const config = TOAST_CONFIG[type] || TOAST_CONFIG.info
    const id = ++toastIdCounter
    const toast = { id, message, type, duration: duration ?? config.duration }
    setToasts((prev) => [...prev, toast])
    return id
  }, [])

  const dismissToast = useCallback((id) => {
    setToasts((prev) => prev.filter((t) => t.id !== id))
  }, [])

  return (
    <ToastContext.Provider value={{ addToast, dismissToast }}>
      {children}
      {createPortal(
        <div
          aria-live="polite"
          className="fixed bottom-6 right-6 z-50 flex flex-col gap-3 pointer-events-none"
        >
          {toasts.map((toast) => (
            <div key={toast.id} className="pointer-events-auto">
              <Toast toast={toast} onDismiss={dismissToast} />
            </div>
          ))}
        </div>,
        document.body
      )}
    </ToastContext.Provider>
  )
}

export function useToast() {
  const context = useContext(ToastContext)
  if (!context) {
    throw new Error('useToast must be used within a ToastProvider')
  }
  return context
}
