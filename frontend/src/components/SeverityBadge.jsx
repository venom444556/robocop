import { XCircle, AlertTriangle, AlertCircle, Info } from 'lucide-react'

const SEVERITY_MAP = {
  critical: {
    icon: XCircle,
    label: 'Critical',
    classes: 'bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-200',
    iconColor: 'text-red-600 dark:text-red-400',
  },
  high: {
    icon: AlertTriangle,
    label: 'High',
    classes: 'bg-orange-100 text-orange-800 dark:bg-orange-900 dark:text-orange-200',
    iconColor: 'text-orange-600 dark:text-orange-400',
  },
  medium: {
    icon: AlertCircle,
    label: 'Medium',
    classes: 'bg-yellow-100 text-yellow-800 dark:bg-yellow-900 dark:text-yellow-200',
    iconColor: 'text-yellow-600 dark:text-yellow-400',
  },
  low: {
    icon: Info,
    label: 'Low',
    classes: 'bg-blue-100 text-blue-800 dark:bg-blue-900 dark:text-blue-200',
    iconColor: 'text-blue-600 dark:text-blue-400',
  },
  informational: {
    icon: Info,
    label: 'Info',
    classes: 'bg-gray-100 text-gray-800 dark:bg-gray-700 dark:text-gray-200',
    iconColor: 'text-gray-500 dark:text-gray-400',
  },
}

export default function SeverityBadge({ severity, size = 'md' }) {
  const key = severity?.toLowerCase() || 'informational'
  const config = SEVERITY_MAP[key] || SEVERITY_MAP.informational
  const Icon = config.icon

  const sizeClasses = size === 'sm'
    ? 'px-1.5 py-0.5 text-xs gap-1'
    : 'px-2.5 py-1 text-sm gap-1.5'

  const iconSize = size === 'sm' ? 'h-3 w-3' : 'h-4 w-4'

  return (
    <span className={`inline-flex items-center font-medium rounded-full ${sizeClasses} ${config.classes}`}>
      <Icon className={`${iconSize} ${config.iconColor}`} />
      {config.label}
    </span>
  )
}
