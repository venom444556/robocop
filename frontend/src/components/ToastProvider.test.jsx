import { describe, it, expect, vi } from 'vitest'
import { render, screen, act } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { ToastProvider, useToast } from './ToastProvider'

function TestConsumer() {
  const { addToast } = useToast()
  return (
    <div>
      <button onClick={() => addToast('Test success', 'success')}>Show Success</button>
      <button onClick={() => addToast('Test error', 'error')}>Show Error</button>
      <button onClick={() => addToast('Persistent', 'error', 0)}>Show Persistent</button>
    </div>
  )
}

describe('ToastProvider', () => {
  it('renders children without toasts', () => {
    render(
      <ToastProvider>
        <div>Child content</div>
      </ToastProvider>
    )
    expect(screen.getByText('Child content')).toBeInTheDocument()
  })

  it('shows a toast when addToast is called', async () => {
    const user = userEvent.setup()
    render(
      <ToastProvider>
        <TestConsumer />
      </ToastProvider>
    )

    await user.click(screen.getByText('Show Success'))
    expect(screen.getByText('Test success')).toBeInTheDocument()
  })

  it('shows multiple toasts', async () => {
    const user = userEvent.setup()
    render(
      <ToastProvider>
        <TestConsumer />
      </ToastProvider>
    )

    await user.click(screen.getByText('Show Success'))
    await user.click(screen.getByText('Show Error'))
    expect(screen.getByText('Test success')).toBeInTheDocument()
    expect(screen.getByText('Test error')).toBeInTheDocument()
  })

  it('auto-dismisses toast after timeout', async () => {
    vi.useFakeTimers()
    render(
      <ToastProvider>
        <TestConsumer />
      </ToastProvider>
    )

    await act(async () => {
      screen.getByText('Show Success').click()
    })
    expect(screen.getByText('Test success')).toBeInTheDocument()

    await act(async () => {
      vi.advanceTimersByTime(6000)
    })
    expect(screen.queryByText('Test success')).not.toBeInTheDocument()
    vi.useRealTimers()
  })

  it('persistent toast stays until dismissed', async () => {
    vi.useFakeTimers()
    render(
      <ToastProvider>
        <TestConsumer />
      </ToastProvider>
    )

    await act(async () => {
      screen.getByText('Show Persistent').click()
    })
    expect(screen.getByText('Persistent')).toBeInTheDocument()

    await act(async () => {
      vi.advanceTimersByTime(30000)
    })
    // Should still be there
    expect(screen.getByText('Persistent')).toBeInTheDocument()
    vi.useRealTimers()
  })

  it('dismisses toast when X button is clicked', async () => {
    const user = userEvent.setup()
    render(
      <ToastProvider>
        <TestConsumer />
      </ToastProvider>
    )

    await user.click(screen.getByText('Show Success'))
    expect(screen.getByText('Test success')).toBeInTheDocument()

    await user.click(screen.getByLabelText('Dismiss notification'))
    expect(screen.queryByText('Test success')).not.toBeInTheDocument()
  })
})
