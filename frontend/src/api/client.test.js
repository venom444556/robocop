import { describe, it, expect, vi } from 'vitest'
import client, { setToastFn } from './client.js'

describe('API Client', () => {
  it('should use /api as default base URL', () => {
    expect(client.defaults.baseURL).toBe('/api')
  })

  it('should set Content-Type header to application/json', () => {
    expect(client.defaults.headers['Content-Type']).toBe('application/json')
  })

  it('should export setToastFn function', () => {
    expect(typeof setToastFn).toBe('function')
  })

  it('should attach API key via request interceptor when set in localStorage', () => {
    // The interceptor reads from localStorage at call time
    localStorage.setItem('api_key', 'test-key-abc')

    // Find and call the API key interceptor directly
    const handlers = client.interceptors.request.handlers.filter(h => h?.fulfilled)
    let found = false
    for (const handler of handlers) {
      const config = { headers: {} }
      const result = handler.fulfilled(config)
      if (result.headers['X-API-Key'] === 'test-key-abc') {
        found = true
        break
      }
    }
    expect(found).toBe(true)

    localStorage.removeItem('api_key')
  })

  it('should not attach API key header when localStorage is empty', () => {
    localStorage.removeItem('api_key')

    const handlers = client.interceptors.request.handlers.filter(h => h?.fulfilled)
    for (const handler of handlers) {
      const config = { headers: {} }
      const result = handler.fulfilled(config)
      expect(result.headers['X-API-Key']).toBeUndefined()
    }
  })
})
