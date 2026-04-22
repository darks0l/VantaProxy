import type { SSEEvent } from '../types'

type EventCallback = (event: SSEEvent) => void

export class SSEClient {
  private eventSource: EventSource | null = null
  private callbacks: Map<string, Set<EventCallback>> = new Map()
  private reconnectDelay = 1000
  private maxReconnectDelay = 30000
  private currentReconnectDelay = this.reconnectDelay
  private reconnectTimer: number | null = null
  private url: string
  private isManualClose = false

  constructor(url = '/admin/events') {
    this.url = url
  }

  connect(): void {
    if (this.eventSource) {
      return // Already connected
    }

    this.isManualClose = false
    this.eventSource = new EventSource(this.url)

    // Handle connection open
    this.eventSource.addEventListener('open', () => {
      console.log('SSE connected')
      this.currentReconnectDelay = this.reconnectDelay // Reset reconnect delay
    })

    // Handle connection error
    this.eventSource.addEventListener('error', () => {
      console.error('SSE connection error')
      this.eventSource?.close()
      this.eventSource = null

      // Reconnect with exponential backoff
      if (!this.isManualClose) {
        this.scheduleReconnect()
      }
    })

    // Handle different event types
    this.eventSource.addEventListener('audit_entry', (e) => {
      this.handleEvent('audit_entry', e)
    })

    // Handle generic messages
    this.eventSource.addEventListener('message', (e) => {
      this.handleEvent('message', e)
    })
  }

  private handleEvent(type: string, event: MessageEvent): void {
    try {
      const parsed = JSON.parse(event.data)

      // Backend sends: { type: "...", data: {...}, channel: "..." }
      // We want to extract the nested data
      const actualData = parsed.data || parsed

      const sseEvent: SSEEvent = {
        type: type as any,
        data: actualData,
        channel: parsed.channel
      }

      // Call all callbacks registered for this event type
      const callbacks = this.callbacks.get(type)
      if (callbacks) {
        callbacks.forEach(callback => callback(sseEvent))
      }

      // Also call callbacks registered for 'all' events
      const allCallbacks = this.callbacks.get('*')
      if (allCallbacks) {
        allCallbacks.forEach(callback => callback(sseEvent))
      }
    } catch (error) {
      console.error('Failed to parse SSE event:', error, event.data)
    }
  }

  private scheduleReconnect(): void {
    if (this.reconnectTimer) {
      clearTimeout(this.reconnectTimer)
    }

    console.log(`Reconnecting in ${this.currentReconnectDelay}ms...`)

    this.reconnectTimer = window.setTimeout(() => {
      this.connect()

      // Increase reconnect delay for next time (exponential backoff)
      this.currentReconnectDelay = Math.min(
        this.currentReconnectDelay * 2,
        this.maxReconnectDelay
      )
    }, this.currentReconnectDelay)
  }

  on(eventType: string, callback: EventCallback): () => void {
    if (!this.callbacks.has(eventType)) {
      this.callbacks.set(eventType, new Set())
    }

    this.callbacks.get(eventType)!.add(callback)

    // Return unsubscribe function
    return () => {
      const callbacks = this.callbacks.get(eventType)
      if (callbacks) {
        callbacks.delete(callback)
      }
    }
  }

  disconnect(): void {
    this.isManualClose = true

    if (this.reconnectTimer) {
      clearTimeout(this.reconnectTimer)
      this.reconnectTimer = null
    }

    if (this.eventSource) {
      this.eventSource.close()
      this.eventSource = null
    }

    console.log('SSE disconnected')
  }

  isConnected(): boolean {
    return this.eventSource !== null && this.eventSource.readyState === EventSource.OPEN
  }
}

// Singleton instance
let sseClient: SSEClient | null = null

export function getSSEClient(): SSEClient {
  if (!sseClient) {
    // Auth is handled via the "token" cookie which the browser sends
    // automatically with EventSource requests. Tokens are never placed
    // in the URL to avoid leaking credentials in logs and Referer headers.
    sseClient = new SSEClient('/admin/events')
  }
  return sseClient
}

// Resets the singleton so a new client (with a different token) can be created.
export function resetSSEClient(): void {
  if (sseClient) {
    sseClient.disconnect()
    sseClient = null
  }
}
