// Stand-in for the Wails JS runtime (wailsjs/runtime/runtime.js).
//
// runtime.js resolves EventsOn through window.runtime.EventsOnMultiple, so
// installing that function is enough to let the real module work. Event
// handlers are recorded so a test can push a backend event into the component.
import {vi} from 'vitest'

type Handler = (...args: unknown[]) => void

const handlers = new Map<string, Set<Handler>>()

// EventsOn in runtime.js forwards to EventsOnMultiple(name, callback, max)
// and expects the cancel function it returns.
function eventsOnMultiple(name: string, callback: Handler): () => void {
  const set = handlers.get(name) ?? new Set<Handler>()
  set.add(callback)
  handlers.set(name, set)
  return () => {
    set.delete(callback)
  }
}

export function installRuntime(): void {
  const w = window as unknown as Record<string, unknown>
  w.runtime = {
    EventsOnMultiple: vi.fn((name: string, callback: Handler) => eventsOnMultiple(name, callback)),
    EventsEmit: vi.fn(),
    BrowserOpenURL: vi.fn(),
    Quit: vi.fn(),
  }
}

export function installBridge(bridge: Record<string, unknown>): void {
  const w = window as unknown as Record<string, unknown>
  w.go = {main: {App: bridge}}
}

// Fires a backend event at the component the way the Wails runtime would.
export function emit(name: string, ...args: unknown[]): void {
  for (const handler of [...(handlers.get(name) ?? [])]) {
    handler(...args)
  }
}

export function resetRuntime(): void {
  handlers.clear()
}
