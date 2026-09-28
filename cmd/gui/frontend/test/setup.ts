import '@testing-library/jest-dom/vitest'
import {cleanup} from '@testing-library/svelte'
import {afterEach, beforeEach, vi} from 'vitest'
import {bridge} from './bridge'
import {installBridge, installRuntime, resetRuntime} from './runtime'

beforeEach(() => {
  // mockReset restores the implementation each vi.fn was declared with, so this
  // also puts every binding back to its default.
  vi.resetAllMocks()
  installBridge(bridge)
  installRuntime()
})

afterEach(() => {
  cleanup()
  resetRuntime()
})
