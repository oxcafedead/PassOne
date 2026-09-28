import {svelte} from '@sveltejs/vite-plugin-svelte'
import {defineConfig} from 'vitest/config'

// DOM smoke tests for the Wails frontend.
//
// App.svelte reaches the Go backend through the generated bindings, which need
// a live Wails runtime. test/setup.ts installs a window.go/window.runtime stand-in
// so the real wailsjs modules resolve and the component can be driven in jsdom.
//
// No alias is involved on purpose: the generated App.js stays in the loop, so a
// binding that calls the wrong window path fails here too.
// cmd/gui/binding_contract_test.go covers the other half, that the generated
// bindings and App.svelte's import list still match *App.
//
// The Tailwind plugin is deliberately absent. It has no named ESM export, and
// vitest does not need the stylesheet pipeline to exercise behaviour.
export default defineConfig({
  plugins: [svelte()],
  // svelte's package exports have a server entry that throws on mount(). Pin the
  // browser condition so the client build is used under jsdom.
  resolve: {
    conditions: ['browser'],
  },
  test: {
    environment: 'jsdom',
    include: ['test/**/*.test.ts'],
    setupFiles: ['./test/setup.ts'],
  },
})
