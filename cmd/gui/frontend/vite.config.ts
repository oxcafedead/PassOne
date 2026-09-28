import {defineConfig, type Plugin} from 'vite'
import {svelte} from '@sveltejs/vite-plugin-svelte'
import tailwindcss from '@tailwindcss/vite'

// The policy that ships to Wails (index.html) sets `style-src 'self'` with no
// 'unsafe-inline', because `vite build` emits one stylesheet and links it. The
// dev server cannot work that way: it serves CSS as JavaScript and appends
// <style> elements as modules load, which that policy blocks. So the dev
// server rewrites style-src, and only the dev server does.
//
// It has to be a rewrite rather than a second meta tag: a browser enforces
// every policy it finds, so adding a relaxed one cannot relax the strict one.
function devInlineStyleCSP(): Plugin {
  return {
    name: 'passone-dev-inline-style-csp',
    apply: 'serve',
    transformIndexHtml(html) {
      return html.replace("style-src 'self'", "style-src 'self' 'unsafe-inline'")
    }
  }
}

// https://vitejs.dev/config/
export default defineConfig({
  plugins: [svelte(), tailwindcss(), devInlineStyleCSP()]
})
