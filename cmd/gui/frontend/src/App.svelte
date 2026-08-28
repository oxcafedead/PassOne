<script lang="ts">
  import {onMount} from 'svelte'
  import {
    IsUnlocked,
    Unlock,
    AppInfo,
    ListPasswords,
    ShowPassword,
    CopyPassword,
    ClipboardClearSeconds,
  } from '../wailsjs/go/main/App.js'
  import {EventsOn} from '../wailsjs/runtime/runtime.js'

  let info: Record<string, string> = {dataDir: '', storePath: '', pgpKey: '', sshKey: '', autoLock: ''}
  let pgpPass: string = ''
  let sshPass: string = ''
  let error: string = ''
  let busy: boolean = false
  let unlocked: boolean = false

  let entries: string[] = []
  let query: string = ''
  let listing: boolean = false
  let selected: string | null = null
  let detail: string = ''
  let revealed: boolean = false
  let copying: boolean = false
  let clearSeconds: number = 30
  let copiedName: string | null = null
  let copiedRemaining: number = 0
  let copyTimer: ReturnType<typeof setInterval> | null = null

  $: filtered = entries.filter((e) => e.toLowerCase().includes(query.toLowerCase()))

  // Tree model derived from the flat entry paths.
  type Dir = {kind: 'dir'; name: string; path: string; children: Node[]}
  type File = {kind: 'file'; name: string; path: string}
  type Node = Dir | File
  type Row = {node: Node; depth: number}

  let expanded = new Set<string>()
  let expandedInitialized = false

  function buildTree(paths: string[]): Node[] {
    const root: Node[] = []
    const dirs = new Map<string, Dir>()
    for (const p of paths) {
      const parts = p.split('/')
      const name = parts[parts.length - 1]
      let level = root
      let partial = ''
      for (let i = 0; i < parts.length - 1; i++) {
        partial = partial ? partial + '/' + parts[i] : parts[i]
        let d = dirs.get(partial)
        if (!d) {
          d = {kind: 'dir', name: parts[i], path: partial, children: []}
          dirs.set(partial, d)
          level.push(d)
        }
        level = d.children
      }
      level.push({kind: 'file', name, path: p})
    }
    const sortNodes = (ns: Node[]): void => {
      ns.sort((a, b) => {
        if (a.kind !== b.kind) return a.kind === 'dir' ? -1 : 1
        return a.name.localeCompare(b.name)
      })
      for (const n of ns) {
        if (n.kind === 'dir') sortNodes(n.children)
      }
    }
    sortNodes(root)
    return root
  }

  function buildRows(nodes: Node[], expandedSet: Set<string>): Row[] {
    const out: Row[] = []
    const walk = (ns: Node[], depth: number): void => {
      for (const n of ns) {
        out.push({node: n, depth})
        if (n.kind === 'dir' && expandedSet.has(n.path)) {
          walk(n.children, depth + 1)
        }
      }
    }
    walk(nodes, 0)
    return out
  }

  function allDirPaths(nodes: Node[], out: string[]): void {
    for (const n of nodes) {
      if (n.kind === 'dir') {
        out.push(n.path)
        allDirPaths(n.children, out)
      }
    }
  }

  function countsUnder(n: Node): number {
    if (n.kind === 'file') return 1
    let c = 0
    for (const ch of n.children) {
      c += countsUnder(ch)
    }
    return c
  }

  function toggleDir(path: string): void {
    const s = new Set(expanded)
    if (s.has(path)) {
      s.delete(path)
    } else {
      s.add(path)
    }
    expanded = s
  }

  $: tree = buildTree(entries)
  $: rendered = buildRows(tree, expanded)

  async function load(): Promise<void> {
    try {
      unlocked = await IsUnlocked()
    } catch (_) {
      unlocked = false
    }
    try {
      info = await AppInfo()
    } catch (_) {
      // keep defaults
    }
    try {
      clearSeconds = await ClipboardClearSeconds()
    } catch (_) {
      // keep default
    }
    if (unlocked) {
      await refresh()
    }
  }

  async function refresh(): Promise<void> {
    listing = true
    error = ''
    try {
      const keep = selected
      entries = await ListPasswords()
      if (!keep || !entries.includes(keep)) {
        selected = null
      }
      if (!expandedInitialized) {
        const dirs: string[] = []
        allDirPaths(buildTree(entries), dirs)
        expanded = new Set(dirs)
        expandedInitialized = true
      }
      // A refresh never re-decrypts: the selection stays but the content is
      // hidden again until the user asks for it explicitly.
      detail = ''
      revealed = false
    } catch (e) {
      error = String(e)
    } finally {
      listing = false
    }
  }

  // select marks an entry as chosen without decrypting it. The content stays
  // hidden until reveal() is invoked explicitly.
  async function select(name: string): Promise<void> {
    error = ''
    if (selected === name) {
      selected = null
      detail = ''
      revealed = false
      return
    }
    selected = name
    detail = ''
    revealed = false
  }

  // reveal decrypts only the selected entry and renders it. This is the single
  // point where plaintext reaches the DOM; hide() drops it again.
  async function reveal(): Promise<void> {
    if (!selected) {
      return
    }
    error = ''
    try {
      detail = await ShowPassword(selected)
      revealed = true
    } catch (e) {
      detail = ''
      revealed = false
      error = String(e)
    }
  }

  function hide(): void {
    detail = ''
    revealed = false
  }

  async function copySecret(name: string): Promise<void> {
    error = ''
    copying = true
    try {
      await CopyPassword(name)
      copiedName = name
      startCountdown()
    } catch (e) {
      error = String(e)
    } finally {
      copying = false
    }
  }

  function startCountdown(): void {
    stopCountdown()
    copiedRemaining = clearSeconds
    copyTimer = setInterval(() => {
      copiedRemaining -= 1
      if (copiedRemaining <= 0) {
        stopCountdown()
        copiedName = null
      }
    }, 1000)
  }

  function stopCountdown(): void {
    if (copyTimer) {
      clearInterval(copyTimer)
      copyTimer = null
    }
  }

  function onLockEvent(): void {
    unlocked = false
    selected = null
    detail = ''
    revealed = false
    copiedName = null
    error = ''
    stopCountdown()
  }

  async function submit(): Promise<void> {
    error = ''
    busy = true
    try {
      await Unlock(pgpPass, sshPass)
      pgpPass = ''
      sshPass = ''
      await refresh()
    } catch (e) {
      error = String(e)
    } finally {
      busy = false
    }
  }

  onMount(() => {
    void load()
    const offLock = EventsOn('passone:locked', onLockEvent)
    const offUnlock = EventsOn('passone:unlocked', () => {
      unlocked = true
      void refresh()
    })
    return () => {
      offLock()
      offUnlock()
      stopCountdown()
    }
  })
</script>

{#if !unlocked}
  <main class="app-bg flex h-full flex-col items-center justify-center gap-8 px-6 text-main">
    <div class="flex flex-col items-center gap-3">
      <div class="accent-soft flex h-16 w-16 items-center justify-center rounded-2xl">
        <svg xmlns="http://www.w3.org/2000/svg" class="text-accent h-8 w-8" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
          <path stroke-linecap="round" stroke-linejoin="round" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z"/>
        </svg>
      </div>
      <div class="text-center">
        <h1 class="text-main text-xl font-semibold tracking-tight">PassOne</h1>
        <p class="text-faint text-sm">Encrypted passwords for Windows · no gpg, git or ssh needed</p>
      </div>
    </div>

    <dl class="panel ring-panel grid w-full max-w-sm grid-cols-2 gap-x-6 gap-y-1 rounded-xl p-4 text-xs text-faint">
      <dt class="text-mute">Data dir</dt><dd class="truncate text-right">{info.dataDir}</dd>
      <dt class="text-mute">Store</dt><dd class="truncate text-right">{info.storePath}</dd>
      <dt class="text-mute">PGP key</dt><dd class="text-right">{info.pgpKey}</dd>
      <dt class="text-mute">SSH key</dt><dd class="text-right">{info.sshKey}</dd>
      <dt class="text-mute">Auto-lock</dt><dd class="text-right">{info.autoLock}</dd>
    </dl>

    <form class="flex w-full max-w-sm flex-col gap-3" on:submit|preventDefault={submit}>
      <label class="text-faint flex flex-col gap-1 text-xs">
        OpenPGP key passphrase
        <input type="password" bind:value={pgpPass} autocomplete="current-password" placeholder="••••••••" class="input rounded-lg px-3 py-2 text-sm"/>
      </label>
      <label class="text-faint flex flex-col gap-1 text-xs">
        SSH key passphrase
        <input type="password" bind:value={sshPass} placeholder="leave empty if your key has none" class="input rounded-lg px-3 py-2 text-sm"/>
      </label>
      {#if error}
        <p class="text-danger text-xs break-words">{error}</p>
      {/if}
      <button type="submit" disabled={busy} class="btn-accent rounded-lg px-3 py-2 text-sm font-medium">
        {busy ? 'Unlocking…' : 'Unlock'}
      </button>
    </form>
  </main>
{:else}
  <main class="app-bg flex h-full min-h-0 w-full text-main">
    <aside class="flex w-72 shrink-0 flex-col gap-2 border-r border-panel p-3">
      <div class="flex items-center gap-2">
        <input
          bind:value={query}
          placeholder="Search…"
          class="input min-w-0 flex-1 rounded-lg px-3 py-2 text-sm"
        />
        <button
          on:click={refresh}
          title="Refresh list"
          class="btn-ghost rounded-lg px-2.5 py-2"
        >
          <svg xmlns="http://www.w3.org/2000/svg" class="h-4 w-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
            <path stroke-linecap="round" stroke-linejoin="round" d="M4 4v5h5M20 20v-5h-5M4.7 8.6a8 8 0 0115.4-1M19.3 15.4a8 8 0 01-15.4 1"/>
          </svg>
        </button>
      </div>

      {#if error && !selected}
        <p class="text-danger text-xs break-words">{error}</p>
      {/if}

      <nav class="flex-1 overflow-y-auto">
        {#if listing}
          <p class="text-faint mt-2 px-1 text-xs">Loading…</p>
        {:else if query.trim()}
          {#if filtered.length === 0}
            <p class="text-faint mt-2 px-1 text-xs">No matches</p>
          {:else}
            <ul class="flex flex-col gap-0.5">
              {#each filtered as name}
                <li>
                  <button
                    on:click={() => select(name)}
                    class={selected === name
                      ? 'list-item list-item-active flex w-full items-center gap-2 truncate rounded-lg px-3 py-2 text-left text-sm'
                      : 'list-item flex w-full items-center gap-2 truncate rounded-lg px-3 py-2 text-left text-sm'}
                    title={name}
                  >
                    <svg xmlns="http://www.w3.org/2000/svg" class="icon-dim h-3.5 w-3.5 shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
                      <path stroke-linecap="round" stroke-linejoin="round" d="M19 20H5a2 2 0 01-2-2V6a2 2 0 012-2h3l2 2h7a2 2 0 012 2v8h3"/>
                    </svg>
                    <span class="truncate font-mono text-xs">{name}</span>
                  </button>
                </li>
              {/each}
            </ul>
          {/if}
        {:else if rendered.length === 0}
          <p class="text-faint mt-2 px-1 text-xs">No entries</p>
        {:else}
          <ul class="flex flex-col gap-0.5">
            {#each rendered as row (row.node.path + ':' + row.depth)}
              {#if row.node.kind === 'dir'}
                <li>
                  <button
                    on:click={() => toggleDir(row.node.path)}
                    style="padding-left: {8 + row.depth * 14}px"
                    class="list-item flex w-full items-center gap-1.5 rounded-lg px-2 py-1.5 text-left text-sm"
                  >
                    <svg xmlns="http://www.w3.org/2000/svg" class="text-dim h-3 w-3 shrink-0 transition-transform duration-150 {expanded.has(row.node.path) ? 'rotate-90' : ''}" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
                      <path stroke-linecap="round" stroke-linejoin="round" d="M9 5l7 7-7 7"/>
                    </svg>
                    <svg xmlns="http://www.w3.org/2000/svg" class="text-faint h-3.5 w-3.5 shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
                      <path stroke-linecap="round" stroke-linejoin="round" d="M3 7a2 2 0 012-2h4l2 2h8a2 2 0 012 2v8a2 2 0 01-2 2H5a2 2 0 01-2-2V7z"/>
                    </svg>
                    <span class="text-sub truncate font-medium">{row.node.name}</span>
                    <span class="text-dim text-ml ml-auto text-xs">{countsUnder(row.node)}</span>
                  </button>
                </li>
              {:else}
                <li>
                  <button
                    on:click={() => select(row.node.path)}
                    title={row.node.path}
                    style="padding-left: {8 + (row.depth + 1) * 14}px"
                    class={selected === row.node.path
                      ? 'list-item list-item-active flex w-full items-center gap-2 truncate rounded-lg px-2 py-2 text-left text-sm'
                      : 'list-item flex w-full items-center gap-2 truncate rounded-lg px-2 py-2 text-left text-sm'}
                  >
                    <svg xmlns="http://www.w3.org/2000/svg" class="icon-dim h-3.5 w-3.5 shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
                      <path stroke-linecap="round" stroke-linejoin="round" d="M7 21h10a2 2 0 002-2V9.4a2 2 0 00-.59-1.42L15.4 5.17A2 2 0 0013.98 4.6H7a1 1 0 00-1 1V20a1 1 0 001 1zm8-11h-2a3 3 0 00-3 3h5m-5 4h5"/>
                    </svg>
                    <span class="truncate font-mono text-xs">{row.node.name}</span>
                  </button>
                </li>
              {/if}
            {/each}
          </ul>
        {/if}
      </nav>

      <p class="text-dim border-panel border-t px-1 pt-2 text-xs">Auto-lock: {info.autoLock}</p>
    </aside>

    <section class="flex min-w-0 flex-1 flex-col gap-3 p-4">
      {#if selected}
        <header class="flex items-center gap-3">
          <h2 class="text-main min-w-0 truncate font-mono text-sm font-medium">{selected}</h2>
          <span class="flex-1"></span>
          {#if copiedName === selected}
            <span class="badge-success rounded-md px-2 py-1 text-xs">Copied · clears in {copiedRemaining}s</span>
          {/if}
          <button
            data-testid="reveal"
            on:click={revealed ? hide : reveal}
            title={revealed ? 'Drop the clear-text from the page' : 'Decrypt and show this entry'}
            class="btn-ghost flex items-center gap-1.5 rounded-lg px-3 py-1.5 text-sm font-medium"
          >
            {revealed ? 'Hide' : 'Show'}
          </button>
          <button
            on:click={() => copySecret(selected)}
            disabled={copying}
            title="Copy the first line to the clipboard"
            class="btn-accent flex items-center gap-1.5 rounded-lg px-3 py-1.5 text-sm font-medium"
          >
            <svg xmlns="http://www.w3.org/2000/svg" class="h-4 w-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
              <path stroke-linecap="round" stroke-linejoin="round" d="M8 5H6a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2v-1M8 5a2 2 0 002 2h2a2 2 0 002-2M8 5a2 2 0 012-2h2a2 2 0 012 2m0 0h2a2 2 0 012 2v3m2 4H10m0 0l3-3m-3 3l3 3"/>
            </svg>
            {copying ? 'Copying…' : 'Copy'}
          </button>
        </header>
        {#if error}
          <p class="text-danger text-xs break-words">{error}</p>
        {/if}
        {#if detail}
          <pre class="panel ring-panel text-sub min-h-0 flex-1 overflow-auto whitespace-pre-wrap rounded-xl p-4 font-mono text-xs leading-relaxed">{detail}</pre>
        {:else}
          <div class="flex min-h-0 flex-1 flex-col items-center justify-center gap-4 rounded-xl border border-dashed border-panel text-sm text-faint">
            <svg xmlns="http://www.w3.org/2000/svg" class="icon-dim h-8 w-8" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="1.5">
              <path stroke-linecap="round" stroke-linejoin="round" d="M2.58 12.5S5.5 6.5 12 6.5s9.42 6 9.42 6-2.92 6-9.42 6-9.42-6-9.42-6zM15 12a3 3 0 11-6 0 3 3 0 016 0z"/>
            </svg>
            <div class="flex max-w-xs flex-col items-center gap-1 text-center">
              <span class="text-mute">Content is locked.</span>
              <span>It stays encrypted on disk until you explicitly decrypt it.</span>
            </div>
            <button
              data-testid="reveal-empty"
              on:click={reveal}
              class="btn-accent rounded-lg px-4 py-2 text-sm font-medium"
            >
              Show password
            </button>
          </div>
        {/if}
      {:else}
        <div class="text-dim flex flex-1 items-center justify-center text-sm">Select an entry to view it</div>
      {/if}
    </section>
  </main>
{/if}