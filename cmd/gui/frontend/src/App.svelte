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
  <main class="flex h-full flex-col items-center justify-center gap-8 bg-[#12141a] px-6 text-gray-200">
    <div class="flex flex-col items-center gap-3">
      <div class="flex h-16 w-16 items-center justify-center rounded-2xl bg-indigo-500/15 ring-1 ring-indigo-400/30">
        <svg xmlns="http://www.w3.org/2000/svg" class="h-8 w-8 text-indigo-300" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
          <path stroke-linecap="round" stroke-linejoin="round" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z"/>
        </svg>
      </div>
      <div class="text-center">
        <h1 class="text-xl font-semibold tracking-tight text-gray-100">PassOne</h1>
        <p class="text-sm text-gray-500">Encrypted passwords for Windows · no gpg, git or ssh needed</p>
      </div>
    </div>

    <dl class="grid w-full max-w-sm grid-cols-2 gap-x-6 gap-y-1 rounded-xl bg-white/5 p-4 text-xs text-gray-400 ring-1 ring-white/10">
      <dt class="text-gray-500">Data dir</dt><dd class="truncate text-right">{info.dataDir}</dd>
      <dt class="text-gray-500">Store</dt><dd class="truncate text-right">{info.storePath}</dd>
      <dt class="text-gray-500">PGP key</dt><dd class="text-right">{info.pgpKey}</dd>
      <dt class="text-gray-500">SSH key</dt><dd class="text-right">{info.sshKey}</dd>
      <dt class="text-gray-500">Auto-lock</dt><dd class="text-right">{info.autoLock}</dd>
    </dl>

    <form class="flex w-full max-w-sm flex-col gap-3" on:submit|preventDefault={submit}>
      <label class="flex flex-col gap-1 text-xs text-gray-400">
        OpenPGP key passphrase
        <input type="password" bind:value={pgpPass} autocomplete="current-password" placeholder="••••••••" class="rounded-lg bg-white/5 px-3 py-2 text-sm text-gray-100 placeholder-gray-600 outline-none ring-1 ring-white/10 focus:ring-indigo-400/60"/>
      </label>
      <label class="flex flex-col gap-1 text-xs text-gray-400">
        SSH key passphrase
        <input type="password" bind:value={sshPass} placeholder="leave empty if your key has none" class="rounded-lg bg-white/5 px-3 py-2 text-sm text-gray-100 placeholder-gray-600 outline-none ring-1 ring-white/10 focus:ring-indigo-400/60"/>
      </label>
      {#if error}
        <p class="text-xs break-words text-red-400">{error}</p>
      {/if}
      <button type="submit" disabled={busy} class="rounded-lg bg-indigo-500 px-3 py-2 text-sm font-medium text-white transition hover:bg-indigo-400 disabled:opacity-50">
        {busy ? 'Unlocking…' : 'Unlock'}
      </button>
    </form>
  </main>
{:else}
  <main class="flex h-full min-h-0 w-full bg-[#12141a] text-gray-200">
    <aside class="flex w-72 shrink-0 flex-col gap-2 border-r border-white/10 p-3">
      <div class="flex items-center gap-2">
        <input
          bind:value={query}
          placeholder="Search…"
          class="min-w-0 flex-1 rounded-lg bg-white/5 px-3 py-2 text-sm text-gray-100 placeholder-gray-600 outline-none ring-1 ring-white/10 focus:ring-indigo-400/60"
        />
        <button
          on:click={refresh}
          title="Refresh list"
          class="rounded-lg bg-white/5 px-2.5 py-2 text-gray-300 transition hover:bg-white/10 disabled:opacity-50"
        >
          <svg xmlns="http://www.w3.org/2000/svg" class="h-4 w-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
            <path stroke-linecap="round" stroke-linejoin="round" d="M4 4v5h5M20 20v-5h-5M4.7 8.6a8 8 0 0115.4-1M19.3 15.4a8 8 0 01-15.4 1"/>
          </svg>
        </button>
      </div>

      {#if error && !selected}
        <p class="text-xs break-words text-red-400">{error}</p>
      {/if}

      <nav class="flex-1 overflow-y-auto">
        {#if listing}
          <p class="mt-2 px-1 text-xs text-gray-500">Loading…</p>
        {:else if filtered.length === 0}
          <p class="mt-2 px-1 text-xs text-gray-500">No entries</p>
        {:else}
          <ul class="flex flex-col gap-0.5">
            {#each filtered as name}
              <li>
                <button
                  on:click={() => select(name)}
                  class={selected === name
                    ? 'flex w-full items-center gap-2 truncate rounded-lg px-3 py-2 text-left text-sm text-emerald-300 transition hover:bg-white/10 bg-emerald-500/15'
                    : 'flex w-full items-center gap-2 truncate rounded-lg px-3 py-2 text-left text-sm text-gray-300 transition hover:bg-white/10'}
                >
                  <svg xmlns="http://www.w3.org/2000/svg" class="h-3.5 w-3.5 shrink-0 text-gray-600" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
                    <path stroke-linecap="round" stroke-linejoin="round" d="M19 20H5a2 2 0 01-2-2V6a2 2 0 012-2h3l2 2h7a2 2 0 012 2v8h3"/>
                  </svg>
                  <span class="truncate font-mono text-xs">{name}</span>
                </button>
              </li>
            {/each}
          </ul>
        {/if}
      </nav>

      <p class="border-t border-white/10 px-1 pt-2 text-xs text-gray-600">Auto-lock: {info.autoLock}</p>
    </aside>

    <section class="flex min-w-0 flex-1 flex-col gap-3 p-4">
      {#if selected}
        <header class="flex items-center gap-3">
          <h2 class="min-w-0 truncate font-mono text-sm font-medium text-gray-100">{selected}</h2>
          <span class="flex-1"></span>
          {#if copiedName === selected}
            <span class="rounded-md bg-emerald-500/15 px-2 py-1 text-xs text-emerald-300">Copied · clears in {copiedRemaining}s</span>
          {/if}
          <button
            data-testid="reveal"
            on:click={revealed ? hide : reveal}
            title={revealed ? 'Drop the clear-text from the page' : 'Decrypt and show this entry'}
            class="flex items-center gap-1.5 rounded-lg bg-white/5 px-3 py-1.5 text-sm font-medium text-gray-300 transition hover:bg-white/10 ring-1 ring-white/10"
          >
            {revealed ? 'Hide' : 'Show'}
          </button>
          <button
            on:click={() => copySecret(selected)}
            disabled={copying}
            title="Copy the first line to the clipboard"
            class="flex items-center gap-1.5 rounded-lg bg-indigo-500 px-3 py-1.5 text-sm font-medium text-white transition hover:bg-indigo-400 disabled:opacity-50"
          >
            <svg xmlns="http://www.w3.org/2000/svg" class="h-4 w-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
              <path stroke-linecap="round" stroke-linejoin="round" d="M8 5H6a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2v-1M8 5a2 2 0 002 2h2a2 2 0 002-2M8 5a2 2 0 012-2h2a2 2 0 012 2m0 0h2a2 2 0 012 2v3m2 4H10m0 0l3-3m-3 3l3 3"/>
            </svg>
            {copying ? 'Copying…' : 'Copy'}
          </button>
        </header>
        {#if error}
          <p class="text-xs break-words text-red-400">{error}</p>
        {/if}
        {#if detail}
          <pre class="min-h-0 flex-1 overflow-auto whitespace-pre-wrap rounded-xl bg-white/5 p-4 font-mono text-xs leading-relaxed text-gray-300 ring-1 ring-white/10">{detail}</pre>
        {:else}
          <div class="flex min-h-0 flex-1 flex-col items-center justify-center gap-4 rounded-xl border border-dashed border-white/10 text-sm text-gray-500">
            <svg xmlns="http://www.w3.org/2000/svg" class="h-8 w-8 text-gray-700" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="1.5">
              <path stroke-linecap="round" stroke-linejoin="round" d="M2.58 12.5S5.5 6.5 12 6.5s9.42 6 9.42 6-2.92 6-9.42 6-9.42-6-9.42-6zM15 12a3 3 0 11-6 0 3 3 0 016 0z"/>
            </svg>
            <div class="flex max-w-xs flex-col items-center gap-1 text-center">
              <span class="text-gray-400">Content is locked.</span>
              <span>It stays encrypted on disk until you explicitly decrypt it.</span>
            </div>
            <button
              data-testid="reveal-empty"
              on:click={reveal}
              class="rounded-lg bg-indigo-500 px-4 py-2 text-sm font-medium text-white transition hover:bg-indigo-400"
            >
              Show password
            </button>
          </div>
        {/if}
      {:else}
        <div class="flex flex-1 items-center justify-center text-sm text-gray-600">Select an entry to view it</div>
      {/if}
    </section>
  </main>
{/if}