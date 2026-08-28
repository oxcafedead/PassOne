<script lang="ts">
  import {IsUnlocked, Unlock, AppInfo} from '../wailsjs/go/main/App.js'

  let info: Record<string, string> = {dataDir: '', storePath: '', pgpKey: '', sshKey: '', autoLock: ''}
  let pgpPass: string = ''
  let sshPass: string = ''
  let error: string = ''
  let busy: boolean = false
  let unlocked: boolean = false

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
  }
  load()

  async function submit(): Promise<void> {
    error = ''
    busy = true
    try {
      await Unlock(pgpPass, sshPass)
      unlocked = true
      pgpPass = ''
      sshPass = ''
    } catch (e) {
      error = String(e)
    } finally {
      busy = false
    }
  }
</script>

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

  {#if unlocked}
    <p class="text-lg font-medium text-emerald-400">Unlocked — key material is in memory</p>
  {:else}
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
  {/if}
</main>