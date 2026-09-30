<script lang="ts">
  import {onMount} from 'svelte'
  import {
    IsUnlocked,
    Unlock,
    AppInfo,
    ListPasswords,
    ShowPassword,
    ShowNotes,
    CopyPassword,
    CopyKeyID,
    CopyUsername,
    CopyTOTP,
    HasTOTP,
    Username,
    ClipboardClearSeconds,
    ClipboardHistoryEnabled,
    CreatePassword,
    UpdatePassword,
    MovePassword,
    RemovePassword,
    RevealPath,
    PickPrivateKey,
    PickStoreDir,
    ImportPGPKeyFile,
    GeneratePGPKey,
    CreateStore,
    DefaultStoreDir,
    ImportSSHKeyFile,
    HasSSHKeyLoaded,
    LoadSSHKey,
    OpenLocalStore,
    StoredStores,
    PrepareClone,
    TrustHost,
    CloneStore,
    CurrentSettings,
    ChangeLockPassword,
    SetAutoLock,
    SetClipboardClear,
    SetGitAuthor,
    SetUsernameSource,
    UsernameSource,
    Status,
    Sync,
    KnownHosts,
  } from '../wailsjs/go/main/App.js'
  import {EventsOn} from '../wailsjs/runtime/runtime.js'

  interface SettingsInfo {
    dataDir: string
    storePath: string
    gitRemote: string
    pgpKeyFingerprint: string
    sshKeyId: string
    autoLockMinutes: number
    clipboardClearSeconds: number
    gitAuthorName: string
    gitAuthorEmail: string
    usernameSource: string
    hasPgp: boolean
    hasSsh: boolean
  }

  interface PickedDlg {
    path: string
    canceled: boolean
  }

  // One row of the lock screen's location list.
  //
  // Each row is either a directory, which the user can open, or a key, which the
  // user can copy by identifier -- never a key file, which is a thing they have
  // no reason to point at. So the two row kinds share one shape and one action
  // slot rather than each carrying a column of its own: label, value, one button.
  interface Location {
    key: string
    label: string
    what: string
    // The value as rendered. A path is middle-elided, a key ID is shown whole.
    text: string
    // The full value, for the hover. Equal to text when nothing was elided.
    title: string
    // The untruncated path, sent to RevealPath. Empty on a key row.
    path: string
    // The kind of key, sent to CopyKeyID. Empty on a directory row.
    kind: string
  }

  interface ClonePrep {
    host: string
    fingerprint: string
    known: boolean
  }

  // The lock screen's environment block. Written only by refreshInfo, so a
  // value never means one thing on the lock screen and another in Settings.
  let info: Record<string, string> = {dataDir: '', storePath: '', pgpKey: '', sshKey: '', autoLock: ''}
  let pgpPass: string = ''
  let sshPass: string = ''
  let lockPass: string = ''
  let error: string = ''
  let busy: boolean = false
  let unlocked: boolean = false

  let entries: string[] = []
  let query: string = ''
  let listing: boolean = false
  // Whether a listing has ever landed. An empty store is a normal state and
  // "No entries" says so, so the loading placeholder must mean "not known yet"
  // rather than "a listing is running": keying it on `listing` alone left an
  // empty store with no honest text to show but "Loading…", because that is the
  // only branch its empty rows can reach. Any listing still in flight when the
  // vault screen painted — which the unlock path starts twice over, once from
  // the event handler and once from the unlock button — then sat there over a
  // list that was never going to grow.
  let listed: boolean = false
  let selected: string | null = null
  let detail: string = ''
  let revealed: boolean = false
  let totpAvailable: boolean = false
  let username: string = ''
  let hasUsername: boolean = false
  let copying: boolean = false
  let copyingUsername: boolean = false
  let copyingTOTP: boolean = false
  let copiedUsernameName: string | null = null
  let copiedUsernameRemaining: number = 0
  let copyUsernameTimer: ReturnType<typeof setInterval> | null = null
  let copiedTOTPName: string | null = null
  let copiedTOTPRemaining: number = 0
  let copyTOTPTimer: ReturnType<typeof setInterval> | null = null
  let clearSeconds: number = 30
  let copiedName: string | null = null
  let copiedRemaining: number = 0
  let copyTimer: ReturnType<typeof setInterval> | null = null

  // Which row last had its key identifier copied, and the timer that takes the
  // tick off it. A fingerprint is not cleared, so this is the only thing that
  // says the copy landed.
  let copiedLoc: string = ''
  let copyLocTimer: ReturnType<typeof setTimeout> | null = null

  // Windows snapshots the clipboard into Clipboard History and the cloud
  // clipboard as an item is set, so the countdown below cannot reach what it
  // already took. The backend marks its copies so Windows skips both stores; if
  // the account has the history switched on, say so rather than implying the
  // countdown is the whole story.
  let clipboardHistory: boolean = false

  type EditingState = {mode: 'add'} | {mode: 'edit'; name: string} | null
  let editing: EditingState = null
  let edName: string = ''
  let edPass: string = ''
  let edConfirm: string = ''
  let edBody: string = ''
  // The notes the dialog was opened with, which is what `edBody` starts as and
  // what a save is compared against: a save that leaves both alone is a no-op
  // here rather than a re-encrypt of identical plaintext, so an untouched Save
  // does not commit the file again for nothing.
  let edOrig: string = ''
  let edBusy: boolean = false
  let edError: string = ''
  // Rename/move dialog. `moving` holds the entry being moved, so the dialog
  // cannot drift from the selection it was opened for, and `mvTarget` starts
  // at the current path so the common case is an edit to the last segment
  // rather than a retype. The backend renames the stored file, so the entry is
  // never re-encrypted and the content cannot change here.
  let moving: string | null = null
  let mvTarget: string = ''
  let mvBusy: boolean = false
  let mvError: string = ''
  let armDelete: boolean = false
  let status: string = ''
  let statusError: boolean = false
  let statusTimer: ReturnType<typeof setTimeout> | null = null

  // Settings / onboarding screen state.
  let settingsOpen: boolean = false
  let sw: SettingsInfo = {
    dataDir: '',
    storePath: '',
    gitRemote: '',
    pgpKeyFingerprint: '',
    sshKeyId: '',
    autoLockMinutes: 0,
    clipboardClearSeconds: 30,
    gitAuthorName: '',
    gitAuthorEmail: '',
    usernameSource: 'auto',
    hasPgp: false,
    hasSsh: false,
  }
  let setupErr: string = ''
  let pgpPicked: string = ''
  let sshPicked: string = ''
  let sshLoaded: boolean = false
  let importBusy: boolean = false
  let openBusy: boolean = false
  let cloneUrl: string = ''
  let cloneBusy: boolean = false
  let clonePrep: ClonePrep | null = null
  let prefsBusy: boolean = false
  let cpwOld: string = ''
  let cpwNew: string = ''
  let cpwConfirm: string = ''
  let cpwBusy: boolean = false
  let cpwErr: string = ''
  let gitText: string = ''
  let gitBusy: boolean = false
  let hosts: string[] = []
  let hostsLoaded: boolean = false
  let localStores: string[] = []
  let onboarding: boolean = false
  let step: number = 0

  // Key generation and store creation. Both are for a machine that has neither a
  // key nor a store yet, which is the state the wizard opens in on a first run.
  let genName: string = ''
  let genEmail: string = ''
  let genPass: string = ''
  let genConfirm: string = ''
  let genBusy: boolean = false
  let newStoreName: string = ''
  let newStorePath: string = ''
  let newStoreRemote: string = ''
  let storeBusy: boolean = false

  // Wizard step names, used both for the heading and for the progress bars'
  // tooltips, so the two can never describe different steps.
  const stepTitles = ['Decryption key', 'Store', 'Preferences']

  function flash(msg: string, isError: boolean = false): void {
    status = msg
    statusError = isError
    if (statusTimer) {
      clearTimeout(statusTimer)
    }
    statusTimer = setTimeout(() => {
      status = ''
    }, isError ? 6000 : 4500)
  }

  $: filtered = entries.filter((e) => e.toLowerCase().includes(query.toLowerCase()))

  // Setup wizard: step 0 requires an OpenPGP key. It comes first because a new
  // store is encrypted to that key, so there is nothing to create in step 1
  // without it. Step 1 requires a store from somewhere: opened, cloned, or
  // created here.
  $: canNext = step === 0
    ? sw.hasPgp && !importBusy && !genBusy
    : step === 1
      ? sw.storePath !== '' && !cloneBusy && !openBusy && !storeBusy
      : true

  // Tree model derived from the flat entry paths.
  type Dir = {kind: 'dir'; name: string; path: string; count: number; children: Node[]}
  type File = {kind: 'file'; name: string; path: string}
  type Node = Dir | File
  type Row = {node: Node; depth: number}

  let tree: Node[] = []
  let rows: Row[] = []
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
          d = {kind: 'dir', name: parts[i], path: partial, count: 0, children: []}
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
    const countFiles = (n: Node): number => {
      if (n.kind === 'file') return 1
      let c = 0
      for (const ch of n.children) c += countFiles(ch)
      n.count = c
      return c
    }
    sortNodes(root)
    for (const n of root) countFiles(n)
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

  // Indentation is a class per depth level, not an inline padding-left: the
  // CSP sets style-src 'self', so a style attribute is dropped by the webview.
  // style.css defines .tree-d0 .. .tree-d12 at 14px per level; anything deeper
  // shares the last step.
  const maxIndentDepth = 12

  function indentClass(depth: number): string {
    return 'tree-d' + Math.min(depth, maxIndentDepth)
  }

  function expandAll(nodes: Node[]): void {
    const dirs: string[] = []
    const collect = (ns: Node[]): void => {
      for (const n of ns) {
        if (n.kind === 'dir') {
          dirs.push(n.path)
          collect(n.children)
        }
      }
    }
    collect(nodes)
    expanded = new Set(dirs)
  }

  function toggleDir(path: string): void {
    const s = new Set(expanded)
    if (s.has(path)) {
      s.delete(path)
    } else {
      s.add(path)
    }
    expanded = s
    rows = buildRows(tree, expanded)
  }

  // expandAncestors opens every folder on the way to an entry, so a row is
  // never invisible while it is the selected one. A move needs this: it can
  // drop an entry into a folder that did not exist a moment ago, and the tree
  // would otherwise render that folder collapsed with the just-renamed entry
  // hidden inside it. refresh() rebuilds the rows from `expanded`, so the
  // folders have to be added before it runs.
  function expandAncestors(p: string): void {
    const parts = p.split('/')
    parts.pop() // the entry itself is a leaf, not a folder to open
    if (parts.length === 0) {
      return
    }
    const s = new Set(expanded)
    for (let i = 1; i <= parts.length; i++) {
      s.add(parts.slice(0, i).join('/'))
    }
    expanded = s
  }

  // The lock screen's environment block comes from exactly one call. Settings
  // used to write three of these fields back with values of a different shape
  // (a store path with no "(none)" in it, a key fingerprint where a presence
  // note belonged), which is how the rows stopped meaning what their labels say.
  async function refreshInfo(): Promise<void> {
    try {
      info = await AppInfo()
    } catch (_) {
      // keep defaults
    }
  }

  async function load(): Promise<void> {
    try {
      unlocked = await IsUnlocked()
    } catch (_) {
      unlocked = false
    }
    await refreshInfo()
    try {
      clearSeconds = await ClipboardClearSeconds()
    } catch (_) {
      // keep default
    }
    try {
      clipboardHistory = (await ClipboardHistoryEnabled()) ?? false
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
        detail = ''
        revealed = false
      }
      tree = buildTree(entries)
      if (!expandedInitialized) {
        expandAll(tree)
        expandedInitialized = true
      }
      rows = buildRows(tree, expanded)
      // If the selected entry still exists, preserve both the selection and
      // the decrypted detail so the user isn't kicked out of the entry they
      // were viewing.
    } catch (e) {
      flash(String(e), true)
    } finally {
      listing = false
      // A listing that failed still answered the question: the list is known,
      // and the error is on screen. Treating that as "still unknown" is what
      // would park the tree on the placeholder for good.
      listed = true
    }
  }

  // adoptStore re-lists after the app has switched which store is open. The rows
  // on screen belong to the store the user just left, and nothing else in the
  // app re-lists on a switch, so a store created here was never shown at all.
  async function adoptStore(): Promise<void> {
    entries = []
    tree = []
    rows = []
    listed = false
    selected = null
    detail = ''
    revealed = false
    // The expanded set still names directories in the old store, so a new store
    // would render every folder collapsed and expandAll would never re-run.
    expandedInitialized = false
    await refresh()
  }

  async function syncAndRefresh(): Promise<void> {
    gitBusy = true
    error = ''
    try {
      const msg = await Sync()
      flash(msg)
      // Remote changes may have altered the selected entry; hide stale content.
      detail = ''
      revealed = false
      await refresh()
      await probeSelected()
    } catch (e) {
      flash(String(e), true)
    } finally {
      gitBusy = false
    }
  }

  // select marks an entry as chosen without decrypting it for display. The
  // content stays hidden until reveal() is invoked explicitly. Selecting still
  // decrypts once in the backend to discover whether the entry carries a TOTP
  // seed or a login, so the matching actions can be shown; the plaintext never
  // reaches the DOM.
  async function select(name: string): Promise<void> {
    error = ''
    armDelete = false
    if (selected === name) {
      selected = null
      detail = ''
      revealed = false
      totpAvailable = false
      username = ''
      hasUsername = false
      return
    }
    selected = name
    detail = ''
    revealed = false
    await probeSelected()
  }

  // probeSelected re-derives the TOTP presence and login of the selected entry
  // by decrypting it in the backend only; nothing is shown to the user.
  async function probeSelected(): Promise<void> {
    if (!selected) {
      totpAvailable = false
      username = ''
      hasUsername = false
      return
    }
    try {
      totpAvailable = (await HasTOTP(selected)) ?? false
    } catch (_) {
      totpAvailable = false
    }
    try {
      username = (await Username(selected)) ?? ''
      hasUsername = username !== ''
    } catch (_) {
      username = ''
      hasUsername = false
    }
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
      flash(String(e), true)
    }
  }

  function hide(): void {
    detail = ''
    revealed = false
  }

  function hasTOTP(body: string): boolean {
    return body.split('\n').some((l) => l.trim().startsWith('otpauth://'))
  }

  // The TOTP action is available as soon as the backend confirms a seed exists,
  // even before the entry's content is revealed. Once revealed, the printed
  // body is authoritative as a fallback.
  $: totpVisible = totpAvailable || (revealed && hasTOTP(detail))

  async function copySecret(name: string): Promise<void> {
    error = ''
    copying = true
    try {
      await CopyPassword(name)
      copiedName = name
      startCountdown()
    } catch (e) {
      flash(String(e), true)
    } finally {
      copying = false
    }
  }

  async function copyUsername(name: string): Promise<void> {
    error = ''
    copyingUsername = true
    try {
      await CopyUsername(name)
      copiedUsernameName = name
      startUsernameCountdown()
    } catch (e) {
      flash(String(e), true)
    } finally {
      copyingUsername = false
    }
  }

  async function copyTOTPCode(name: string): Promise<void> {
    error = ''
    copyingTOTP = true
    try {
      await CopyTOTP(name)
      copiedTOTPName = name
      startTOTPCountdown()
    } catch (e) {
      flash(String(e), true)
    } finally {
      copyingTOTP = false
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

  function startTOTPCountdown(): void {
    stopTOTPCountdown()
    copiedTOTPRemaining = clearSeconds
    copyTOTPTimer = setInterval(() => {
      copiedTOTPRemaining -= 1
      if (copiedTOTPRemaining <= 0) {
        stopTOTPCountdown()
        copiedTOTPName = null
      }
    }, 1000)
  }

  function stopTOTPCountdown(): void {
    if (copyTOTPTimer) {
      clearInterval(copyTOTPTimer)
      copyTOTPTimer = null
    }
  }

  function startUsernameCountdown(): void {
    stopUsernameCountdown()
    copiedUsernameRemaining = clearSeconds
    copyUsernameTimer = setInterval(() => {
      copiedUsernameRemaining -= 1
      if (copiedUsernameRemaining <= 0) {
        stopUsernameCountdown()
        copiedUsernameName = null
      }
    }, 1000)
  }

  function stopUsernameCountdown(): void {
    if (copyUsernameTimer) {
      clearInterval(copyUsernameTimer)
      copyUsernameTimer = null
    }
  }

  // What the countdown badge does and does not promise. Windows snapshots the
  // clipboard into Clipboard History and the cloud clipboard as the item is set,
  // so no clear can reach what those stores already took, and the marker
  // PassOne writes is a request rather than something Windows guarantees.
  function copyBadgeTitle(): string {
    const cleared = 'Removed from the clipboard when the countdown ends.'
    if (!clipboardHistory) {
      return cleared + ' Windows Clipboard History and the cloud clipboard are off for this account.'
    }
    return cleared +
      ' Windows Clipboard History is on: PassOne asks Windows to keep this out of the history and the cloud clipboard, but a copy that was already snapshotted, or a Windows build that ignores the request, is not covered.'
  }

  function onLockEvent(): void {
    unlocked = false
    selected = null
    detail = ''
    revealed = false
    totpAvailable = false
    username = ''
    hasUsername = false
    copiedName = null
    copiedUsernameName = null
    copiedTOTPName = null
    error = ''
    armDelete = false
    closeEdit()
    moving = null
    mvTarget = ''
    mvError = ''
    status = ''
    stopCountdown()
    stopTOTPCountdown()
    stopUsernameCountdown()
    settingsOpen = false
    lockPass = ''
    pgpPass = ''
    sshPass = ''
    cpwOld = ''
    cpwNew = ''
    cpwConfirm = ''
    cpwErr = ''
  }

  async function loadSettings(): Promise<void> {
    try {
      sw = await CurrentSettings()
      await refreshInfo()
    } catch (e) {
      setupErr = String(e)
      flash(setupErr, true)
    }
    try {
      sshLoaded = (await HasSSHKeyLoaded()) ?? false
    } catch (_) {
      sshLoaded = false
    }
    try {
      hostsLoaded = true
      hosts = (await KnownHosts()) ?? []
    } catch (_) {
      hosts = []
    }
    try {
      localStores = (await StoredStores()) ?? []
    } catch (_) {
      localStores = []
    }
  }

  function storeBase(p: string): string {
    return p.split(/[\\/]+/).filter(Boolean).pop() ?? p
  }

  // The lock screen used to be a two-column table whose cells ended in a CSS
  // ellipsis, which cut the tail of every path — the one part of a Windows path
  // that says what it is (PassOne, stores\work) — and had no tooltip at all, so
  // the head was lost too. A path is now middle-elided, which keeps the drive
  // the reader can guess and the tail they cannot, and carries the whole path as
  // its title so a hover reads out what the row had to drop.
  //
  // PATH_BUDGET is a character count rather than a pixel measurement because
  // style-src 'self' means no inline style, and because the value is rendered in
  // a monospace face where a character is a fixed fraction of the font size. It
  // is deliberately under the width the column can actually reach — 32rem of
  // block, less the label and the button and the gaps — so the CSS ellipsis
  // stays a safety net for a path longer than expected rather than the thing
  // that decides what a path looks like.
  const PATH_BUDGET = 44

  function elidePath(p: string): string {
    if (p.length <= PATH_BUDGET) {
      return p
    }
    // Cut the middle, not the end.
    const tail = Math.ceil((PATH_BUDGET - 1) / 2)
    const head = PATH_BUDGET - 1 - tail
    return p.slice(0, head) + '…' + p.slice(p.length - tail)
  }

  function dirLocation(key: string, label: string, what: string, path: string): Location {
    return {
      key,
      label,
      what,
      text: path ? elidePath(path) : '(none)',
      title: path,
      path,
      kind: '',
    }
  }

  function keyLocation(key: string, label: string, kind: string, id: string): Location {
    return {
      key,
      label,
      what: kind === 'pgp' ? 'OpenPGP key' : 'SSH key',
      // A fingerprint is 40 hex characters and an SSH id is shorter, so both
      // fit the value column whole and are never elided: an identifier that is
      // cut is useless, and the point of this row is to be read.
      text: id || 'not imported',
      title: id,
      path: '',
      kind,
    }
  }

  function buildLocations(i: Record<string, string>): Location[] {
    const store = i.storePath === '(none)' ? '' : i.storePath
    return [
      dirLocation('dataDir', 'Data dir', 'data directory', i.dataDir),
      dirLocation('store', 'Store', 'store', store),
      keyLocation('pgpKey', 'PGP key', 'pgp', i.pgpKey),
      keyLocation('sshKey', 'SSH key', 'ssh', i.sshKey),
    ]
  }

  // info is passed in rather than closed over: a reactive statement whose body
  // is a bare call has no visible dependency, so the compiler would never re-run
  // it and the rows would keep rendering the values AppInfo was first asked for.
  $: locations = buildLocations(info)

  function stopLocationCopy(): void {
    if (copyLocTimer) {
      clearTimeout(copyLocTimer)
      copyLocTimer = null
    }
    copiedLoc = ''
  }

  async function copyKeyLoc(loc: Location): Promise<void> {
    // The same test the button's disabled attribute uses. Guarding in the
    // handler too means the row does nothing without an identifier, rather than
    // relying on a disabled button to be unclickable.
    if (!loc.title) {
      return
    }
    try {
      await CopyKeyID(loc.kind)
      stopLocationCopy()
      copiedLoc = loc.key
      copyLocTimer = setTimeout(stopLocationCopy, 1600)
    } catch (e) {
      flash(String(e), true)
    }
  }

  async function openDirLoc(loc: Location): Promise<void> {
    if (!loc.path) {
      return
    }
    try {
      await RevealPath(loc.path)
    } catch (e) {
      flash(String(e), true)
    }
  }

  function openSettings(): void {
    setupErr = ''
    onboarding = false
    void loadSettings()
    settingsOpen = true
  }

  // Landing point when something is unfinished: jump straight into the wizard
  // at the step that still needs work instead of a dead unlock screen.
  //  - no OpenPGP key → step 0 (generate or import one; a store is encrypted to it)
  //  - otherwise a missing store → step 1 (open, clone, or create)
  //  - everything in place → no wizard.
  async function openSettingsIfFirstRun(): Promise<void> {
    await loadSettings()
    let start: number | null = null
    if (!sw.hasPgp) {
      start = 0
    } else if (!sw.storePath) {
      start = 1
    }
    if (start !== null) {
      onboarding = true
      step = start
      settingsOpen = true
    }
  }

  function closeSettings(): void {
    settingsOpen = false
    pgpPicked = ''
    sshPicked = ''
    cloneUrl = ''
    clonePrep = null
    setupErr = ''
    lockPass = ''
    pgpPass = ''
    sshPass = ''
    cpwOld = ''
    cpwNew = ''
    cpwConfirm = ''
    cpwErr = ''
    genName = ''
    genEmail = ''
    genPass = ''
    genConfirm = ''
    newStoreName = ''
    newStorePath = ''
    newStoreRemote = ''
  }

  async function pickPgp(): Promise<void> {
    try {
      const r = await PickPrivateKey('Select your OpenPGP private key (ASCII armored)')
      if (!r.canceled) {
        pgpPicked = r.path
      }
    } catch (e) {
      setupErr = String(e)
      flash(setupErr, true)
    }
  }

  async function pickSsh(): Promise<void> {
    try {
      const r = await PickPrivateKey('Select your SSH private key (OpenSSH format)')
      if (!r.canceled) {
        sshPicked = r.path
      }
    } catch (e) {
      setupErr = String(e)
      flash(setupErr, true)
    }
  }

  async function importPgp(): Promise<void> {
    if (!pgpPicked) {
      setupErr = 'Choose a PGP key file first'
      flash(setupErr, true)
      return
    }
    importBusy = true
    setupErr = ''
    try {
      const msg = await ImportPGPKeyFile(pgpPicked, pgpPass, lockPass)
      pgpPicked = ''
      pgpPass = ''
      lockPass = ''
      flash(msg)
      await loadSettings()
    } catch (e) {
      setupErr = String(e)
      flash(setupErr, true)
    } finally {
      importBusy = false
    }
  }

  // generateKey is the no-gpg path: a machine with no key anywhere gets one
  // here. The passphrase is confirmed because this key is not recoverable from
  // anywhere else once it is sealed -- an imported key still exists as a file
  // the user chose, a generated one exists only in the vault.
  async function generateKey(): Promise<void> {
    if (genEmail.trim() === '') {
      setupErr = 'An email address is required'
      flash(setupErr, true)
      return
    }
    if (genPass === '') {
      setupErr = 'A non-empty passphrase is required for the new key'
      flash(setupErr, true)
      return
    }
    if (genPass !== genConfirm) {
      setupErr = 'The passphrases do not match'
      flash(setupErr, true)
      return
    }
    if (lockPass === '') {
      setupErr = 'A lock password is required to seal the new key'
      flash(setupErr, true)
      return
    }
    genBusy = true
    setupErr = ''
    try {
      const fp = await GeneratePGPKey(genName.trim(), genEmail.trim(), genPass, lockPass)
      genPass = ''
      genConfirm = ''
      lockPass = ''
      flash('Key generated: ' + fp)
      await loadSettings()
    } catch (e) {
      setupErr = String(e)
      flash(setupErr, true)
    } finally {
      genBusy = false
    }
  }

  // resolveNewStorePath turns the folder field into the path the store would be
  // created at, so the user sees where it lands before creating anything. A
  // name with a separator in it comes back empty and the button stays disabled
  // rather than the app inventing a location.
  async function resolveNewStorePath(): Promise<void> {
    const name = newStoreName.trim()
    if (name === '') {
      newStorePath = ''
      setupErr = ''
      return
    }
    try {
      newStorePath = (await DefaultStoreDir(name)) ?? ''
      if (newStorePath === '') {
        setupErr = 'Enter a plain folder name, not a path with separators'
        flash(setupErr, true)
      } else {
        setupErr = ''
      }
    } catch (e) {
      newStorePath = ''
      setupErr = String(e)
      flash(setupErr, true)
    }
  }

  async function createStore(): Promise<void> {
    if (newStorePath === '') {
      setupErr = 'Enter a folder name for the new store'
      flash(setupErr, true)
      return
    }
    storeBusy = true
    setupErr = ''
    try {
      await CreateStore(newStorePath, newStoreRemote.trim())
      flash('Store created: ' + newStorePath)
      newStoreName = ''
      newStorePath = ''
      newStoreRemote = ''
      await loadSettings()
      await adoptStore()
    } catch (e) {
      setupErr = String(e)
      flash(setupErr, true)
    } finally {
      storeBusy = false
    }
  }

  async function importSsh(): Promise<void> {
    if (!sshPicked) {
      setupErr = 'Choose an SSH key file first'
      flash(setupErr, true)
      return
    }
    importBusy = true
    setupErr = ''
    try {
      const msg = await ImportSSHKeyFile(sshPicked, sshPass, lockPass)
      sshPicked = ''
      sshPass = ''
      lockPass = ''
      flash(msg)
      await loadSettings()
    } catch (e) {
      setupErr = String(e)
      flash(setupErr, true)
    } finally {
      importBusy = false
    }
  }

  async function sshLoad(): Promise<void> {
    importBusy = true
    setupErr = ''
    try {
      await LoadSSHKey(lockPass)
      lockPass = ''
      sshPass = ''
      sshLoaded = true
      flash('SSH key loaded')
    } catch (e) {
      setupErr = String(e)
      flash(setupErr, true)
    } finally {
      importBusy = false
    }
  }

  async function openStore(): Promise<void> {
    openBusy = true
    setupErr = ''
    try {
      const r = await PickStoreDir()
      if (r.canceled) {
        return
      }
      await OpenLocalStore(r.path)
      flash('Store opened: ' + r.path)
      await loadSettings()
      await adoptStore()
    } catch (e) {
      setupErr = String(e)
      flash(setupErr, true)
    } finally {
      openBusy = false
    }
  }

  async function useLocalStore(p: string): Promise<void> {
    openBusy = true
    setupErr = ''
    try {
      await OpenLocalStore(p)
      flash('Store opened: ' + p)
      await loadSettings()
      await adoptStore()
    } catch (e) {
      setupErr = String(e)
      flash(setupErr, true)
    } finally {
      openBusy = false
    }
  }

  async function probeClone(): Promise<void> {
    const url = cloneUrl.trim()
    if (!url) {
      setupErr = 'Enter a git SSH URL first (git@host:owner/store.git)'
      flash(setupErr, true)
      return
    }
    cloneBusy = true
    setupErr = ''
    clonePrep = null
    try {
      clonePrep = await PrepareClone(url)
    } catch (e) {
      setupErr = String(e)
      flash(setupErr, true)
    } finally {
      cloneBusy = false
    }
  }

  async function doClone(): Promise<void> {
    if (!sshLoaded) {
      setupErr = 'Load your SSH key with its passphrase first'
      flash(setupErr, true)
      return
    }
    if (!clonePrep) {
      await probeClone()
      return
    }
    cloneBusy = true
    setupErr = ''
    try {
      if (!clonePrep.known) {
        await TrustHost(clonePrep.host)
      }
      const url = cloneUrl.trim()
      await CloneStore(url, '')
      flash('Store cloned and opened')
      clonePrep = null
      cloneUrl = ''
      await loadSettings()
      await adoptStore()
    } catch (e) {
      setupErr = String(e)
      flash(setupErr, true)
    } finally {
      cloneBusy = false
    }
  }

  async function savePrefs(): Promise<void> {
    prefsBusy = true
    setupErr = ''
    try {
      await SetAutoLock(sw.autoLockMinutes)
      await SetClipboardClear(sw.clipboardClearSeconds)
      await SetGitAuthor(sw.gitAuthorName, sw.gitAuthorEmail)
      await SetUsernameSource(sw.usernameSource)
      flash('Settings saved')
      await loadSettings()
    } catch (e) {
      setupErr = String(e)
      flash(setupErr, true)
    } finally {
      prefsBusy = false
    }
  }

  async function finishWizard(): Promise<void> {
    await savePrefs()
    if (setupErr) {
      return
    }
    onboarding = false
    settingsOpen = false
  }

  async function runStatus(): Promise<void> {
    gitBusy = true
    setupErr = ''
    try {
      gitText = await Status()
    } catch (e) {
      setupErr = String(e)
      flash(setupErr, true)
    } finally {
      gitBusy = false
    }
  }

  async function runSync(): Promise<void> {
    gitBusy = true
    setupErr = ''
    try {
      const msg = await Sync()
      flash('Sync complete')
      const st = await Status()
      gitText = msg + '\n\n' + st
      await loadSettings()
    } catch (e) {
      setupErr = String(e)
      flash(setupErr, true)
    } finally {
      gitBusy = false
    }
  }

  async function reloadHosts(): Promise<void> {
    try {
      hostsLoaded = true
      hosts = await KnownHosts()
    } catch (e) {
      setupErr = String(e)
      flash(setupErr, true)
    }
  }

  function closeEdit(): void {
    editing = null
    edName = ''
    edPass = ''
    edConfirm = ''
    // Drop the decrypted notes with the dialog. The field is the only place they
    // exist in the renderer, and a closed dialog is not a reason to keep them.
    edBody = ''
    edOrig = ''
    edError = ''
  }

  function openAdd(): void {
    error = ''
    armDelete = false
    closeEdit()
    editing = {mode: 'add'}
  }

  // Opening the dialog decrypts the entry, because the notes field starts with
  // the entry's current notes: an edit that only changes the password used to
  // have them retyped from the view pane by hand, and one that changed a note
  // replaced the rest. The password is not part of that answer — the dialog's
  // password field stays empty, so an empty field still means "keep the stored
  // secret" — which is why this asks for the notes alone instead of reusing the
  // full-plaintext call the view pane uses.
  async function openEdit(): Promise<void> {
    const name = selected
    if (!name) {
      return
    }
    error = ''
    armDelete = false
    edPass = ''
    edConfirm = ''
    edError = ''
    let notes: string
    try {
      notes = await ShowNotes(name)
    } catch (e) {
      // Refuse to open rather than open an empty box. Nothing here would say the
      // notes failed to load, and an empty notes field now means "delete them",
      // so a save after a failed load would quietly drop what the entry holds.
      flash(String(e), true)
      return
    }
    // The decrypt is awaited, so a lock or a different row picked in the
    // meantime must not leave notes sitting in a dialog about another entry.
    if (selected !== name) {
      return
    }
    edBody = notes
    edOrig = notes
    editing = {mode: 'edit', name}
  }

  function toggleDeleteArm(): void {
    if (armDelete) {
      void deleteEntry()
    } else {
      armDelete = true
    }
  }

  function openMove(): void {
    if (!selected) {
      return
    }
    error = ''
    armDelete = false
    mvTarget = selected
    mvError = ''
    moving = selected
  }

  function closeMove(): void {
    moving = null
    mvError = ''
  }

  async function submitMove(): Promise<void> {
    const from = moving
    if (!from) {
      return
    }
    const to = mvTarget.trim()
    if (to === '') {
      mvError = 'Enter a new password path'
      flash(mvError, true)
      return
    }
    mvBusy = true
    mvError = ''
    try {
      const msg = await MovePassword(from, to)
      closeMove()
      // The name is the entry's identity, so the selection has to follow it,
      // and the decrypted detail belonged to the old path: it is dropped
      // without being shown again, exactly as an edit does.
      selected = to
      detail = ''
      revealed = false
      flash(msg)
      expandAncestors(to)
      await refresh()
      await probeSelected()
    } catch (e) {
      mvError = String(e)
      flash(mvError, true)
    } finally {
      mvBusy = false
    }
  }

  async function submitEdit(): Promise<void> {
    if (!editing) {
      return
    }
    edError = ''
    edBusy = true
    try {
      const keepPassword = edPass.trim() === ''
      if (!keepPassword && edPass !== edConfirm) {
        edError = 'Passwords do not match'
        flash(edError, true)
        return
      }
      if (editing.mode === 'add') {
        const msg = await CreatePassword(edName.trim(), edPass, edConfirm, edBody)
        const created = edName.trim()
        closeEdit()
        flash(msg)
        await refresh()
        await select(created)
      } else {
        const name = editing.name
        if (keepPassword && edBody === edOrig) {
          // The notes are exactly what the entry already holds and no new
          // password was typed. The backend cannot tell this from a real
          // notes-only edit, so the comparison happens here, where what the
          // field opened with is known.
          closeEdit()
          flash('No changes to ' + name)
          return
        }
        const msg = await UpdatePassword(name, edPass.trim(), edBody, keepPassword)
        closeEdit()
        selected = name
        // Never auto-reveal after an edit: only an explicit Show decrypts.
        detail = ''
        revealed = false
        flash(msg)
        await refresh()
        // The edit may have added or removed an otpauth line or a login, and
        // both actions are gated on a probe that ran before the edit. Without
        // this the TOTP and Username buttons keep whatever the entry carried
        // when it was selected, so adding a seed shows no button and removing
        // one leaves a button whose copy call then fails.
        await probeSelected()
      }
    } catch (e) {
      edError = String(e)
      flash(edError, true)
    } finally {
      edBusy = false
    }
  }

  async function deleteEntry(): Promise<void> {
    if (!selected) {
      return
    }
    error = ''
    armDelete = false
    try {
      const gone = selected
      await RemovePassword(gone)
      selected = null
      detail = ''
      revealed = false
      flash(gone + ' removed')
      await refresh()
    } catch (e) {
      flash(String(e), true)
    }
  }

  async function submit(): Promise<void> {
    error = ''
    busy = true
    try {
      await Unlock(lockPass)
      lockPass = ''
      await refresh()
    } catch (e) {
      flash(String(e), true)
    } finally {
      busy = false
    }
  }

  async function changePassword(): Promise<void> {
    cpwErr = ''
    if (cpwNew !== cpwConfirm) {
      cpwErr = 'New password and confirmation do not match'
      flash(cpwErr, true)
      return
    }
    cpwBusy = true
    try {
      await ChangeLockPassword(cpwOld, cpwNew)
      cpwOld = ''
      cpwNew = ''
      cpwConfirm = ''
      flash('Lock password changed')
    } catch (e) {
      cpwErr = String(e)
      flash(cpwErr, true)
    } finally {
      cpwBusy = false
    }
  }

  onMount(() => {
    void load().then(() => void openSettingsIfFirstRun())
    const offLock = EventsOn('passone:locked', onLockEvent)
    const offUnlock = EventsOn('passone:unlocked', () => {
      unlocked = true
      sshLoaded = true
      void refresh()
    })
    // A clipboard clear runs on a timer after the copy call returned, so a
    // failure arrives here rather than as an error the button could show.
    const offWarning = EventsOn('passone:clipboard-warning', (msg: string) => {
      flash(`Clipboard: ${msg}`, true)
    })
    return () => {
      offLock()
      offUnlock()
      offWarning()
      stopCountdown()
      stopTOTPCountdown()
      stopLocationCopy()
      if (statusTimer) {
        clearTimeout(statusTimer)
      }
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

    <!--
      One shared grid, and every row contributes all three of its cells -- the
      auto-lock row included, with an empty action slot. That is what keeps the
      rows in alignment: the columns are defined once by the container, and no
      row can shift or re-size them by having a different number of cells.
      Every cell is h-6, the same height as the button, so the rows are also
      evenly spaced instead of stepping by whatever each row happens to hold.
    -->
    <div class="grid w-full max-w-lg grid-cols-[4.5rem_minmax(0,1fr)_1.5rem] items-center gap-x-2 gap-y-0.5">
      {#each locations as loc (loc.key)}
        <div class="text-faint h-6 truncate text-xs leading-6">{loc.label}</div>
        <span class="text-sub h-6 min-w-0 truncate font-mono text-xs leading-6" title={loc.title}>{loc.text}</span>
        <div class="flex h-6 items-center justify-end">
          {#if loc.kind}
            <button
              on:click={() => copyKeyLoc(loc)}
              title={'Copy the ' + loc.what + ' ID'}
              disabled={!loc.title}
              class="btn-ghost flex h-6 w-6 items-center justify-center rounded disabled:opacity-40"
            >
              {#if copiedLoc === loc.key}
                <svg xmlns="http://www.w3.org/2000/svg" class="text-success h-3.5 w-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2.5">
                  <path stroke-linecap="round" stroke-linejoin="round" d="M5 13l4 4L19 7"/>
                </svg>
              {:else}
                <svg xmlns="http://www.w3.org/2000/svg" class="icon-dim h-3.5 w-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
                  <path stroke-linecap="round" stroke-linejoin="round" d="M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2m0 0h3a1 1 0 011 1v3"/>
                </svg>
              {/if}
            </button>
          {:else}
            <button
              on:click={() => openDirLoc(loc)}
              title={'Open the ' + loc.what + ' in File Explorer'}
              disabled={!loc.path}
              class="btn-ghost flex h-6 w-6 items-center justify-center rounded disabled:opacity-40"
            >
              <svg xmlns="http://www.w3.org/2000/svg" class="icon-dim h-3.5 w-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
                <path stroke-linecap="round" stroke-linejoin="round" d="M3 7a2 2 0 012-2h4l2 2h8a2 2 0 012 2v9a2 2 0 01-2 2H5a2 2 0 01-2-2V7z"/>
              </svg>
            </button>
          {/if}
        </div>
      {/each}
      <div class="text-faint h-6 truncate text-xs leading-6">Auto-lock</div>
      <span class="text-sub h-6 min-w-0 truncate text-xs leading-6">{info.autoLock}</span>
      <div class="h-6"></div>
    </div>

    <form class="flex w-full max-w-sm flex-col gap-3" on:submit|preventDefault={submit}>
      <label class="text-faint flex flex-col gap-1 text-xs">
        Lock password
        <input type="password" bind:value={lockPass} autocomplete="current-password" placeholder="••••••••" class="input rounded-lg px-3 py-2 text-sm"/>
      </label>
      <button type="submit" disabled={busy} class="btn-accent rounded-lg px-3 py-2 text-sm font-medium">
        {busy ? 'Unlocking…' : 'Unlock'}
      </button>
    </form>
  </main>
{:else}
  <main class="app-bg relative flex h-full min-h-0 w-full text-main">
    <div class="flex h-full w-full" class:pointer-events-none={gitBusy} class:opacity-60={gitBusy}>
      <aside class="flex w-72 shrink-0 flex-col gap-2 border-r border-panel p-3">
        <div class="flex items-center gap-2">
        <input
          bind:value={query}
          placeholder="Search…"
          class="input min-w-0 flex-1 rounded-lg px-3 py-2 text-sm"
        />
        <button
          on:click={openAdd}
          title="Add entry"
          class="btn-ghost rounded-lg px-2.5 py-2"
        >
          <svg xmlns="http://www.w3.org/2000/svg" class="h-4 w-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
            <path stroke-linecap="round" stroke-linejoin="round" d="M12 4v16m8-8H4"/>
          </svg>
        </button>
        {#if sw.gitRemote}
          <button
            on:click={syncAndRefresh}
            disabled={gitBusy}
            title="Sync with remote (pull + push)"
            class="btn-ghost rounded-lg px-2.5 py-2"
          >
            <svg xmlns="http://www.w3.org/2000/svg" class="h-4 w-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
              <path stroke-linecap="round" stroke-linejoin="round" d="M7 16V4m0 0L3 8m4-4l4 4m6 0v12m0 0l4-4m-4 4l-4-4"/>
            </svg>
          </button>
        {/if}
        <button
          on:click={refresh}
          disabled={listing}
          title="Refresh list"
          class="btn-ghost rounded-lg px-2.5 py-2"
        >
          <svg xmlns="http://www.w3.org/2000/svg" class="h-4 w-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
            <path stroke-linecap="round" stroke-linejoin="round" d="M4 4v5h5M20 20v-5h-5M4.7 8.6a8 8 0 0115.4-1M19.3 15.4a8 8 0 01-15.4 1"/>
          </svg>
        </button>
      </div>

      <nav class="flex-1 overflow-y-auto">
        <!-- The placeholder means "this store has never been listed", not "a
        listing is running". Keying it on `listing` left a store holding nothing
        with no honest text to show but "Loading…", because an empty row list is
        all it has to render — and the unlock path starts two listings while the
        vault screen paints. rows still holds the previous listing until a new one
        lands, so a populated list is never replaced (GH #33). -->
        {#if !listed && rows.length === 0}
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
                      ? 'entry-row entry-row-active flex w-full items-center gap-2 truncate rounded-lg px-3 py-2 text-left text-sm'
                      : 'entry-row flex w-full items-center gap-2 truncate rounded-lg px-3 py-2 text-left text-sm'}
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
        {:else if rows.length === 0}
          <p class="text-faint mt-2 px-1 text-xs">No entries</p>
        {:else}
          <ul class="flex flex-col gap-0.5">
            {#each rows as row (row.node.kind + ':' + row.node.path + ':' + row.depth)}
              {#if row.node.kind === 'dir'}
                <li>
                  <button
                    on:click={() => toggleDir(row.node.path)}
                    class="entry-row {indentClass(row.depth)} flex w-full min-w-0 flex-nowrap items-center gap-1 overflow-hidden truncate rounded-lg pr-2 py-1.5 text-left text-sm"
                  >
                    <span class="flex shrink-0 items-center justify-center">
                      <svg xmlns="http://www.w3.org/2000/svg" class="text-dim h-3 w-3 shrink-0 transition-transform duration-150 {expanded.has(row.node.path) ? 'rotate-90' : ''}" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
                        <path stroke-linecap="round" stroke-linejoin="round" d="M9 5l7 7-7 7"/>
                      </svg>
                    </span>
                    <span class="flex shrink-0 items-center justify-center">
                      <svg xmlns="http://www.w3.org/2000/svg" class="text-faint h-3.5 w-3.5 shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
                        <path stroke-linecap="round" stroke-linejoin="round" d="M3 7a2 2 0 012-2h4l2 2h8a2 2 0 012 2v8a2 2 0 01-2 2H5a2 2 0 01-2-2V7z"/>
                      </svg>
                    </span>
                    <span class="min-w-0 truncate whitespace-nowrap font-medium">{row.node.name}</span>
                    <span class="shrink-0 whitespace-nowrap text-ml text-right text-xs">{row.node.count}</span>
                  </button>
                </li>
              {:else}
                <li>
                  <button
                    on:click={() => select(row.node.path)}
                    title={row.node.path}
                    class:entry-row-active={selected === row.node.path}
                    class="entry-row {indentClass(row.depth)} flex w-full min-w-0 flex-nowrap items-center gap-1 overflow-hidden truncate rounded-lg pr-2 py-1.5 text-left text-sm"
                  >
                    <span class="flex shrink-0 items-center justify-center"></span>
                    <span class="flex shrink-0 items-center justify-center">
                      <svg xmlns="http://www.w3.org/2000/svg" class="icon-dim h-3.5 w-3.5 shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
                        <path stroke-linecap="round" stroke-linejoin="round" d="M7 21h10a2 2 0 002-2V9.4a2 2 0 00-.59-1.42L15.4 5.17A2 2 0 0013.98 4.6H7a1 1 0 00-1 1V20a1 1 0 001 1zm8-11h-2a3 3 0 00-3 3h5m-5 4h5"/>
                      </svg>
                    </span>
                    <span class="min-w-0 truncate font-mono text-xs">{row.node.name}</span>
                  </button>
                </li>
              {/if}
            {/each}
          </ul>
        {/if}
      </nav>

      <div class="border-panel flex items-center gap-2 border-t px-1 pt-2">
        <p class="text-dim flex-1 text-xs">Auto-lock: {info.autoLock}</p>
        <button
          on:click={openSettings}
          title="Setup / settings"
          class="btn-ghost rounded-lg p-1.5"
        >
          <svg xmlns="http://www.w3.org/2000/svg" class="h-4 w-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
            <path stroke-linecap="round" stroke-linejoin="round" d="M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.065 2.572c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.572 1.065c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.065-2.572c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z"/>
            <path stroke-linecap="round" stroke-linejoin="round" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z"/>
          </svg>
        </button>
      </div>
    </aside>

    <section class="flex min-w-0 flex-1 flex-col gap-3 p-4">
      {#if selected}
        <header class="flex items-center gap-3">
          <h2 class="text-main min-w-0 truncate font-mono text-sm font-medium">{selected}</h2>
          <span class="flex-1"></span>
          {#if copiedUsernameName === selected}
            <span class="badge-success rounded-md px-2 py-1 text-xs" title={copyBadgeTitle()}>Username · clears in {copiedUsernameRemaining}s</span>
          {/if}
          {#if copiedName === selected}
            <span class="badge-success rounded-md px-2 py-1 text-xs" title={copyBadgeTitle()}>Copied · clears in {copiedRemaining}s</span>
          {/if}
          {#if copiedTOTPName === selected}
            <span class="badge-success rounded-md px-2 py-1 text-xs" title={copyBadgeTitle()}>TOTP · clears in {copiedTOTPRemaining}s</span>
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
          {#if totpVisible}
            <button
              on:click={() => copyTOTPCode(selected)}
              disabled={copyingTOTP}
              title="Copy the current TOTP code"
              class="btn-ghost flex items-center gap-1.5 rounded-lg px-3 py-1.5 text-sm font-medium"
            >
              <svg xmlns="http://www.w3.org/2000/svg" class="h-4 w-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
                <path stroke-linecap="round" stroke-linejoin="round" d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z"/>
              </svg>
              {copyingTOTP ? 'Generating…' : 'TOTP'}
            </button>
          {/if}
          {#if hasUsername}
            <button
              on:click={() => copyUsername(selected)}
              disabled={copyingUsername}
              title={'Copy the login: ' + (username || 'no login')}
              class="btn-ghost flex items-center gap-1.5 rounded-lg px-3 py-1.5 text-sm font-medium"
            >
              <svg xmlns="http://www.w3.org/2000/svg" class="h-4 w-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
                <path stroke-linecap="round" stroke-linejoin="round" d="M16 7a4 4 0 11-8 0 4 4 0 018 0zM12 14a7 7 0 00-7 7h14a7 7 0 00-7-7z"/>
              </svg>
              {copyingUsername ? 'Copying…' : 'Username'}
            </button>
          {/if}
          <button
            on:click={openEdit}
            title="Edit this entry"
            class="btn-ghost flex items-center gap-1.5 rounded-lg px-3 py-1.5 text-sm font-medium"
          >
            <svg xmlns="http://www.w3.org/2000/svg" class="h-4 w-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
              <path stroke-linecap="round" stroke-linejoin="round" d="M11 5H6a2 2 0 00-2 2v11a2 2 0 002 2h11a2 2 0 002-2v-5m-1.414-9.414a2 2 0 112.828 2.828L11.828 15H9v-2.828l8.586-8.586z"/>
            </svg>
            Edit
          </button>
          <button
            data-testid="move"
            on:click={openMove}
            title="Rename this entry, or move it into another folder by changing its path"
            class="btn-ghost flex items-center gap-1.5 rounded-lg px-3 py-1.5 text-sm font-medium"
          >
            <svg xmlns="http://www.w3.org/2000/svg" class="h-4 w-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
              <path stroke-linecap="round" stroke-linejoin="round" d="M13 16V6a1 1 0 00-1-1H4a1 1 0 00-1 1v10a1 1 0 001 1h12a1 1 0 001-1zm8-8a1 1 0 00-1-1h-6a1 1 0 00-1 1v10a1 1 0 001 1h6a1 1 0 001-1V8z"/>
            </svg>
            Move
          </button>
          <button
            on:click={toggleDeleteArm}
            title="Delete this entry (asks twice)"
            class={'btn-ghost flex items-center gap-1.5 rounded-lg px-3 py-1.5 text-sm font-medium ' + (armDelete ? 'text-danger' : '')}
          >
            <svg xmlns="http://www.w3.org/2000/svg" class="h-4 w-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
              <path stroke-linecap="round" stroke-linejoin="round" d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16"/>
            </svg>
            {armDelete ? 'Confirm delete?' : 'Delete'}
          </button>
        </header>
        {#if detail}
          <textarea
            readonly
            data-testid="detail"
            spellcheck="false"
            class="detail-area panel ring-panel min-h-0 flex-1 resize-none overflow-auto rounded-xl p-4 font-mono text-xs leading-relaxed"
            value={detail}
          ></textarea>
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
    </div>
    {#if gitBusy}
      <div class="absolute inset-0 z-50 flex items-center justify-center bg-black/10">
        <div class="panel ring-panel flex items-center gap-2 rounded-lg px-4 py-2 text-sm shadow-lg">
          <svg xmlns="http://www.w3.org/2000/svg" class="text-accent h-4 w-4 animate-spin" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
            <path stroke-linecap="round" stroke-linejoin="round" d="M4 4v5h5M20 20v-5h-5M4.7 8.6a8 8 0 0115.4-1M19.3 15.4a8 8 0 01-15.4 1"/>
          </svg>
          Syncing…
        </div>
      </div>
    {/if}
  </main>

  {#if editing}
    <div class="fixed inset-0 z-50 flex items-center justify-center bg-black/45 p-4">
      <form class="panel ring-panel flex w-full max-w-md flex-col gap-3 rounded-xl p-4" on:submit|preventDefault={submitEdit}>
        <h3 class="text-main text-sm font-semibold">
          {editing.mode === 'add' ? 'Add entry' : 'Edit entry'}
        </h3>
        {#if editing.mode === 'add'}
          <label class="text-faint flex flex-col gap-1 text-xs">
            Path
            <input
              bind:value={edName}
              autofocus
              placeholder="folder/example.com"
              class="input rounded-lg px-3 py-2 font-mono text-sm"
            />
          </label>
        {:else}
          <p class="text-faint text-xs break-words">
            Editing: <span class="text-sub font-mono">{editing.name}</span>
          </p>
        {/if}
        <label class="text-faint flex flex-col gap-1 text-xs">
          {editing.mode === 'add' ? 'Password' : 'New password (leave empty to keep current)'}
          <input
            type="password"
            bind:value={edPass}
            autocomplete="new-password"
            placeholder="••••••••"
            class="input rounded-lg px-3 py-2 text-sm"
          />
        </label>
        {#if edPass || editing.mode === 'add'}
          <label class="text-faint flex flex-col gap-1 text-xs">
            Confirm password
            <input
              type="password"
              bind:value={edConfirm}
              autocomplete="new-password"
              placeholder="••••••••"
              class="input rounded-lg px-3 py-2 text-sm"
            />
          </label>
        {/if}
        <label class="text-faint flex flex-col gap-1 text-xs">
          Notes
          <textarea
            data-testid="ed-body"
            bind:value={edBody}
            rows="4"
            placeholder={editing.mode === 'edit' ? 'No notes' : 'usernames, urls, backup codes…'}
            class="input rounded-lg px-3 py-2 font-mono text-xs"
          ></textarea>
        </label>
        {#if editing.mode === 'edit'}
          <p class="text-faint text-xs">
            Notes are shown as they are stored, password line excluded. Saving with the box emptied
            deletes them.
          </p>
        {/if}
        <div class="flex items-center justify-end gap-2">
          <button
            type="button"
            on:click={closeEdit}
            class="btn-ghost rounded-lg px-3 py-2 text-sm"
          >
            Cancel
          </button>
          <button type="submit" disabled={edBusy} class="btn-accent rounded-lg px-3 py-2 text-sm font-medium">
            {edBusy
              ? editing.mode === 'add'
                ? 'Creating…'
                : 'Saving…'
              : editing.mode === 'add'
                ? 'Create'
                : 'Save'}
          </button>
        </div>
      </form>
    </div>
  {/if}

  {#if moving}
    <div class="fixed inset-0 z-50 flex items-center justify-center bg-black/45 p-4">
      <form class="panel ring-panel flex w-full max-w-md flex-col gap-3 rounded-xl p-4" on:submit|preventDefault={submitMove}>
        <h3 class="text-main text-sm font-semibold">Move entry</h3>
        <p class="text-faint text-xs break-words">
          Moving <span class="text-sub font-mono">{moving}</span>
        </p>
        <label class="text-faint flex flex-col gap-1 text-xs">
          New path
          <input
            data-testid="move-target"
            bind:value={mvTarget}
            autofocus
            spellcheck="false"
            placeholder="folder/example.com"
            class="input rounded-lg px-3 py-2 font-mono text-sm"
          />
        </label>
        <p class="text-faint text-xs">
          The stored file is renamed as it is, so nothing is decrypted or re-encrypted. Add a folder to the
          path to move the entry into it.
        </p>
        {#if mvError}
          <p class="text-danger text-xs break-words">{mvError}</p>
        {/if}
        <div class="flex items-center justify-end gap-2">
          <button
            type="button"
            on:click={closeMove}
            class="btn-ghost rounded-lg px-3 py-2 text-sm"
          >
            Cancel
          </button>
          <button type="submit" disabled={mvBusy} class="btn-accent rounded-lg px-3 py-2 text-sm font-medium">
            {mvBusy ? 'Moving…' : 'Move'}
          </button>
        </div>
      </form>
    </div>
  {/if}
{/if}

{#if status}
  <div
    class="fixed right-4 bottom-4 z-[60] rounded-lg px-3 py-2 text-sm {statusError
      ? 'bg-red-500 text-white ring-1 ring-red-500'
      : 'panel ring-panel text-main'}"
  >
    {status}
  </div>
{/if}

{#if settingsOpen}
  <div class="fixed inset-0 z-50 flex items-center justify-center bg-black/45 p-4">
    <div class="panel ring-panel flex max-h-full w-full max-w-2xl flex-col gap-4 overflow-y-auto rounded-xl p-5">
      <div class="flex items-center gap-2">
        <h3 class="text-main flex-1 text-sm font-semibold">
          {onboarding
            ? 'Step ' + (step + 1) + ' of 3 · ' + stepTitles[step]
            : 'Setup & settings'}
        </h3>
        <button on:click={closeSettings} class="btn-ghost rounded-lg px-3 py-1.5 text-sm">Close</button>
      </div>

      {#if onboarding}
        <div class="flex items-center gap-1.5">
          {#each stepTitles as label, i}
            <div
              class={'h-1.5 flex-1 rounded-full ' + (i <= step ? 'accent-soft' : 'panel ring-panel')}
              title={label}
            ></div>
          {/each}
        </div>

        {#if step === 0}
          <section class="flex flex-col gap-2">
            <p class="text-faint text-xs leading-relaxed">
              Encrypted passwords are only readable with the matching OpenPGP secret key of
              the store. Import a key you already have, or generate a new one here — the store
              you create next is encrypted to it, and a generated key exists only in this app.
            </p>

            <label class="text-faint flex flex-col gap-1 text-xs">
              Lock password (protects all stored keys)
              <input type="password" bind:value={lockPass} placeholder="••••••••" class="input rounded-lg px-3 py-2 text-sm"/>
            </label>

            {#if sw.hasPgp}
              <div class="flex items-center gap-2">
                <span class="badge-success rounded-md px-2 py-1 text-xs">PGP key ready</span>
                <span class="text-faint min-w-0 flex-1 truncate font-mono text-xs">{sw.pgpKeyFingerprint}</span>
              </div>
            {:else}
              <h4 class="text-mute mt-1 text-xs font-semibold tracking-wide uppercase">Import an existing key</h4>
              <div class="flex items-center gap-2">
                <button on:click={pickPgp} class="btn-ghost rounded-lg px-3 py-1.5 text-sm">Choose PGP key…</button>
                <span class="text-faint min-w-0 flex-1 truncate text-xs">
                  {pgpPicked || 'No OpenPGP key selected'}
                </span>
              </div>
              <div class="flex flex-col gap-1">
                <span class="text-faint text-xs">Passphrase (empty if your key has none)</span>
                <div class="flex items-center gap-2">
                  <input type="password" bind:value={pgpPass} placeholder="••••••••" class="input min-w-0 flex-1 max-w-[420px] rounded-lg px-3 py-2 text-sm"/>
                  <button
                    on:click={importPgp}
                    disabled={importBusy || !pgpPicked}
                    class="btn-accent rounded-lg px-3 py-2 text-sm"
                  >
                    {importBusy ? 'Importing…' : 'Import'}
                  </button>
                </div>
              </div>

              <h4 class="text-mute mt-2 text-xs font-semibold tracking-wide uppercase">… or generate a new key</h4>
              <div class="grid grid-cols-2 gap-2">
                <label class="text-faint flex flex-col gap-1 text-xs">
                  Name
                  <input bind:value={genName} placeholder="Jane Doe" class="input rounded-lg px-3 py-2 text-sm"/>
                </label>
                <label class="text-faint flex flex-col gap-1 text-xs">
                  Email
                  <input type="email" bind:value={genEmail} placeholder="jane@example.com" class="input rounded-lg px-3 py-2 text-sm"/>
                </label>
              </div>
              <div class="grid grid-cols-2 gap-2">
                <label class="text-faint flex flex-col gap-1 text-xs">
                  Passphrase for the key
                  <input type="password" bind:value={genPass} placeholder="••••••••" class="input rounded-lg px-3 py-2 text-sm"/>
                </label>
                <label class="text-faint flex flex-col gap-1 text-xs">
                  Repeat passphrase
                  <input type="password" bind:value={genConfirm} placeholder="••••••••" class="input rounded-lg px-3 py-2 text-sm"/>
                </label>
              </div>
              <p class="text-faint text-xs leading-relaxed">
                A generated key is stored only in the app's sealed vault. If you lose the
                passphrase, nothing on this machine can decrypt the store again — write it down
                or use an import instead.
              </p>
              <button
                on:click={generateKey}
                disabled={genBusy || genEmail.trim() === '' || genPass === ''}
                class="btn-accent w-fit rounded-lg px-3 py-2 text-sm"
              >
                {genBusy ? 'Generating…' : 'Generate key'}
              </button>
            {/if}
          </section>
        {:else if step === 1}
          <section class="flex flex-col gap-2">
            <p class="text-faint text-xs leading-relaxed">
              Open a store that already exists, create a new one, or clone one over SSH. A new
              store is encrypted to the OpenPGP key from the previous step; an SSH key is only
              needed to reach a remote.
            </p>

            {#if sw.storePath}
              <div class="flex items-center gap-2">
                <span class="badge-success rounded-md px-2 py-1 text-xs">Store ready</span>
                <span class="text-faint min-w-0 flex-1 truncate font-mono text-xs" title={sw.storePath}>
                  {sw.storePath}
                </span>
              </div>
              {#if sw.gitRemote}
                <p class="text-faint truncate text-xs">
                  Remote: <span class="text-sub font-mono">{sw.gitRemote}</span>
                </p>
              {/if}
              <div>
                <button on:click={openStore} disabled={openBusy} class="btn-ghost rounded-lg px-3 py-1.5 text-sm">
                  Open another folder…
                </button>
              </div>
            {:else}
              <h4 class="text-mute mt-1 text-xs font-semibold tracking-wide uppercase">Create a new store</h4>
              <div class="flex flex-col gap-1">
                <label class="text-faint flex flex-col gap-1 text-xs">
                  Folder name
                  <input
                    bind:value={newStoreName}
                    on:blur={resolveNewStorePath}
                    on:keydown={(e) => { if (e.key === 'Enter') { void resolveNewStorePath() } }}
                    placeholder="passwords"
                    class="input rounded-lg px-3 py-2 font-mono text-sm"
                  />
                </label>
                {#if newStorePath !== ''}
                  <p class="text-faint font-mono text-xs break-all">Will be created at {newStorePath}</p>
                {/if}
              </div>
              <label class="text-faint flex flex-col gap-1 text-xs">
                Git remote (optional, not contacted yet)
                <input
                  bind:value={newStoreRemote}
                  placeholder="git@github.com:you/passwords.git"
                  class="input rounded-lg px-3 py-2 font-mono text-sm"
                />
              </label>
              <p class="text-faint text-xs leading-relaxed">
                The folder is created as a git repository whose first commit records the
                recipient key, so the store can be cloned on another machine straight away.
                A remote you enter is recorded, not contacted: the first sync is the push, and
                nothing leaves this machine until you run it.
              </p>
              <button
                on:click={createStore}
                disabled={storeBusy || newStorePath === ''}
                class="btn-accent w-fit rounded-lg px-3 py-2 text-sm"
              >
                {storeBusy ? 'Creating…' : 'Create store'}
              </button>

              <h4 class="text-mute mt-2 text-xs font-semibold tracking-wide uppercase">… or open one that exists</h4>
              <div>
                <button
                  on:click={openStore}
                  disabled={openBusy}
                  class="btn-ghost w-fit rounded-lg px-3 py-1.5 text-sm"
                >
                  {openBusy ? 'Opening…' : 'Open an existing store folder…'}
                </button>
              </div>
              {#if localStores.length > 0}
                <div class="text-mute mt-1 text-xs">Found on this machine:</div>
                <ul class="flex flex-col gap-1">
                  {#each localStores as p}
                    <li>
                      <button
                        on:click={() => useLocalStore(p)}
                        disabled={openBusy}
                        title={p}
                        class="btn-ghost w-full truncate rounded-lg px-3 py-1.5 text-left font-mono text-xs"
                      >
                        {storeBase(p)}
                      </button>
                    </li>
                  {/each}
                </ul>
              {/if}

              <h4 class="text-mute mt-2 text-xs font-semibold tracking-wide uppercase">… or clone one over SSH</h4>
              <input
                bind:value={cloneUrl}
                placeholder="git@github.com:you/passwords.git"
                class="input rounded-lg px-3 py-2 font-mono text-sm"
              />
              {#if clonePrep}
                <p class="text-faint text-xs break-words">
                  Host {clonePrep.host} · {clonePrep.known ? 'already trusted' : 'not yet trusted'} · fingerprint {clonePrep.fingerprint}
                </p>
              {/if}
              <div>
                <button
                  on:click={doClone}
                  disabled={cloneBusy}
                  class="btn-accent rounded-lg px-3 py-2 text-sm"
                >
                  {cloneBusy
                    ? 'Working…'
                    : clonePrep
                      ? clonePrep.known
                        ? 'Clone store'
                        : 'Trust host & clone'
                      : 'Probe host'}
                </button>
              </div>

              {#if !(sw.hasSsh && sshLoaded)}
                <h4 class="text-mute mt-2 text-xs font-semibold tracking-wide uppercase">SSH key (for cloning)</h4>
                <label class="text-faint flex flex-col gap-1 text-xs">
                  Lock password (needed to seal or load the key)
                  <input type="password" bind:value={lockPass} placeholder="••••••••" class="input rounded-lg px-3 py-2 text-sm"/>
                </label>
                {#if sw.hasSsh}
                  <div class="flex items-center gap-2">
                    <span class="badge-success rounded-md px-2 py-1 text-xs">SSH key stored</span>
                    <span class="text-faint min-w-0 flex-1 truncate font-mono text-xs">{sw.sshKeyId}</span>
                  </div>
                  <div class="flex flex-col gap-1">
                    <span class="text-faint text-xs">Passphrase to use the key (empty if your key has none)</span>
                    <div class="flex items-center gap-2">
                      <input type="password" bind:value={sshPass} placeholder="••••••••" class="input min-w-0 flex-1 max-w-[420px] rounded-lg px-3 py-2 text-sm"/>
                      <button
                        on:click={sshLoad}
                        disabled={importBusy}
                        class="btn-accent rounded-lg px-3 py-2 text-sm"
                      >
                        {importBusy ? 'Loading…' : 'Load key'}
                      </button>
                    </div>
                  </div>
                {:else}
                  <div class="flex items-center gap-2">
                    <button on:click={pickSsh} class="btn-ghost rounded-lg px-3 py-1.5 text-sm">Choose SSH key…</button>
                    <span class="text-faint min-w-0 flex-1 truncate text-xs">
                      {sshPicked || 'No SSH key imported'}
                    </span>
                  </div>
                  <div class="flex flex-col gap-1">
                    <span class="text-faint text-xs">Passphrase (empty if your key has none)</span>
                    <div class="flex items-center gap-2">
                      <input type="password" bind:value={sshPass} placeholder="••••••••" class="input min-w-0 flex-1 max-w-[420px] rounded-lg px-3 py-2 text-sm"/>
                      <button
                        on:click={importSsh}
                        disabled={importBusy || !sshPicked}
                        class="btn-accent rounded-lg px-3 py-2 text-sm"
                      >
                        {importBusy ? 'Importing…' : 'Import'}
                      </button>
                    </div>
                  </div>
                {/if}
              {/if}
            {/if}
          </section>
        {:else}
          <section class="flex flex-col gap-2">
            <p class="text-faint text-xs leading-relaxed">
              One last step — these are optional and can be changed later from Setup.
            </p>
            <div class="grid grid-cols-2 gap-2">
              <label class="text-faint flex flex-col gap-1 text-xs">
                Auto-lock after (minutes, 0 = never)
                <input type="number" min="0" bind:value={sw.autoLockMinutes} class="input rounded-lg px-3 py-2 text-sm"/>
              </label>
              <label class="text-faint flex flex-col gap-1 text-xs">
                Clear clipboard after (seconds)
                <input type="number" min="1" bind:value={sw.clipboardClearSeconds} class="input rounded-lg px-3 py-2 text-sm"/>
              </label>
            </div>
            <p class="text-faint text-xs leading-relaxed">
              Copied secrets are marked so Windows keeps them out of Clipboard History and the cloud clipboard,
              which snapshot an item the moment it is copied. That marker is a request Windows may ignore, so the
              countdown above is the only part PassOne can guarantee.
              {#if clipboardHistory}
                <span class="text-danger">Clipboard history is on for this account</span>: turn it off in Windows
                Settings, System, Clipboard if a copy you cannot retract is not acceptable.
              {/if}
            </p>
            <div class="grid grid-cols-2 gap-2">
              <label class="text-faint flex flex-col gap-1 text-xs">
                Git author name
                <input bind:value={sw.gitAuthorName} class="input rounded-lg px-3 py-2 text-sm"/>
              </label>
              <label class="text-faint flex flex-col gap-1 text-xs">
                Git author email
                <input type="email" bind:value={sw.gitAuthorEmail} class="input rounded-lg px-3 py-2 text-sm"/>
              </label>
            </div>
            <label class="text-faint flex flex-col gap-1 text-xs">
              Where the login (username) comes from
              <select bind:value={sw.usernameSource} class="input rounded-lg px-3 py-2 text-sm">
                <option value="auto">Body field, fall back to file name</option>
                <option value="body">Body field only</option>
                <option value="filename">File name only</option>
              </select>
            </label>
          </section>
        {/if}

        <div class="mt-1 flex items-center justify-between gap-2">
          <button
            on:click={() => {
              step = Math.max(0, step - 1)
              setupErr = ''
            }}
            disabled={step === 0}
            class="btn-ghost rounded-lg px-3 py-2 text-sm"
          >
            Back
          </button>
          {#if step < 2}
            <button
              on:click={() => {
                setupErr = ''
                step += 1
              }}
              disabled={!canNext}
              class="btn-accent rounded-lg px-3 py-2 text-sm font-medium"
            >
              Next
            </button>
          {:else}
            <button
              on:click={finishWizard}
              disabled={prefsBusy}
              class="btn-accent rounded-lg px-3 py-2 text-sm font-medium"
            >
              {prefsBusy ? 'Saving…' : 'Finish'}
            </button>
          {/if}
        </div>
      {:else if unlocked}
      <section class="flex flex-col gap-2">
        <h4 class="text-mute text-xs font-semibold tracking-wide uppercase">Your keys</h4>
        <label class="text-faint flex flex-col gap-1 text-xs">
          Lock password (protects all stored keys)
          <input type="password" bind:value={lockPass} placeholder="••••••••" class="input rounded-lg px-3 py-2 text-sm"/>
        </label>
        <div class="flex items-center gap-2">
          <button on:click={pickPgp} class="btn-ghost rounded-lg px-3 py-1.5 text-sm">Choose PGP key…</button>
          <span class="text-faint min-w-0 flex-1 truncate text-xs">
            {#if pgpPicked}
              {pgpPicked}
            {:else if sw.hasPgp}
              Imported: {sw.pgpKeyFingerprint}
            {:else}
              No OpenPGP key imported
            {/if}
          </span>
        </div>
        <div class="flex flex-col gap-2">
          <label class="text-faint flex flex-1 flex-col gap-1 text-xs">
            PGP passphrase (leave empty if your key has none)
            <input type="password" bind:value={pgpPass} placeholder="••••••••" class="input rounded-lg px-3 py-2 text-sm"/>
          </label>
          <button
            on:click={importPgp}
            disabled={importBusy || !pgpPicked}
            class="btn-accent rounded-lg px-3 py-2 text-sm"
          >
            {importBusy ? 'Importing…' : 'Import PGP key'}
          </button>
        </div>
        {#if !sw.hasPgp}
          <h4 class="text-mute mt-1 text-xs font-semibold tracking-wide uppercase">… or generate a new key</h4>
          <div class="grid grid-cols-2 gap-2">
            <label class="text-faint flex flex-col gap-1 text-xs">
              Name
              <input bind:value={genName} placeholder="Jane Doe" class="input rounded-lg px-3 py-2 text-sm"/>
            </label>
            <label class="text-faint flex flex-col gap-1 text-xs">
              Email
              <input type="email" bind:value={genEmail} placeholder="jane@example.com" class="input rounded-lg px-3 py-2 text-sm"/>
            </label>
          </div>
          <div class="grid grid-cols-2 gap-2">
            <label class="text-faint flex flex-col gap-1 text-xs">
              Passphrase for the key
              <input type="password" bind:value={genPass} placeholder="••••••••" class="input rounded-lg px-3 py-2 text-sm"/>
            </label>
            <label class="text-faint flex flex-col gap-1 text-xs">
              Repeat passphrase
              <input type="password" bind:value={genConfirm} placeholder="••••••••" class="input rounded-lg px-3 py-2 text-sm"/>
            </label>
          </div>
          <p class="text-faint text-xs leading-relaxed">
            A generated key is stored only in the app's sealed vault, so if the passphrase is
            lost nothing on this machine can decrypt the store again.
          </p>
          <button
            on:click={generateKey}
            disabled={genBusy || genEmail.trim() === '' || genPass === ''}
            class="btn-accent w-fit rounded-lg px-3 py-2 text-sm"
          >
            {genBusy ? 'Generating…' : 'Generate key'}
          </button>
        {/if}
        <div class="flex items-center gap-2 pt-1">
          <button on:click={pickSsh} class="btn-ghost rounded-lg px-3 py-1.5 text-sm">Choose SSH key…</button>
          <span class="text-faint min-w-0 flex-1 truncate text-xs">
            {#if sshPicked}
              {sshPicked}
            {:else if sw.hasSsh}
              Imported: {sw.sshKeyId}
            {:else}
              No SSH key imported
            {/if}
          </span>
        </div>
        <div class="flex flex-col gap-2">
          <label class="text-faint flex flex-1 flex-col gap-1 text-xs">
            SSH passphrase (leave empty if your key has none)
            <input type="password" bind:value={sshPass} placeholder="••••••••" class="input rounded-lg px-3 py-2 text-sm"/>
          </label>
          <button
            on:click={importSsh}
            disabled={importBusy || !sshPicked}
            class="btn-accent rounded-lg px-3 py-2 text-sm"
          >
            {importBusy ? 'Importing…' : 'Import SSH key'}
          </button>
        </div>
      </section>

      <section class="flex flex-col gap-2">
        <h4 class="text-mute text-xs font-semibold tracking-wide uppercase">Store</h4>
        <p class="text-faint truncate text-xs">
          Current store: <span class="text-sub font-mono">{sw.storePath || '(none)'}</span>
        </p>
        {#if sw.gitRemote}
          <p class="text-faint truncate text-xs">
            Remote: <span class="text-sub font-mono">{sw.gitRemote}</span>
          </p>
        {/if}
        <button
          on:click={openStore}
          disabled={openBusy}
          class="btn-ghost rounded-lg px-3 py-1.5 text-sm"
        >
          {openBusy ? 'Opening…' : 'Open an existing store folder…'}
        </button>
        {#if localStores.length > 0}
          <div class="text-mute mt-1 text-xs">Found on this machine:</div>
          <ul class="flex flex-col gap-1">
            {#each localStores as p}
              <li>
                <button
                  on:click={() => useLocalStore(p)}
                  disabled={openBusy}
                  title={p}
                  class="btn-ghost w-full truncate rounded-lg px-3 py-1.5 text-left font-mono text-xs"
                >
                  {storeBase(p)}
                </button>
              </li>
            {/each}
          </ul>
        {/if}
        <div class="text-faint mt-1 text-xs">… or clone one over SSH:</div>
        <input
          bind:value={cloneUrl}
          placeholder="git@github.com:you/passwords.git"
          class="input rounded-lg px-3 py-2 font-mono text-sm"
        />
        {#if clonePrep}
          <p class="text-faint text-xs break-words">
            Host {clonePrep.host} · {clonePrep.known ? 'already trusted' : 'not yet trusted'} · fingerprint {clonePrep.fingerprint}
          </p>
        {/if}
        <button
          on:click={doClone}
          disabled={cloneBusy}
          class="btn-accent rounded-lg px-3 py-2 text-sm"
        >
          {cloneBusy
            ? 'Working…'
            : clonePrep
              ? clonePrep.known
                ? 'Clone store'
                : 'Trust host & clone'
              : 'Probe host'}
        </button>
      </section>

      <section class="flex flex-col gap-2">
        <h4 class="text-mute text-xs font-semibold tracking-wide uppercase">Create a new store</h4>
        <p class="text-faint text-xs leading-relaxed">
          A new store is a git repository encrypted to your OpenPGP key, and becomes the
          active store. A remote you enter is recorded, not contacted: the first sync is the
          push.
        </p>
        <label class="text-faint flex flex-col gap-1 text-xs">
          Folder name
          <input
            bind:value={newStoreName}
            on:blur={resolveNewStorePath}
            on:keydown={(e) => { if (e.key === 'Enter') { void resolveNewStorePath() } }}
            placeholder="passwords"
            class="input rounded-lg px-3 py-2 font-mono text-sm"
          />
        </label>
        {#if newStorePath !== ''}
          <p class="text-faint font-mono text-xs break-all">Will be created at {newStorePath}</p>
        {/if}
        <label class="text-faint flex flex-col gap-1 text-xs">
          Git remote (optional)
          <input
            bind:value={newStoreRemote}
            placeholder="git@github.com:you/passwords.git"
            class="input rounded-lg px-3 py-2 font-mono text-sm"
          />
        </label>
        <button
          on:click={createStore}
          disabled={storeBusy || newStorePath === ''}
          class="btn-accent w-fit rounded-lg px-3 py-2 text-sm"
        >
          {storeBusy ? 'Creating…' : 'Create store'}
        </button>
      </section>

      <section class="flex flex-col gap-2">
        <h4 class="text-mute text-xs font-semibold tracking-wide uppercase">Preferences</h4>
        <div class="grid grid-cols-2 gap-2">
          <label class="text-faint flex flex-col gap-1 text-xs">
            Auto-lock after (minutes, 0 = never)
            <input type="number" min="0" bind:value={sw.autoLockMinutes} class="input rounded-lg px-3 py-2 text-sm"/>
          </label>
          <label class="text-faint flex flex-col gap-1 text-xs">
            Clear clipboard after (seconds)
            <input type="number" min="1" bind:value={sw.clipboardClearSeconds} class="input rounded-lg px-3 py-2 text-sm"/>
          </label>
        </div>
        <p class="text-faint text-xs leading-relaxed">
          Copied secrets are marked so Windows keeps them out of Clipboard History and the cloud clipboard,
          which snapshot an item the moment it is copied. That marker is a request Windows may ignore, so the
          countdown above is the only part PassOne can guarantee.
          {#if clipboardHistory}
            <span class="text-danger">Clipboard history is on for this account</span>: turn it off in Windows
            Settings, System, Clipboard if a copy you cannot retract is not acceptable.
          {/if}
        </p>
        <label class="text-faint flex flex-col gap-1 text-xs">
          Username source
          <select bind:value={sw.usernameSource} class="input rounded-lg px-3 py-2 text-sm">
            <option value="auto">Body field, fall back to file name</option>
            <option value="body">Body field only</option>
            <option value="filename">File name only</option>
          </select>
        </label>
        <div class="grid grid-cols-2 gap-2">
          <label class="text-faint flex flex-col gap-1 text-xs">
            Git author name
            <input bind:value={sw.gitAuthorName} class="input rounded-lg px-3 py-2 text-sm"/>
          </label>
          <label class="text-faint flex flex-col gap-1 text-xs">
            Git author email
            <input type="email" bind:value={sw.gitAuthorEmail} class="input rounded-lg px-3 py-2 text-sm"/>
          </label>
        </div>
        <button
          on:click={savePrefs}
          disabled={prefsBusy}
          class="btn-accent rounded-lg px-3 py-2 text-sm"
        >
          {prefsBusy ? 'Saving…' : 'Save preferences'}
        </button>
      </section>

      <section class="flex flex-col gap-2">
        <h4 class="text-mute text-xs font-semibold tracking-wide uppercase">Lock password</h4>
        <p class="text-faint text-xs">The lock password protects every stored key. Changing it re-seals all of them.</p>
        <input
          type="password"
          bind:value={cpwOld}
          placeholder="Current lock password"
          autocomplete="current-password"
          class="input rounded-lg px-3 py-2 text-sm"
        />
        <input
          type="password"
          bind:value={cpwNew}
          placeholder="New lock password"
          autocomplete="new-password"
          class="input rounded-lg px-3 py-2 text-sm"
        />
        <input
          type="password"
          bind:value={cpwConfirm}
          placeholder="Confirm new lock password"
          autocomplete="new-password"
          class="input rounded-lg px-3 py-2 text-sm"
        />
        <button
          on:click={changePassword}
          disabled={cpwBusy || !cpwOld || !cpwNew || !cpwConfirm}
          class="btn-accent rounded-lg px-3 py-2 text-sm"
        >
          {cpwBusy ? 'Changing…' : 'Change lock password'}
        </button>
      </section>

      <section class="flex flex-col gap-2">
        <h4 class="text-mute text-xs font-semibold tracking-wide uppercase">Git tools</h4>
        {#if sw.storePath}
          <div class="flex items-center gap-2">
            <button on:click={runStatus} disabled={gitBusy} class="btn-ghost rounded-lg px-3 py-1.5 text-sm">
              Status
            </button>
            {#if sw.gitRemote}
              <button on:click={runSync} disabled={gitBusy} class="btn-accent rounded-lg px-3 py-1.5 text-sm">
                {gitBusy ? 'Working…' : 'Sync (pull + push)'}
              </button>
            {/if}
          </div>
          {#if gitText}
            <pre class="panel ring-panel text-sub max-h-40 overflow-auto whitespace-pre-wrap rounded-lg p-2 font-mono text-[11px] leading-relaxed">{gitText}</pre>
          {/if}
          <div class="flex items-center gap-2">
            <button on:click={reloadHosts} class="btn-ghost rounded-lg px-3 py-1.5 text-sm">
              Refresh known hosts
            </button>
            {#if hostsLoaded && hosts.length > 0}
              <span class="text-faint truncate text-xs">{hosts.length} host(s) trusted</span>
            {/if}
          </div>
          {#if hostsLoaded && hosts.length > 0}
            <pre class="panel ring-panel text-faint max-h-32 overflow-auto whitespace-pre-wrap rounded-lg p-2 font-mono text-[11px]">{hosts.join('\n')}</pre>
          {/if}
        {:else}
          <p class="text-faint text-xs">Open or clone a store first.</p>
        {/if}
      </section>

      {:else}
        <p class="text-faint text-sm">Unlock PassOne to change settings.</p>
      {/if}
    </div>
  </div>
{/if}