import {render, screen, waitFor, fireEvent, within} from '@testing-library/svelte'
import {tick} from 'svelte'
import {describe, expect, it} from 'vitest'
import App from '../src/App.svelte'
import {bridge} from './bridge'
import {emit} from './runtime'

const {
  AppInfo,
  ClipboardHistoryEnabled,
  CopyPassword,
  CopyKeyID,
  CreatePassword,
  CreateStore,
  CurrentSettings,
  DefaultStoreDir,
  GeneratePGPKey,
  HasTOTP,
  IsUnlocked,
  ListPasswords,
  MovePassword,
  RemovePassword,
  RevealPath,
  ShowNotes,
  ShowPassword,
  Unlock,
  UpdatePassword,
  Username,
} = bridge

// One entry, already unlocked, already listed. Each test overrides only what it
// cares about.
function vault(entry = 'github/personal', plaintext = 'hunter2\nrecovery codes'): void {
  IsUnlocked.mockResolvedValue(true)
  ListPasswords.mockResolvedValue([entry])
  ShowPassword.mockResolvedValue(plaintext)
  // The edit dialog's notes come out of the same entry content with the password
  // line dropped, which is the rule the Go side applies, so a test that changes
  // the fixture changes both.
  ShowNotes.mockResolvedValue(plaintext.split('\n').slice(1).join('\n'))
}

function locked(): void {
  IsUnlocked.mockResolvedValue(false)
}

// A promise plus its resolver, so a test can hold a bridge call open and assert
// what the UI shows while it is still in flight. Every mock resolves immediately,
// which hides the window where `listing` is true.
function deferred<T>(): {promise: Promise<T>; resolve: (v: T) => void} {
  let resolve!: (v: T) => void
  const promise = new Promise<T>((r) => {
    resolve = r
  })
  return {promise, resolve}
}

async function selectEntry(entry = 'github/personal'): Promise<void> {
  await waitFor(() => screen.getByTitle(entry))
  await fireEvent.click(screen.getByTitle(entry))
  await screen.findByRole('heading', {level: 2, name: entry})
}

// Selecting an entry awaits a probe, but the heading it renders first appears
// while that probe is still in flight, so an assertion about a button the probe
// gates can pass or fail on timing alone. Wait for the probe to land and for the
// DOM to be flushed, and only then read the button.
async function probeSettled(): Promise<void> {
  await waitFor(() => expect(HasTOTP).toHaveBeenCalled())
  await waitFor(() => expect(Username).toHaveBeenCalled())
  await tick()
}

// The lock screen's location list is one shared grid: every row contributes
// exactly three cells, in the order label, value, action. Anchoring on the label
// cell and walking forward keeps an assertion about one row from silently
// reading another, and the fact that the count is always three is the same
// property that keeps the real rows aligned.
type Cell = 'value' | 'action'

function locationCell(label: string, cell: Cell): HTMLElement {
  const at = cell === 'value' ? 1 : 2
  let node: Element | null = screen.getByText(label)
  for (let i = 0; i < at && node; i++) {
    node = node.nextElementSibling
  }
  if (!node) {
    throw new Error(`the ${label} row has no ${cell} cell`)
  }
  return node as HTMLElement
}

// The value cell carries the full value as its title, which is what a hover
// reads out and what makes a path cut on screen recoverable.
function locationValue(label: string): HTMLElement {
  return locationCell(label, 'value')
}

// A vault big enough that the sidebar list overflows and can actually be
// scrolled: one folder plus one entry per index, so a row is deleted well above
// the fold and the list stays long enough to keep the offset meaningful.
function bigVault(count: number): string[] {
  return Array.from({length: count}, (_, i) => `folder${i}/entry${i}`)
}

// jsdom has no layout engine, so a scrollTop set here is stored and returned
// unchanged even after the content that justified it is removed: asserting it
// would pass against the very bug this guards. Model the one rule that bites in
// a real webview instead — scrollTop cannot exceed scrollHeight - clientHeight,
// so it is clamped back when the scroller is left with less content than the
// offset needs. Rows are a fixed height, so the row count stands in for pixels.
const ROW_PX = 32

function modelScrollClamping(nav: HTMLElement, visibleRows: number): void {
  new MutationObserver(() => {
    const reachable = Math.max(0, nav.querySelectorAll('li').length - visibleRows) * ROW_PX
    if (nav.scrollTop > reachable) {
      nav.scrollTop = reachable
    }
  }).observe(nav, {childList: true, subtree: true})
}

describe('lock screen', () => {
  it('shows where the store lives and calls Unlock with the typed password', async () => {
    locked()
    ClipboardHistoryEnabled.mockResolvedValue(false)
    render(App)

    await screen.findByRole('button', {name: 'Unlock'})
    expect(screen.getByRole('heading', {name: 'PassOne'})).toBeInTheDocument()
    // The lock screen renders before AppInfo has answered, so wait for it.
    await waitFor(() =>
      expect(locationValue('Data dir')).toHaveTextContent(
        'C:\\Users\\tester\\AppData\\Local\\PassOne',
      ),
    )

    // Nothing from the vault is reachable before the lock is open.
    expect(screen.queryByTitle('Add entry')).not.toBeInTheDocument()
    expect(screen.queryByRole('button', {name: 'Edit'})).not.toBeInTheDocument()

    const field = screen.getByLabelText('Lock password')
    await fireEvent.input(field, {target: {value: 'correct horse'}})
    await fireEvent.click(screen.getByRole('button', {name: 'Unlock'}))

    await waitFor(() => expect(Unlock).toHaveBeenCalledWith('correct horse'))
  })

  it('keeps every path whole: the full value is on the row and in its title', async () => {
    locked()
    render(App)

    // Issue #36: the lock screen cut the data dir and store paths with a CSS
    // ellipsis and gave those two rows no title at all, so the identifying tail
    // was on screen and the rest was nowhere. Every row now carries the whole
    // path in the title, which is what a hover reads out.
    const dirs = [
      ['Data dir', 'C:\\Users\\tester\\AppData\\Local\\PassOne'],
      ['Store', 'C:\\Users\\tester\\AppData\\Local\\PassOne\\store'],
    ] as const
    for (const [label, full] of dirs) {
      await waitFor(() => expect(locationValue(label)).toHaveAttribute('title', full))
    }

    // The key rows name the key, not the file it is sealed in: a user confirms a
    // fingerprint and never needs the path of a sealed key.
    expect(locationValue('PGP key')).toHaveTextContent(
      '0xDEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEF',
    )
    expect(locationValue('SSH key')).toHaveTextContent('not imported')
    for (const label of ['PGP key', 'SSH key']) {
      expect(screen.queryByTitle(`Open the ${label} in File Explorer`)).not.toBeInTheDocument()
    }
  })

  it('gives a directory an open action and a key a copy action, never both', async () => {
    locked()
    render(App)

    // A directory is somewhere to go, and the user is expected to recognise it
    // from a path -- so it opens. A key is an identifier, and the thing to do
    // with an identifier is paste it somewhere.
    expect(screen.getByTitle('Open the data directory in File Explorer')).toBeInTheDocument()
    expect(screen.getByTitle('Open the store in File Explorer')).toBeInTheDocument()
    expect(screen.queryByTitle('Copy the data directory path')).not.toBeInTheDocument()
    expect(screen.getByTitle('Copy the OpenPGP key ID')).toBeInTheDocument()
    expect(screen.getByTitle('Copy the SSH key ID')).toBeInTheDocument()
    expect(screen.queryByTitle('Open the OpenPGP key in File Explorer')).not.toBeInTheDocument()
  })

  it('lines every row up in the same three columns', async () => {
    locked()
    render(App)
    await waitFor(() =>
      expect(locationValue('Data dir')).toHaveAttribute(
        'title',
        'C:\\Users\\tester\\AppData\\Local\\PassOne',
      ),
    )

    // The auto-lock row is not part of the each block, so it is the one row that
    // could drift out of alignment: it has to contribute all three cells like
    // every other, and every cell has to be the same height as the button in it.
    const labels = ['Data dir', 'Store', 'PGP key', 'SSH key', 'Auto-lock']
    const rows = labels.map((label) => {
      const labelCell = screen.getByText(label)
      const value = labelCell.nextElementSibling as HTMLElement
      const action = value?.nextElementSibling as HTMLElement
      expect(action, `the ${label} row has no action cell`).not.toBeNull()
      return [labelCell, value, action] as const
    })
    // Every row is the same shape, and every cell is the same height, so nothing
    // can sit lower than its neighbours.
    for (const [labelCell, value, action] of rows) {
      for (const cell of [labelCell, value, action]) {
        expect(cell.className).toContain('h-6')
      }
    }
  })

  it('elides the middle of a path that will not fit, never the tail', async () => {
    locked()
    AppInfo.mockResolvedValue({
      dataDir:
        'C:\\Users\\a-very-long-account-name\\OneDrive\\Documents\\AppData\\Local\\PassOne',
      storePath:
        'C:\\Users\\a-very-long-account-name\\OneDrive\\Documents\\AppData\\Local\\PassOne\\store',
      pgpKey: '0xDEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEF',
      sshKey: '',
      autoLock: '10 min',
    })
    render(App)

    const cell = await waitFor(() => {
      const found = locationValue('Data dir')
      expect(found).toHaveTextContent('…')
      return found
    })
    // CSS would cut this at the end and take the directory name with it.
    expect(cell).toHaveTextContent('PassOne')
    expect(cell.textContent?.endsWith('PassOne')).toBe(true)
    // What is on screen is shortened; what the title holds is not.
    expect(cell.textContent?.length).toBeLessThan(
      'C:\\Users\\a-very-long-account-name\\OneDrive\\Documents\\AppData\\Local\\PassOne'.length,
    )
    expect(cell).toHaveAttribute(
      'title',
      'C:\\Users\\a-very-long-account-name\\OneDrive\\Documents\\AppData\\Local\\PassOne',
    )

    // A key identifier is never shortened: a cut fingerprint is useless.
    expect(locationValue('PGP key').textContent).toHaveLength(42)
  })

  it('opens a directory in Explorer and copies a key ID, confirming the copy', async () => {
    locked()
    render(App)

    const dataDir = 'C:\\Users\\tester\\AppData\\Local\\PassOne'
    await waitFor(() => expect(locationValue('Data dir')).toHaveAttribute('title', dataDir))

    await fireEvent.click(screen.getByTitle('Open the store in File Explorer'))
    // The whole path goes over, not the elided text that is on screen.
    await waitFor(() => expect(RevealPath).toHaveBeenCalledWith(dataDir + '\\store'))

    await fireEvent.click(screen.getByTitle('Copy the OpenPGP key ID'))
    await waitFor(() => expect(CopyKeyID).toHaveBeenCalledWith('pgp'))
    // A fingerprint is not cleared on a timer, so the tick is the only feedback.
    await waitFor(() =>
      expect(locationCell('PGP key', 'action').querySelector('.text-success')).not.toBeNull(),
    )
  })

  it('disables the action for a location that is not there yet', async () => {
    locked()
    AppInfo.mockResolvedValue({
      dataDir: 'C:\\Users\\tester\\AppData\\Local\\PassOne',
      storePath: '(none)',
      pgpKey: '',
      sshKey: '',
      autoLock: '10 min',
    })
    render(App)

    await waitFor(() => expect(locationValue('Store')).toHaveTextContent('(none)'))
    expect(screen.getByTitle('Open the store in File Explorer')).toBeDisabled()
    expect(screen.getByTitle('Copy the OpenPGP key ID')).toBeDisabled()
    expect(screen.getByTitle('Copy the SSH key ID')).toBeDisabled()

    await fireEvent.click(screen.getByTitle('Open the store in File Explorer'))
    await fireEvent.click(screen.getByTitle('Copy the OpenPGP key ID'))
    expect(RevealPath).not.toHaveBeenCalled()
    expect(CopyKeyID).not.toHaveBeenCalled()
  })

  it('says why a path could not be opened instead of failing silently', async () => {
    locked()
    RevealPath.mockRejectedValue('C:\\Windows is not inside the PassOne data directory')
    render(App)

    // The row is only actionable once AppInfo has answered. Waiting on the real
    // path matters: the title attribute exists while the path is still empty,
    // and an empty one leaves the button disabled with nothing to wait on.
    await waitFor(() =>
      expect(locationValue('Data dir')).toHaveAttribute(
        'title',
        'C:\\Users\\tester\\AppData\\Local\\PassOne',
      ),
    )
    await fireEvent.click(screen.getByTitle('Open the data directory in File Explorer'))
    expect(RevealPath).toHaveBeenCalledWith('C:\\Users\\tester\\AppData\\Local\\PassOne')
    expect(
      await screen.findByText(/is not inside the PassOne data directory/),
    ).toBeInTheDocument()
  })

  it('reports a bad password and stays locked', async () => {
    locked()
    Unlock.mockRejectedValue('lock password is wrong')
    render(App)

    const field = screen.getByLabelText('Lock password')
    await fireEvent.input(field, {target: {value: 'nope'}})
    await fireEvent.click(screen.getByRole('button', {name: 'Unlock'}))

    await screen.findByText('lock password is wrong')
    expect(ListPasswords).not.toHaveBeenCalled()
  })
})

describe('entry detail', () => {
  it('stays encrypted until an explicit Show', async () => {
    vault()
    render(App)
    await selectEntry()

    expect(ShowPassword).not.toHaveBeenCalled()
    expect(screen.getByText('Content is locked.')).toBeInTheDocument()

    await fireEvent.click(screen.getByTestId('reveal-empty'))

    const detail = await screen.findByTestId('detail')
    expect(detail).toHaveValue('hunter2\nrecovery codes')
    expect(ShowPassword).toHaveBeenCalledWith('github/personal')
  })

  it('copies the secret on demand', async () => {
    vault()
    render(App)
    await selectEntry()

    await fireEvent.click(screen.getByRole('button', {name: /Copy/}))

    await waitFor(() => expect(CopyPassword).toHaveBeenCalledWith('github/personal'))
  })
})

describe('entry actions row', () => {
  // GH #41. TOTP and Username exist only for entries that carry a seed or a
  // login, and the header laid every action out on one fixed line. A flex item
  // cannot shrink below its own label, so as soon as both buttons showed up the
  // row grew past the window and the page scrolled sideways — and no window
  // width fixed it for an entry with a TOTP, because the row wanted more than
  // the screen had.
  //
  // jsdom has no layout engine, so a measured width cannot be asserted here; the
  // assertions are on the mechanism instead. A single-line row, a button allowed
  // to shrink (or to wrap its label onto two lines), and a heading sharing the
  // buttons' line each bring the overflow back, so each one is pinned.
  it('wraps the actions instead of widening the page when TOTP and Username show up', async () => {
    HasTOTP.mockResolvedValue(true)
    Username.mockResolvedValue('octocat')
    vault()
    render(App)
    await selectEntry()
    await screen.findByRole('button', {name: 'TOTP'})
    await screen.findByRole('button', {name: 'Username'})

    const heading = screen.getByRole('heading', {level: 2, name: 'github/personal'})
    const header = heading.closest('header')
    if (!header) {
      throw new Error('the entry actions are not in a header')
    }
    // Every action shares the one row, the two the entry earned by carrying a
    // seed and a login included.
    const actions = within(header).getAllByRole('button')
    expect(actions.map((b) => b.textContent?.trim())).toEqual([
      'Show',
      'Copy',
      'TOTP',
      'Username',
      'Edit',
      'Move',
      'Delete',
    ])
    expect(header.className).toContain('flex-wrap')
    for (const button of actions) {
      expect(button.className).toContain('shrink-0')
      expect(button.className).toContain('whitespace-nowrap')
      expect(button.getAttribute('style')).toBeNull()
    }
    // The path takes a line of its own and gives up characters instead of width,
    // so a deep entry cannot be what pushes the buttons off screen either.
    for (const wanted of ['basis-full', 'min-w-0', 'truncate']) {
      expect(heading.className).toContain(wanted)
    }
  })
})

describe('edit', () => {
  it('opens with the entry notes already in the box', async () => {
    vault()
    render(App)
    await selectEntry()

    await fireEvent.click(screen.getByRole('button', {name: 'Edit'}))

    await screen.findByRole('heading', {name: 'Edit entry'})
    // The dialog opens on the entry's current notes, so an edit that only
    // touches the password does not silently replace them, and the user does not
    // retype them from the view pane. Only the notes come back: the password
    // field is deliberately left empty, so it keeps meaning "keep the stored
    // secret" and the secret is not put in the renderer to get here.
    expect(screen.getByTestId('ed-body')).toHaveValue('recovery codes')
    expect(screen.getByLabelText('New password (leave empty to keep current)')).toHaveValue('')
    expect(ShowNotes).toHaveBeenCalledWith('github/personal')
    expect(ShowPassword).toHaveBeenCalledTimes(0)
  })

  it('saves the notes that are in the box with an empty password so the current one is kept', async () => {
    vault()
    UpdatePassword.mockResolvedValue('Updated github/personal')
    render(App)
    await selectEntry()

    await fireEvent.click(screen.getByRole('button', {name: 'Edit'}))

    await screen.findByRole('heading', {name: 'Edit entry'})
    expect(screen.getByText(/Editing:/)).toHaveTextContent('Editing: github/personal')
    // The dialog starts blank: it must not prefill a secret the user did not ask for.
    expect(screen.getByLabelText('New password (leave empty to keep current)')).toHaveValue('')

    // Appending to what the dialog opened with is the point of the prefill: the
    // existing note survives an edit that only adds one.
    await fireEvent.input(screen.getByTestId('ed-body'), {
      target: {value: 'recovery codes\nsecond factor'},
    })
    await fireEvent.click(screen.getByRole('button', {name: 'Save'}))

    // An empty password plus keepPassword: the Go side splices the original
    // first line back in. A pre-built "password\nnotes" would be a second line.
    await waitFor(() =>
      expect(UpdatePassword).toHaveBeenCalledWith(
        'github/personal',
        '',
        'recovery codes\nsecond factor',
        true,
      ),
    )
    expect(CreatePassword).not.toHaveBeenCalled()
    await screen.findByText('Updated github/personal')

    // An edit must not quietly re-decrypt the entry.
    expect(screen.queryByTestId('detail')).not.toBeInTheDocument()
    expect(ShowPassword).toHaveBeenCalledTimes(0)
  })

  // The notes box opens holding the entry's notes, so an emptied box is the user
  // deleting them. If the backend read empty as "keep", a save after clearing it
  // would report success and keep the notes: the argument assertion is the only
  // thing that catches it.
  it('sends an empty body when the notes are deleted', async () => {
    vault()
    UpdatePassword.mockResolvedValue('Updated github/personal')
    render(App)
    await selectEntry()

    await fireEvent.click(screen.getByRole('button', {name: 'Edit'}))
    await screen.findByRole('heading', {name: 'Edit entry'})
    await fireEvent.input(screen.getByTestId('ed-body'), {target: {value: ''}})
    await fireEvent.click(screen.getByRole('button', {name: 'Save'}))

    await waitFor(() => expect(UpdatePassword).toHaveBeenCalledWith('github/personal', '', '', true))
  })

  // Re-encrypting identical plaintext is not free: SavePassword commits, so an
  // untouched Save in a git store would add a commit that changes nothing.
  it('does not save when nothing was changed', async () => {
    vault()
    render(App)
    await selectEntry()

    await fireEvent.click(screen.getByRole('button', {name: 'Edit'}))
    await screen.findByRole('heading', {name: 'Edit entry'})
    await fireEvent.click(screen.getByRole('button', {name: 'Save'}))

    await screen.findByText('No changes to github/personal')
    expect(UpdatePassword).not.toHaveBeenCalled()
  })

  // A failed load must not leave an empty box that reads as "delete the notes".
  // The dialog is refused instead, so the notes can only be edited by a user who
  // can see them.
  it('does not open the dialog when the notes cannot be read', async () => {
    vault()
    ShowNotes.mockRejectedValue('store is locked')
    render(App)
    await selectEntry()

    await fireEvent.click(screen.getByRole('button', {name: 'Edit'}))

    await screen.findByText('store is locked')
    expect(screen.queryByRole('heading', {name: 'Edit entry'})).not.toBeInTheDocument()
    expect(screen.queryByTestId('ed-body')).not.toBeInTheDocument()
  })

  it('rejects a mismatched confirmation without touching the store', async () => {
    vault()
    render(App)
    await selectEntry()

    await fireEvent.click(screen.getByRole('button', {name: 'Edit'}))
    await screen.findByRole('heading', {name: 'Edit entry'})

    await fireEvent.input(screen.getByLabelText('New password (leave empty to keep current)'), {
      target: {value: 'a-new-secret'},
    })
    await fireEvent.input(screen.getByLabelText('Confirm password'), {
      target: {value: 'a-different-secret'},
    })
    await fireEvent.click(screen.getByRole('button', {name: 'Save'}))

    await screen.findByText('Passwords do not match')
    expect(UpdatePassword).not.toHaveBeenCalled()
  })

  it('closes without saving on Cancel', async () => {
    vault()
    render(App)
    await selectEntry()

    await fireEvent.click(screen.getByRole('button', {name: 'Edit'}))
    await screen.findByRole('heading', {name: 'Edit entry'})
    await fireEvent.click(screen.getByRole('button', {name: 'Cancel'}))

    await waitFor(() => expect(screen.queryByRole('heading', {name: 'Edit entry'})).not.toBeInTheDocument())
    expect(UpdatePassword).not.toHaveBeenCalled()
  })

  // The TOTP and Username buttons are gated on a probe taken when the entry was
  // selected, and the edit is what changes the answer. Both directions are
  // covered because a stale probe fails each one differently: adding a seed
  // leaves a button missing, removing one leaves a button that cannot work.
  it('shows the TOTP button after an edit adds a seed', async () => {
    vault()
    // The entry carries no seed until the edit below gives it one.
    HasTOTP.mockResolvedValueOnce(false).mockResolvedValue(true)
    UpdatePassword.mockResolvedValue('Updated github/personal')
    render(App)
    await selectEntry()
    await probeSettled()
    expect(screen.queryByRole('button', {name: 'TOTP'})).not.toBeInTheDocument()

    await fireEvent.click(screen.getByRole('button', {name: 'Edit'}))
    await screen.findByRole('heading', {name: 'Edit entry'})
    await fireEvent.input(screen.getByTestId('ed-body'), {
      target: {value: 'otpauth://totp/example\nrecovery codes'},
    })
    await fireEvent.click(screen.getByRole('button', {name: 'Save'}))

    await waitFor(() => expect(UpdatePassword).toHaveBeenCalled())
    expect(await screen.findByRole('button', {name: 'TOTP'})).toBeInTheDocument()
  })

  it('hides the TOTP button after an edit removes the seed', async () => {
    vault()
    // The entry carries a seed until the edit below strips it.
    HasTOTP.mockResolvedValueOnce(true).mockResolvedValue(false)
    UpdatePassword.mockResolvedValue('Updated github/personal')
    render(App)
    await selectEntry()
    expect(await screen.findByRole('button', {name: 'TOTP'})).toBeInTheDocument()

    await fireEvent.click(screen.getByRole('button', {name: 'Edit'}))
    await screen.findByRole('heading', {name: 'Edit entry'})
    await fireEvent.input(screen.getByTestId('ed-body'), {
      target: {value: 'recovery codes\nthe seed line is gone'},
    })
    await fireEvent.click(screen.getByRole('button', {name: 'Save'}))

    await waitFor(() => expect(UpdatePassword).toHaveBeenCalled())
    await waitFor(() => expect(HasTOTP).toHaveBeenCalledTimes(2))
    await probeSettled()
    expect(screen.queryByRole('button', {name: 'TOTP'})).not.toBeInTheDocument()
  })
})

describe('create', () => {
  it('sends path, password, confirmation and notes', async () => {
    vault()
    CreatePassword.mockResolvedValue('Created folder/example.com')
    render(App)

    await waitFor(() => screen.getByTitle('Add entry'))
    await fireEvent.click(screen.getByTitle('Add entry'))

    await screen.findByRole('heading', {name: 'Add entry'})
    await fireEvent.input(screen.getByPlaceholderText('folder/example.com'), {
      target: {value: 'folder/example.com'},
    })
    await fireEvent.input(screen.getByLabelText('Password'), {target: {value: 'p4ssw0rd'}})
    await fireEvent.input(screen.getByLabelText('Confirm password'), {target: {value: 'p4ssw0rd'}})
    await fireEvent.input(screen.getByPlaceholderText('usernames, urls, backup codes…'), {
      target: {value: 'notes here'},
    })
    await fireEvent.click(screen.getByRole('button', {name: 'Create'}))

    await waitFor(() =>
      expect(CreatePassword).toHaveBeenCalledWith('folder/example.com', 'p4ssw0rd', 'p4ssw0rd', 'notes here'),
    )
    await screen.findByText('Created folder/example.com')
  })
})

describe('delete', () => {
  it('asks twice and only then removes the entry', async () => {
    vault()
    render(App)
    await selectEntry()

    await fireEvent.click(screen.getByRole('button', {name: 'Delete'}))
    expect(RemovePassword).not.toHaveBeenCalled()

    await fireEvent.click(await screen.findByRole('button', {name: 'Confirm delete?'}))

    await waitFor(() => expect(RemovePassword).toHaveBeenCalledWith('github/personal'))
  })

  // GH #33. A removal refreshes the list, and the refresh used to swap the whole
  // list for a "Loading…" line. That emptied the <nav> scroll container, so its
  // scrollHeight collapsed and the browser reset scrollTop to 0 — deleting any
  // entry threw the user back to the top of the list.
  it('leaves the list scrolled where it was after a removal', async () => {
    const names = bigVault(40)
    // A backing store, so the refresh after the removal really does come back
    // without the deleted entry rather than replaying the same list.
    const store = [...names]
    IsUnlocked.mockResolvedValue(true)
    ListPasswords.mockImplementation(async () => [...store])
    RemovePassword.mockImplementation(async (name: string) => {
      store.splice(store.indexOf(name), 1)
      return 'Removed'
    })
    render(App)

    const scroller = (await screen.findByTitle(names[0])).closest('nav')
    if (!scroller) {
      throw new Error('the entry list is not inside a scroll container')
    }
    modelScrollClamping(scroller, 12)
    // A folder row and an entry row per vault entry, all folders expanded.
    expect(scroller.querySelectorAll('li')).toHaveLength(names.length * 2)
    // Six rows down, far enough to be visibly off the top and shallow enough
    // that losing one row must not legitimately clamp it.
    scroller.scrollTop = 6 * ROW_PX

    await selectEntry(names[0])
    await fireEvent.click(screen.getByRole('button', {name: 'Delete'}))
    await fireEvent.click(await screen.findByRole('button', {name: 'Confirm delete?'}))

    await waitFor(() => expect(RemovePassword).toHaveBeenCalledWith(names[0]))
    await waitFor(() => expect(screen.queryByTitle(names[0])).not.toBeInTheDocument())
    // The refresh must have re-rendered in place, not torn the list down and
    // rebuilt it: a "Loading…" placeholder in this container reads as zero rows
    // and the model clamps the offset away.
    expect(scroller.querySelectorAll('li').length).toBeGreaterThan(0)
    expect(scroller.scrollTop).toBe(6 * ROW_PX)
  })
})

// The header button and the dialog's submit button are both named "Move", so
// everything inside the dialog is looked up inside it. The dialog's root is the
// form the heading sits in.
async function openMoveDialog(): Promise<HTMLElement> {
  await fireEvent.click(screen.getByTestId('move'))
  const heading = await screen.findByRole('heading', {name: 'Move entry'})
  const form = heading.closest('form')
  if (!form) {
    throw new Error('the move dialog is not a form')
  }
  return form as HTMLElement
}

describe('move', () => {
  // The dialog opens with the current path already filled in, so the common case
  // is editing the last segment rather than retyping the whole path.
  it('sends the old and the new path, then follows the rename', async () => {
    vault('github/personal')
    render(App)
    await selectEntry()
    const dialog = await openMoveDialog()

    const target = within(dialog).getByTestId('move-target')
    expect((target as HTMLInputElement).value).toBe('github/personal')
    await fireEvent.input(target, {target: {value: 'github/work'}})
    await fireEvent.click(within(dialog).getByRole('button', {name: 'Move'}))

    // The old and the new name both go over the bridge, in that order: the
    // entry is identified by the name it is leaving.
    await waitFor(() => expect(MovePassword).toHaveBeenCalledWith('github/personal', 'github/work'))
    // The rename is followed by a fresh listing, so the sidebar and the
    // selection are rebuilt from the store rather than from local state.
    await waitFor(() => expect(ListPasswords).toHaveBeenCalledTimes(2))
    await waitFor(() => expect(screen.queryByTestId('move-target')).not.toBeInTheDocument())
  })

  // The tree collapses folders that have never been opened, and a move can drop
  // an entry into a folder that did not exist a moment ago. If the new folder
  // stayed collapsed the row would not be rendered at all, leaving the entry
  // selected and named in the detail pane with nothing to point at on screen.
  it('opens the folders on the way to the moved entry', async () => {
    const store = ['github/personal']
    IsUnlocked.mockResolvedValue(true)
    ListPasswords.mockImplementation(async () => [...store])
    MovePassword.mockImplementation(async (_from: string, to: string) => {
      store.splice(store.indexOf('github/personal'), 1)
      store.push(to)
      return 'Moved github/personal to archive/2026/personal'
    })
    render(App)
    await selectEntry()

    const dialog = await openMoveDialog()
    await fireEvent.input(within(dialog).getByTestId('move-target'), {
      target: {value: 'archive/2026/personal'},
    })
    await fireEvent.click(within(dialog).getByRole('button', {name: 'Move'}))

    // Rows only exist for folders that are open, so finding the entry at its
    // new path is itself the assertion that archive and archive/2026 were
    // expanded by the move.
    await waitFor(() => expect(screen.getByTitle('archive/2026/personal')).toBeInTheDocument())
    expect(screen.queryByTitle('github/personal')).not.toBeInTheDocument()
    // The selection followed the rename, so the detail pane names the new path.
    await screen.findByRole('heading', {level: 2, name: 'archive/2026/personal'})
  })

  it('keeps the dialog open and shows the error when the move is refused', async () => {
    vault('github/personal')
    MovePassword.mockRejectedValue('already exists: work/personal')
    render(App)
    await selectEntry()

    const dialog = await openMoveDialog()
    await fireEvent.input(within(dialog).getByTestId('move-target'), {target: {value: 'work/personal'}})
    await fireEvent.click(within(dialog).getByRole('button', {name: 'Move'}))

    // The refusal is shown in the dialog and in the toast, as it is for the
    // edit dialog: the toast is what a user sees if they look away from the
    // form, and the inline copy is what stays on screen with the path.
    await within(dialog).findByText('already exists: work/personal')
    expect(screen.getAllByText('already exists: work/personal')).toHaveLength(2)
    // Still open, so the path can be corrected instead of retyped from scratch,
    // and nothing was re-listed because nothing changed.
    expect(within(dialog).getByTestId('move-target')).toBeInTheDocument()
    expect(ListPasswords).toHaveBeenCalledTimes(1)
  })

  it('refuses an empty path without calling the backend', async () => {
    vault('github/personal')
    render(App)
    await selectEntry()

    const dialog = await openMoveDialog()
    await fireEvent.input(within(dialog).getByTestId('move-target'), {target: {value: '   '}})
    await fireEvent.click(within(dialog).getByRole('button', {name: 'Move'}))

    await within(dialog).findByText('Enter a new password path')
    expect(MovePassword).not.toHaveBeenCalled()
  })

  it('closes on Cancel without calling the backend', async () => {
    vault('github/personal')
    render(App)
    await selectEntry()

    const dialog = await openMoveDialog()
    await fireEvent.click(within(dialog).getByRole('button', {name: 'Cancel'}))

    await waitFor(() => expect(screen.queryByTestId('move-target')).not.toBeInTheDocument())
    expect(MovePassword).not.toHaveBeenCalled()
  })
})

describe('entry tree indent', () => {
  // style-src 'self' forbids an inline style, so tree depth is a class per step
  // (.tree-d0 … .tree-d12) rather than a computed padding-left. The regression
  // this guards: writing the class as
  //
  //   class={selected ? 'row row-active {indentClass(depth)}' : 'row {indentClass(depth)}'}
  //
  // looks interpolated but is not - Svelte only interpolates {placeholders} in
  // quoted attribute *text*, so the string reached the DOM verbatim and leaf
  // rows rendered flush left. Nothing warns about it, so the assertions below
  // check the DOM the way a user sees it.
  it('indents leaf and folder rows by depth with a real class', async () => {
    vault('github/personal')
    render(App)

    const leaf = await screen.findByTitle('github/personal')
    const folder = screen.getByText('github').closest('button')
    if (!folder) {
      throw new Error('the folder row is not a button')
    }
    expect(folder.className).toContain('tree-d0')
    expect(leaf.className).toContain('tree-d1')
    for (const row of [folder, leaf]) {
      expect(row.className).not.toContain('{')
      expect(row.getAttribute('style')).toBeNull()
    }
  })

  it('clamps a deeply nested entry to the last indent step', async () => {
    const deep = 'a/b/c/d/e/f/g/h/i/j/k/l/m/n'
    vault(deep)
    render(App)

    const leaf = await screen.findByTitle(deep)
    expect(leaf.className).toContain('tree-d12')
  })

  it('keeps the active row highlighted without losing the indent class', async () => {
    vault('github/personal')
    render(App)

    const leaf = await screen.findByTitle('github/personal')
    expect(leaf.className).not.toContain('entry-row-active')
    await fireEvent.click(leaf)

    await waitFor(() => expect(leaf.className).toContain('entry-row-active'))
    expect(leaf.className).toContain('tree-d1')
  })
})

describe('auto-lock', () => {
  it('returns to the lock screen and drops the decrypted detail', async () => {
    vault()
    render(App)
    await selectEntry()
    await fireEvent.click(screen.getByTestId('reveal-empty'))
    await screen.findByTestId('detail')

    emit('passone:locked')

    await waitFor(() => expect(screen.queryByTestId('detail')).not.toBeInTheDocument())
    expect(screen.getByLabelText('Lock password')).toBeInTheDocument()
    expect(locationValue('Data dir')).toBeInTheDocument()
  })
})

// A machine with nothing on it: no key, no store. CurrentSettings drives which
// step the wizard opens at, so a first run and a key-but-no-store machine are
// the same test with one field changed.
function blank(): void {
  locked()
  CurrentSettings.mockResolvedValue({
    ...settingsDefaults,
    storePath: '',
    pgpKeyFingerprint: '',
    hasPgp: false,
  })
}

const settingsDefaults = {
  dataDir: 'C:\\data',
  storePath: 'C:\\data\\store',
  gitRemote: '',
  pgpKeyFingerprint: '0xDEADBEEF',
  sshKeyId: '',
  autoLockMinutes: 10,
  clipboardClearSeconds: 0,
  gitAuthorName: '',
  gitAuthorEmail: '',
  usernameSource: 'auto',
  hasPgp: true,
  hasSsh: false,
}

// A key that is stored but not yet sealing anything: the state the wizard is in
// the moment after GeneratePGPKey returns and before a store exists. Set it
// before the click, because the component re-reads CurrentSettings as part of
// handling the same click.
function keyStored(): void {
  CurrentSettings.mockResolvedValue({...settingsDefaults, storePath: '', hasPgp: true})
}

async function type(label: string, value: string): Promise<void> {
  await fireEvent.input(screen.getByLabelText(label), {target: {value}})
}

describe('setup wizard: generate a key', () => {
  it('opens on the key step when there is no key, before any store exists', async () => {
    blank()
    render(App)

    expect(await screen.findByRole('heading', {name: /Step 1 of 3/})).toHaveTextContent('Decryption key')
    // A keyless machine can do nothing in step 2, so Next stays shut.
    expect(screen.getByRole('button', {name: 'Next'})).toBeDisabled()
  })

  it('sends the typed identity, passphrase and lock password, then unlocks Next', async () => {
    blank()
    GeneratePGPKey.mockResolvedValue('0xFRESH')
    render(App)
    await screen.findByRole('heading', {name: /Step 1 of 3/})

    await type('Name', 'Jane Doe')
    await type('Email', 'jane@example.com')
    await type('Passphrase for the key', 'key-pass')
    await type('Repeat passphrase', 'key-pass')
    await fireEvent.input(screen.getByLabelText('Lock password (protects all stored keys)'), {
      target: {value: 'lock-pass'},
    })
    keyStored()
    await fireEvent.click(screen.getByRole('button', {name: 'Generate key'}))

    // The exact arguments: the passphrase is sealed under the lock password, and
    // a generated key is never persisted anywhere else, so a wrong pair here is
    // the difference between a usable vault and an unreadable one.
    await waitFor(() =>
      expect(GeneratePGPKey).toHaveBeenCalledWith('Jane Doe', 'jane@example.com', 'key-pass', 'lock-pass'),
    )
    await waitFor(() => expect(screen.getByRole('button', {name: 'Next'})).not.toBeDisabled())
  })

  it('refuses mismatched passphrases without calling the backend', async () => {
    blank()
    render(App)
    await screen.findByRole('heading', {name: /Step 1 of 3/})

    await type('Email', 'jane@example.com')
    await type('Passphrase for the key', 'one')
    await type('Repeat passphrase', 'two')
    await fireEvent.input(screen.getByLabelText('Lock password (protects all stored keys)'), {
      target: {value: 'lock-pass'},
    })
    await fireEvent.click(screen.getByRole('button', {name: 'Generate key'}))

    expect(await screen.findByText('The passphrases do not match')).toBeInTheDocument()
    expect(GeneratePGPKey).not.toHaveBeenCalled()
  })

  it('refuses an empty email, which is the only required identity field', async () => {
    blank()
    render(App)
    await screen.findByRole('heading', {name: /Step 1 of 3/})

    // The button is shut until an email is there, so the guard in the handler is
    // the thing under test here rather than the disabled attribute.
    await type('Passphrase for the key', 'key-pass')
    await type('Repeat passphrase', 'key-pass')
    await fireEvent.input(screen.getByLabelText('Lock password (protects all stored keys)'), {
      target: {value: 'lock-pass'},
    })
    expect(screen.getByRole('button', {name: 'Generate key'})).toBeDisabled()
    expect(GeneratePGPKey).not.toHaveBeenCalled()
  })

  it('clears both passphrase fields after a key is sealed', async () => {
    blank()
    GeneratePGPKey.mockResolvedValue('0xFRESH')
    render(App)
    await screen.findByRole('heading', {name: /Step 1 of 3/})

    await type('Email', 'jane@example.com')
    await type('Passphrase for the key', 'key-pass')
    await type('Repeat passphrase', 'key-pass')
    await fireEvent.input(screen.getByLabelText('Lock password (protects all stored keys)'), {
      target: {value: 'lock-pass'},
    })
    await fireEvent.click(screen.getByRole('button', {name: 'Generate key'}))

    await waitFor(() => expect(GeneratePGPKey).toHaveBeenCalled())
    await waitFor(() =>
      expect(screen.getByLabelText('Passphrase for the key')).toHaveValue(''),
    )
    expect(screen.getByLabelText('Repeat passphrase')).toHaveValue('')
    expect(screen.getByLabelText('Lock password (protects all stored keys)')).toHaveValue('')
  })
})

describe('setup wizard: create a store', () => {
  it('opens on the store step when a key exists but no store does', async () => {
    blank()
    render(App)
    await screen.findByRole('heading', {name: /Step 1 of 3/})
    GeneratePGPKey.mockResolvedValue('0xFRESH')
    await type('Email', 'jane@example.com')
    await type('Passphrase for the key', 'key-pass')
    await type('Repeat passphrase', 'key-pass')
    await fireEvent.input(screen.getByLabelText('Lock password (protects all stored keys)'), {
      target: {value: 'lock-pass'},
    })
    keyStored()
    await fireEvent.click(screen.getByRole('button', {name: 'Generate key'}))
    await waitFor(() => expect(GeneratePGPKey).toHaveBeenCalled())

    // A key and no store is the other unfinished state, and it lands on step 2
    // rather than asking for a key that is already there.
    await waitFor(() => expect(screen.getByRole('button', {name: 'Next'})).not.toBeDisabled())
    await fireEvent.click(screen.getByRole('button', {name: 'Next'}))

    expect(await screen.findByRole('heading', {name: /Step 2 of 3/})).toHaveTextContent('Store')
    // Nothing has created a store yet, so Next stays shut here too.
    expect(screen.getByRole('button', {name: 'Create store'})).toBeDisabled()
  })

  it('resolves the folder name to a path and creates the store with the remote', async () => {
    blank()
    keyStored()
    render(App)
    await screen.findByRole('heading', {name: /Step 2 of 3/})

    await type('Folder name', 'passwords')
    await fireEvent.blur(screen.getByLabelText('Folder name'))
    await waitFor(() => expect(DefaultStoreDir).toHaveBeenCalledWith('passwords'))
    expect(await screen.findByText(/Will be created at C:\\data\\stores\\passwords/)).toBeInTheDocument()

    await type('Git remote (optional, not contacted yet)', 'git@github.com:me/passwords.git')
    await fireEvent.click(screen.getByRole('button', {name: 'Create store'}))

    await waitFor(() =>
      expect(CreateStore).toHaveBeenCalledWith('C:\\data\\stores\\passwords', 'git@github.com:me/passwords.git'),
    )
  })

  it('sends an empty remote when none was typed, rather than a stray space', async () => {
    blank()
    keyStored()
    render(App)
    await screen.findByRole('heading', {name: /Step 2 of 3/})

    await type('Folder name', 'passwords')
    await fireEvent.blur(screen.getByLabelText('Folder name'))
    await type('Git remote (optional, not contacted yet)', '   ')
    await fireEvent.click(await screen.findByRole('button', {name: 'Create store'}))

    await waitFor(() => expect(CreateStore).toHaveBeenCalledWith('C:\\data\\stores\\passwords', ''))
  })

  it('refuses a name carrying a separator instead of guessing a location', async () => {
    blank()
    DefaultStoreDir.mockResolvedValue('')
    keyStored()
    render(App)
    await screen.findByRole('heading', {name: /Step 2 of 3/})

    await type('Folder name', 'a/b')
    await fireEvent.blur(screen.getByLabelText('Folder name'))

    expect(await screen.findByText('Enter a plain folder name, not a path with separators')).toBeInTheDocument()
    expect(screen.getByRole('button', {name: 'Create store'})).toBeDisabled()
    expect(CreateStore).not.toHaveBeenCalled()
  })

  it('shows a backend refusal in the wizard instead of closing it', async () => {
    blank()
    keyStored()
    CreateStore.mockRejectedValue('C:\\data\\stores\\passwords is not empty and is not a pass store; refusing to create a store in it')
    render(App)
    await screen.findByRole('heading', {name: /Step 2 of 3/})

    await type('Folder name', 'passwords')
    await fireEvent.blur(screen.getByLabelText('Folder name'))
    await fireEvent.click(await screen.findByRole('button', {name: 'Create store'}))

    expect(await screen.findByText(/is not empty and is not a pass store/)).toBeInTheDocument()
    // The wizard stays open with the name still in the field: the user chose that
    // folder, and the refusal is about its contents, not its name.
    expect(screen.getByLabelText('Folder name')).toHaveValue('passwords')
  })
})

describe('after creating a store', () => {
  // The end of the from-scratch journey: a store exists and holds nothing yet.
  // Listing an empty store must settle on "No entries", not sit on the loading
  // placeholder, which is what a listing that never resolved would look like.
  it('settles on the empty state instead of the loading placeholder', async () => {
    blank()
    keyStored()
    ListPasswords.mockResolvedValue([])
    render(App)
    await screen.findByRole('heading', {name: /Step 2 of 3/})

    await type('Folder name', 'passwords')
    await fireEvent.blur(screen.getByLabelText('Folder name'))
    await fireEvent.click(await screen.findByRole('button', {name: 'Create store'}))
    await waitFor(() => expect(CreateStore).toHaveBeenCalled())

    await fireEvent.click(screen.getByRole('button', {name: 'Next'}))
    await screen.findByRole('heading', {name: /Step 3 of 3/})
    await fireEvent.click(screen.getByRole('button', {name: 'Finish'}))

    // The wizard is gone; the lock screen is what a not-yet-unlocked app shows.
    await waitFor(() => expect(screen.queryByRole('heading', {name: /Step [123] of 3/})).not.toBeInTheDocument())
    expect(screen.getByLabelText('Lock password')).toBeInTheDocument()
  })

  it('lists the new store once the session is unlocked', async () => {
    blank()
    keyStored()
    ListPasswords.mockResolvedValue([])
    render(App)
    await screen.findByRole('heading', {name: /Step 2 of 3/})
    await type('Folder name', 'passwords')
    await fireEvent.blur(screen.getByLabelText('Folder name'))
    await fireEvent.click(await screen.findByRole('button', {name: 'Create store'}))
    await waitFor(() => expect(CreateStore).toHaveBeenCalled())
    await fireEvent.click(screen.getByRole('button', {name: 'Next'}))
    await screen.findByRole('heading', {name: /Step 3 of 3/})
    await fireEvent.click(screen.getByRole('button', {name: 'Finish'}))

    await screen.findByLabelText('Lock password')
    await fireEvent.input(screen.getByLabelText('Lock password'), {target: {value: 'lock-pass'}})
    await fireEvent.click(screen.getByRole('button', {name: /Unlock/}))
    emit('passone:unlocked')

    // The store is empty, so the list is empty. "Loading…" here would mean a
    // listing promise that never settled.
    expect(await screen.findByText('No entries')).toBeInTheDocument()
    await waitFor(() => expect(screen.queryByText(/Loading/)).not.toBeInTheDocument())
  })

  // The placeholder is keyed on "has this store ever been listed", not on "is a
  // listing running". An empty store is the state a new store stays in until its
  // first entry, so keying it on `listing` gave it no honest text but
  // "Loading…" — and any refresh still in flight when the vault screen painted
  // (the unlock path fires two) sat there for good.
  it('never shows the loading placeholder once a store has been listed empty', async () => {
    vault()
    ListPasswords.mockResolvedValue([])
    render(App)
    expect(await screen.findByText('No entries')).toBeInTheDocument()

    // With the mock held open, the tree sits on an in-flight listing with
    // nothing behind it, which is exactly the state the old condition rendered
    // "Loading…" in. The refresh button is the busy indicator instead.
    const pending = deferred<string[]>()
    ListPasswords.mockReturnValue(pending.promise)
    await fireEvent.click(screen.getByTitle('Refresh list'))
    await waitFor(() => expect(screen.getByTitle('Refresh list')).toBeDisabled())
    expect(screen.getByText('No entries')).toBeInTheDocument()
    expect(screen.queryByText(/Loading/)).not.toBeInTheDocument()

    pending.resolve(['fresh-entry'])
    expect(await screen.findByTitle('fresh-entry')).toBeInTheDocument()
  })

  it('shows the loading placeholder before the first listing of a store', async () => {
    // The one case where "Loading…" is the truth: nothing has been listed yet.
    const pending = deferred<string[]>()
    IsUnlocked.mockResolvedValue(true)
    ListPasswords.mockReturnValue(pending.promise)
    render(App)

    expect(await screen.findByText(/Loading/)).toBeInTheDocument()
    pending.resolve([])
    expect(await screen.findByText('No entries')).toBeInTheDocument()
  })

  // A store switch left the previous store's rows on screen and never re-listed,
  // so a store created in the wizard was invisible until a manual refresh. The
  // selection has to go with it: it names an entry in the store just left.
  it('re-lists and drops the selection when the app switches store', async () => {
    IsUnlocked.mockResolvedValue(true)
    ListPasswords.mockResolvedValue(['github/personal'])
    // A key that seals a store which a later step replaces: the settings modal
    // offers the create form exactly while no store is configured.
    CurrentSettings.mockResolvedValue({...settingsDefaults, storePath: '', hasPgp: true})
    render(App)
    await selectEntry()
    await screen.findByRole('heading', {name: /Step 2 of 3/})

    ListPasswords.mockResolvedValue([])
    await type('Folder name', 'second')
    await fireEvent.blur(screen.getByLabelText('Folder name'))
    await fireEvent.click(await screen.findByRole('button', {name: 'Create store'}))
    await waitFor(() => expect(CreateStore).toHaveBeenCalled())

    // The old store's entry is gone from the tree and from the detail pane, and
    // the new store's empty listing is what the nav reports.
    expect(await screen.findByText('No entries')).toBeInTheDocument()
    await waitFor(() => expect(screen.queryByTitle('github/personal')).not.toBeInTheDocument())
    expect(screen.queryByRole('heading', {level: 2, name: 'github/personal'})).not.toBeInTheDocument()
  })

  it('re-expands directories of a newly switched store', async () => {
    // The expanded set still named directories in the old store, so a new
    // store's folders would render collapsed with no way back: expandAll only
    // ever ran once per session.
    IsUnlocked.mockResolvedValue(true)
    ListPasswords.mockResolvedValue(['old/entry', 'shared/entry'])
    CurrentSettings.mockResolvedValue({...settingsDefaults, storePath: '', hasPgp: true})
    render(App)
    await screen.findByTitle('old/entry')
    await screen.findByRole('heading', {name: /Step 2 of 3/})

    ListPasswords.mockResolvedValue(['fresh/entry'])
    await type('Folder name', 'second')
    await fireEvent.blur(screen.getByLabelText('Folder name'))
    await fireEvent.click(await screen.findByRole('button', {name: 'Create store'}))
    await waitFor(() => expect(CreateStore).toHaveBeenCalled())

    expect(await screen.findByTitle('fresh/entry')).toBeInTheDocument()
  })
})
