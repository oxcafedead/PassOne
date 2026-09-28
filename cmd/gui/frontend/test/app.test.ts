import {render, screen, waitFor, fireEvent} from '@testing-library/svelte'
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
  IsUnlocked,
  ListPasswords,
  RemovePassword,
  RevealPath,
  ShowPassword,
  Unlock,
  UpdatePassword,
} = bridge

// One entry, already unlocked, already listed. Each test overrides only what it
// cares about.
function vault(entry = 'github/personal', plaintext = 'hunter2\nrecovery codes'): void {
  IsUnlocked.mockResolvedValue(true)
  ListPasswords.mockResolvedValue([entry])
  ShowPassword.mockResolvedValue(plaintext)
}

function locked(): void {
  IsUnlocked.mockResolvedValue(false)
}

async function selectEntry(entry = 'github/personal'): Promise<void> {
  await waitFor(() => screen.getByTitle(entry))
  await fireEvent.click(screen.getByTitle(entry))
  await screen.findByRole('heading', {level: 2, name: entry})
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

describe('edit', () => {
  it('saves notes with an empty password so the current one is kept', async () => {
    vault()
    UpdatePassword.mockResolvedValue('Updated github/personal')
    render(App)
    await selectEntry()

    await fireEvent.click(screen.getByRole('button', {name: 'Edit'}))

    await screen.findByRole('heading', {name: 'Edit entry'})
    expect(screen.getByText(/Editing:/)).toHaveTextContent('Editing: github/personal')
    // The dialog starts blank: it must not prefill a secret the user did not ask for.
    expect(screen.getByLabelText('New password (leave empty to keep current)')).toHaveValue('')

    await fireEvent.input(screen.getByPlaceholderText('Empty keeps current notes'), {
      target: {value: 'new notes'},
    })
    await fireEvent.click(screen.getByRole('button', {name: 'Save'}))

    // An empty password plus keepPassword: the Go side splices the original
    // first line back in. A pre-built "password\nnotes" would be a second line.
    await waitFor(() =>
      expect(UpdatePassword).toHaveBeenCalledWith('github/personal', '', 'new notes', true),
    )
    expect(CreatePassword).not.toHaveBeenCalled()
    await screen.findByText('Updated github/personal')

    // An edit must not quietly re-decrypt the entry.
    expect(screen.queryByTestId('detail')).not.toBeInTheDocument()
    expect(ShowPassword).toHaveBeenCalledTimes(0)
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
