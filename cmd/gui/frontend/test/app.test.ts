import {render, screen, waitFor, fireEvent} from '@testing-library/svelte'
import {describe, expect, it} from 'vitest'
import App from '../src/App.svelte'
import {bridge} from './bridge'
import {emit} from './runtime'

const {
  ClipboardHistoryEnabled,
  CopyPassword,
  CreatePassword,
  IsUnlocked,
  ListPasswords,
  RemovePassword,
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

// The data directory shown on the lock screen, read through its <dt> so the
// assertion does not depend on the settings wizard having refreshed storePath.
function storeDir(): HTMLElement {
  const dt = screen.getByText('Data dir')
  const dd = dt.nextElementSibling
  if (!dd) {
    throw new Error('the lock screen has no Data dir value')
  }
  return dd as HTMLElement
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
      expect(storeDir()).toHaveTextContent('C:\\Users\\tester\\AppData\\Local\\PassOne'),
    )

    // Nothing from the vault is reachable before the lock is open.
    expect(screen.queryByTitle('Add entry')).not.toBeInTheDocument()
    expect(screen.queryByRole('button', {name: 'Edit'})).not.toBeInTheDocument()

    const field = screen.getByLabelText('Lock password')
    await fireEvent.input(field, {target: {value: 'correct horse'}})
    await fireEvent.click(screen.getByRole('button', {name: 'Unlock'}))

    await waitFor(() => expect(Unlock).toHaveBeenCalledWith('correct horse'))
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
    expect(storeDir()).toBeInTheDocument()
  })
})
