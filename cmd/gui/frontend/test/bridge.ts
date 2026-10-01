// Test double for the Wails Go bridge.
//
// The generated wailsjs/go/main/App.js calls window.go.main.App.<Name>(...), so
// the tests install a mock of that object instead of aliasing the module. That
// keeps the real generated bindings in the loop: a binding that calls the wrong
// window path, or a name App.svelte imports that App.js does not export, fails
// here rather than passing against a stand-in.
import {vi, type Mock} from 'vitest'

// Default behaviour, so the component renders without configuring all 38
// bindings per test. CurrentSettings describes a fully configured store, which
// stops openSettingsIfFirstRun from opening the onboarding wizard over the top
// of every test.
const defaults = {
  IsUnlocked: async () => false,
  Unlock: async () => undefined,
  AppInfo: async () => ({
    dataDir: 'C:\\Users\\tester\\AppData\\Local\\PassOne',
    storePath: 'C:\\Users\\tester\\AppData\\Local\\PassOne\\store',
    pgpKey: '0xDEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEF',
    sshKey: '',
    autoLock: '10 min',
  }),
  ListPasswords: async () => [] as string[],
  ShowPassword: async () => 'hunter2\nrecovery codes',
  ShowNotes: async () => 'recovery codes',
  CopyPassword: async () => undefined,
  CopyKeyID: async () => undefined,
  CopyUsername: async () => undefined,
  CopyTOTP: async () => undefined,
  HasTOTP: async () => false,
  Username: async () => '',
  ClipboardClearSeconds: async () => 0,
  ClipboardHistoryEnabled: async () => false,
  CreatePassword: async () => 'Created',
  UpdatePassword: async () => 'Updated',
  MovePassword: async () => 'Moved',
  RemovePassword: async () => 'Removed',
  RevealPath: async () => undefined,
  PickPrivateKey: async () => ({path: '', canceled: true, password: ''}),
  PickStoreDir: async () => ({path: '', canceled: true}),
  ImportPGPKeyFile: async () => 'ok',
  GeneratePGPKey: async () => '0xNEWKEY0000000000000000000000000000000',
  CreateStore: async () => undefined,
  DefaultStoreDir: async (name: string) => (name === '' ? '' : `C:\\data\\stores\\${name}`),
  ImportSSHKeyFile: async () => 'ok',
  HasSSHKeyLoaded: async () => false,
  LoadSSHKey: async () => 'ok',
  OpenLocalStore: async () => 'ok',
  StoredStores: async () => [] as unknown[],
  PrepareClone: async () => ({}),
  TrustHost: async () => ({}),
  CloneStore: async () => 'ok',
  CurrentSettings: async () => ({
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
  }),
  ChangeLockPassword: async () => 'ok',
  SetAutoLock: async () => undefined,
  SetClipboardClear: async () => undefined,
  SetGitAuthor: async () => undefined,
  SetUsernameSource: async () => undefined,
  UsernameSource: async () => 'auto',
  Status: async () => 'ok',
  Sync: async () => 'ok',
  KnownHosts: async () => [] as unknown[],
  // A released build with nothing newer to report, so the startup check is
  // silent in every test that does not say otherwise.
  CheckForUpdates: async () => ({
    available: false,
    message: 'PassOne v0.1.1 is the latest published release',
  }),
}

export type BridgeName = keyof typeof defaults

export const bridge: Record<BridgeName, Mock> = Object.fromEntries(
  Object.entries(defaults).map(([name, impl]) => [name, vi.fn(impl)]),
) as Record<BridgeName, Mock>
