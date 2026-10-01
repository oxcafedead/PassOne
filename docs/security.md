# Security

Security model, threat boundaries, and accepted risks of passone.

## Model at a glance

- All secret material (SSH/GPG passphrases, and any unarmored private keys) lives
  **only in process memory**. Nothing secret is ever persisted in the clear.
- Every disk-resident secret is wrapped in a vault layer: `Seal(key_disk, …)`
  with AES-256-GCM, where `key_disk = Argon2id(master_passphrase)` is derived in
  memory on every unlock and never written to disk.
- The only request this app makes over the network is a **read-only** release
  lookup: at most once per launch it asks `api.github.com` whether a newer
  PassOne has been published. Nothing local is sent with it — no key identifier,
  store path, hostname or vault data — and nothing is downloaded, verified or run
  in reply. See [the update check](../RELEASES.md#the-update-check).

## Accepted boundaries (threat model)

These limitations are inherent to desktop cryptography. They are not unique
"holes", but are consciously accepted and stated here so users can make an
informed decision.

### 1. Unlocked process + injection

While the process is unlocked and `key_disk`/private keys are in memory, any
process running with the same user's privileges can — if it successfully injects
into our process — read that material. This is a common boundary shared by
virtually all desktop password managers (1Password, KeePass, etc.). It is
minimized by keeping the key-owning layer thin and isolated, and by zeroing
buffers as soon as possible, but it cannot be fully eliminated on a user-trusted
OS.

### 2. Weak master passphrase

Because `key_disk = Argon2id(master_passphrase)`, the strength of protection for
unarmored (passphrase-less) keys is bounded by the master passphrase. A weak
passphrase under offline guessing against the sealed vault files yields weak
protection of unarmored keys.

Mitigation: a high Argon2id memory/time cost, plus enforced master-passphrase
strength whenever passphrase-less keys are stored.

### 3. In-memory lifetime during unlock and migration

Decrypted material exists in memory between unlock and use, and the previous
`app.key` remains in memory briefly during migration (a window between reading the
old key and re-sealing the new files). These windows are minimized and the
buffers zeroed via `internal/security.Zero`, but the material is present in memory
for that interval.

### 4. Zeroing cannot be made total in Go

Locking overwrites what it can reach: passphrases and plaintext buffers with
`internal/security.Zero`, and parsed private keys with
`internal/security.WipeKey` (the SSH key behind the `ssh.Signer` and every
OpenPGP primary key and subkey). What it cannot reach stays readable to anything
that can read the process's memory while the vault is locked:

- Go's garbage collector **reclaims but never erases**. Any buffer a crypto
  library allocated on the way in — decrypted DER, CFB output, `big.Int`
  temporaries — may still hold key material until the collector happens to reuse
  those pages. `Lock` deliberately calls `runtime.GC` to shorten that window, but
  a GC buys no confidentiality of its own.
- Key material inside a crypto library is only overwritable where it is stored
  in exported fields. `WipeKey` covers every such field for the key types this
  project can import; a type with unexported secret state is reported as
  unrecognized rather than silently claimed as wiped.
- Copies made by the runtime, by the compiler, or by anything that had already
  read the key are out of reach. So is a full core dump, a hibernation file, or a
  swap file that captured the unlocked process.

Treat "locked" as *no longer reachable through passone*, not as *erased*. An
attacker with read access to the process's address space at the moment of
locking, or with a memory image captured while the vault was unlocked, is
outside the boundary this design claims.

## Design principles

- **No persistent secret keys on disk.** Keys are derived from the passphrase and
  live only in memory.
- **Zeroing everywhere we can reach.** Decrypted secrets, temp buffers and parsed
  private keys are overwritten via `internal/security.Zero` and
  `internal/security.WipeKey` as soon as they are no longer needed. Section 4
  states what that leaves behind.
- **Isolation of the key-owning layer.** The code that holds secrets is kept thin
  and isolated to minimize attack surface.
- **Nothing replaces the app over the network.** A release check reads a version
  tag and stops. Fetching an artifact, verifying it and running it — or letting a
  remote party decide which binary sits next to an unlocked vault — is left to
  the person using the app, who can check a checksum themselves
  (`RELEASES.md`, `SHA256SUMS.txt`).
