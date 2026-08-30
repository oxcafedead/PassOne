# Security

Security model, threat boundaries, and accepted risks of passone.

## Model at a glance

- All secret material (SSH/GPG passphrases, and any unarmored private keys) lives
  **only in process memory**. Nothing secret is ever persisted in the clear.
- Every disk-resident secret is wrapped in a vault layer: `Seal(key_disk, …)`
  with AES-256-GCM, where `key_disk = Argon2id(master_passphrase)` is derived in
  memory on every unlock and never written to disk.
- Master passphrase entry may be replaced by Windows Hello (biometrics/PIN) when
  available and enabled. See
  [docs/windows-hello-architecture.md](windows-hello-architecture.md).

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
passphrase under offline guessing against `hello.bin` or sealed files yields weak
protection of unarmored keys.

Mitigation: a high Argon2id memory/time cost, plus enforced master-passphrase
strength whenever passphrase-less keys are stored.

### 3. No hardware TPM means software-grade protection

On machines without a TPM, Windows Hello runs in software/VSM mode rather than
hardware-backed. Protection is tied to the account (VSM) and is weaker than
hardware TPM isolation. The GUI honestly reports the detected protection level.

### 4. Fake Hello prompt (phishing)

Malware may present a forged dialog that looks like the Windows Hello prompt and
deceive a user into typing their passphrase. The real dialog invoked through
`NCrypt` is system-provided and hard to forge, but window-phishing of the user is
still possible. Users must confirm a native/system dialog before entering
anything.

### 5. In-memory lifetime during unlock and migration

Decrypted material exists in memory between unlock and use, and the previous
`app.key` remains in memory briefly during migration (a window between reading the
old key and re-sealing the new files). These windows are minimized and the
buffers zeroed via `internal/security.Zero`, but the material is present in memory
for that interval.

## Design principles

- **No persistent secret keys on disk.** Keys are derived from the passphrase and
  live only in memory.
- **Zeroing everywhere.** Decrypted secrets and temp buffers are overwritten via
  `internal/security.Zero` as soon as they are no longer needed.
- **Isolation of the key-owning layer.** The code that holds secrets is kept thin
  and isolated to minimize attack surface.
- **Optional, honest biometric unlock.** Windows Hello is an optional layer over
  passphrase entry; all four support scenarios (no Hello / Hello off / Hello+TPM
  / Hello without TPM) are handled, with honest reporting.

## Related

- [Windows Hello target architecture](windows-hello-architecture.md)
