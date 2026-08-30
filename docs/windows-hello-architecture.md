# Windows Hello: target architecture

Target integration of Windows Hello into passone. This document describes the
**planned** state, not the current code. Many parts are not yet implemented.

Goal: unlock SSH/GPG passphrases via Windows Hello (biometrics/PIN) without typing
them each time — while fully supporting keys both with and without passphrases.

---

## 1. Core idea and key model

All secret material lives **only in process memory**. No unencrypted key is ever
stored on disk.

```
PROCESS MEMORY (the only place secrets exist):
  master_passphrase  <-  hello.Unseal()   OR   manual user input
  key_disk = KDF(master_passphrase)             # Argon2id
  key_disk --> Seal/Open --> all keys on disk

DISK (no secret keys in the clear):
  <passone>/hello.bin  = Enc(hello_key, master_passphrase)  # only when Hello is enabled
  <store>/pgp/*.gpg , ssh.pem = Seal(key_disk, private_key) # armored AND unarmored — identical
  (app.key + DPAPI  — removed from the vault chain)
```

- **`key_disk` is derived**, computed on every unlock from the master passphrase,
  exists only in memory, and is never written to a file.
- No persistent secret key sits on disk. The only disk-resident secret-related
  material is `hello.bin` (the passphrase encrypted with the Windows Hello key)
  and already-sealed keys.

### Why this is better than the current `app.key`

Currently `Vault` uses a random 32-byte `app.key`, encrypted with DPAPI and stored
on disk (`internal/security/vault.go`). That was convenient (the app opens the
vault without entering a passphrase), but created a hole: **any process running as
the same user can `CryptUnprotectData` and steal the vault key**, and therefore
the passphrase-less private keys.

In the target scheme there is no stored key: the secret is the master passphrase
(in memory), and `key_disk` is derived from it each time. A process that does not
know the passphrase has nothing to steal while locked or while keys stay locked.

## 2. Keys with and without passphrases

Both types go through the **same** vault layer `Seal(key_disk, …)`:

- **armored (with passphrase)** — the passphrase lives inside the keys; `key_disk`
  adds read-protection on disk plus integrity.
- **unarmored (no passphrase)** — the private key is protected precisely by
  `key_disk`; the mechanism is identical to armored. The "unarmored in the clear
  on disk" weakness is eliminated.

## 3. Windows Hello — optional layer over passphrase entry

All four cases are supported:

| # | Scenario | Source of master passphrase |
|---|----------|-----------------------------|
| 1 | No Hello in the system | manual input (as today) |
| 2 | Hello present, not enabled | manual input |
| 3 | Hello present, enabled + TPM | `hello.Unseal()` |
| 4 | Hello present, enabled, no TPM (VSM/software) | `hello.Unseal()` + honest warning |

Properties:

- **Unlock once per session**: Hello is asked once, not per password.
- **Application-level timeout**: the working session (`K_session`) lives until
  `AutoLockMinutes` / `HelloTimeoutSeconds` elapses; on expiry the key is zeroed
  and the next operation needs Hello again. This is implemented through the
  existing `requireUnlocked`/`startAutoLock` in `internal/app`.
- **Zeroing**: any decrypted material (`master_passphrase`, `key_disk`, temp
  buffers) is zeroed through `internal/security.Zero`.
- `hello.Unseal()` returns the **master_passphrase**, from which `KDF` then
  yields `key_disk`.

## 4. Changes by package

| Package | Change |
|---------|--------|
| `internal/security` | `Vault` moves from the DPAPI `KeyProtector` + `app.key` to `key_disk = KDF(passphrase)`. `Zero`, GCM, atomic writes — unchanged. |
| `internal/hello` *(new)* | `hello.go` (detect TPM/software/presence), `ngcrypt.go` (CNG `NCrypt*` in TPM/VSM), `enroll.go`, `unseal.go`, `clear.go`, `session.go` |
| `internal/app` | `Unlock*` gain a second passphrase source (`hello.Unseal()`); new methods `UnlockWithHello`, `EnableHello`, `DisableHello`, `IsHelloEnabled`, `HelloAvailable`, `HelloLevel` (`tpm`/`software`/`none`) |
| `internal/config` | Flags `EnableHello bool`, `HelloTimeoutSeconds int` |
| `internal/ui` + `frontend` | Toggle + "Windows Hello" button on the lock screen; honest protection-level indicator |
| `cmd/app` | `unlock --hello`; headless fallback to input |
| migration | On first run of the new version, read the old `app.key` via DPAPI, re-seal all files under `key_disk` from the master passphrase, and remove `app.key` |

## 5. Cryptography

- `KDF = Argon2id` with a high memory/time cost; the salt lives on disk.
- `Seal = AES-256-GCM`.
- `hello.bin = NCryptEncrypt(hello_key, master_passphrase)`.
- CNG: `NCryptCreatePersistedKey` with `NCRYPT_UI_POLICY` (requires Windows
  Hello), `NCRYPT_PIN_CACHE_PROPERTY` (in-kernel unlock timeout), and a
  non-exportable key. The API is identical for TPM and software/VSM — the
  difference is transparently hidden by Windows.

## 6. Documented boundaries (see `security.md`)

The full threat model, including these boundaries, is described in
[docs/security.md](security.md).

These limitations are inherent to desktop cryptography; they are not unique
"holes", but must be consciously accepted and stated to the community.
Summary:

1. **Unlocked process + injection.** While the process is unlocked and
   `key_disk`/private keys are in memory, a user-privilege process injected into
   it can read them. This is a common boundary (1Password, KeePass, etc.) —
   mitigated by layer isolation and zeroing, but not fully eliminated.
2. **Weak master passphrase.** Since `key_disk = KDF(master_passphrase)`, a weak
   passphrase under offline guessing against `hello.bin`/sealed files yields weak
   protection of unarmored keys. **Mitigation:** high Argon2id cost + **enforced
   passphrase strength** for unarmored cases.
3. **Fake Hello prompt.** Malware may draw a forged dialog and deceive the user.
   The real dialog invoked through `NCrypt` is system-provided and hard to forge,
   but window phishing is not excluded.
4. **Without TPM, protection is software.** VPN/software mode (VSM, tied to the
   account) is weaker than hardware TPM protection. The GUI honestly shows the level.
5. **`app.key` migration.** The old key stays in memory for a while during
   migration (a window between reading the old key and re-sealing the new files).

## 7. Implementation status

Planned. See `AGENTS.md` for project context.
