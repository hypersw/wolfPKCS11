# wolfPKCS11 on Windows: TPM-backed SSH keys (findings & recipe)

Status of this fork's `windows-dll` branch: a self-contained, conformant, dual-ABI
wolfPKCS11 provider DLL that drives a **TPM-backed SSH key** on Windows, built &
provenance-attested in CI (`.github/workflows/win-dll.yml`). Tag **`pinless-works`**
marks the first revision where fully-pinless auth works with Microsoft's OpenSSH.

This document records what was changed, the bugs found (for an eventual upstream
filing — that process is interactive, hence captured here first), and how to use it.

## TL;DR recipe (fully pinless, Microsoft OpenSSH)

1. Use the **native** (1-byte packed) DLL: `wolfpkcs11-native.dll`.
2. Provision an **empty-PIN** token (one-time), which makes wolfPKCS11 decode all
   objects at load with no `C_Login`:
   ```
   pkcs11-tool --module wolfpkcs11-native.dll --init-token  --so-pin 12345678 --label ssh
   pkcs11-tool --module wolfpkcs11-native.dll --init-pin    --so-pin 12345678 --pin 123456
   pkcs11-tool --module wolfpkcs11-native.dll --keypairgen --key-type EC:prime256v1 \
                --login --pin 123456 --label github --id 01 --usage-sign
   pkcs11-tool --module wolfpkcs11-native.dll --change-pin --pin 123456 --new-pin=
   ```
   (Direct empty-PIN `keypairgen` currently fails — see Bug 5 — so we keygen with a
   temporary PIN and null it with `change-pin`.)
3. Point **Microsoft Win32-OpenSSH** (>= 10.0p2) at it via `PKCS11Provider`, with
   `WOLFPKCS11_TOKEN_PATH` set to the token dir (default `%LOCALAPPDATA%\wolfPKCS11`).
   `ssh-keygen -D <dll> -e` then exports the pubkey and auth signs — **no PIN, no
   askpass, no prompt**.

## ABI split (important, Windows-specific)

PKCS#11's Windows convention is **1-byte struct packing** (`#pragma pack(1)`). Native
Windows builds (MSVC) — Microsoft OpenSSH, OpenSC `pkcs11-tool`, NSS — all pack.
**Cygwin** builds (Git for Windows' `ssh`) do **not** define `_WIN32`, so they use
natural alignment. A single DLL cannot satisfy both, so CI builds two ABIs:

| variant | packing | for |
|---|---|---|
| `wolfpkcs11-native.dll` | 1-byte packed | Microsoft OpenSSH, pkcs11-tool, NSS, Firefox |
| `wolfpkcs11-posix.dll`  | natural align | Git-for-Windows (Cygwin) `ssh` |

The on-disk token store is **identical** across both (packing only affects the public
`CK_*` API structs, not the internal `WP11_*` structs or the field-serialized store) —
verified: a key provisioned with `native` is read back by `posix`.

## Client compatibility

| client | status |
|---|---|
| Microsoft Win32-OpenSSH 10.0p2 + `native` | **works** (pinless with empty-PIN token; or PIN via askpass) |
| Git-for-Windows `ssh` (Cygwin) + `posix`  | **not yet** — see Bug 4 (needs public-decode-before-login) |

Git-for-Windows `ssh` requires a *successful* `C_Login` before it will read any object
(even public), and gives up if it fails; Microsoft's port reads public objects without
requiring login. Fixing Bug 4 makes the Cygwin/Git path work too — a "works out of the
box on a stock Git install" win worth pursuing (Plan 2 below).

## Changes made on this branch

- **Conformant 1-byte CK_* packing on native Windows** (`d8f5795`): added scoped
  `#pragma pack(push,cryptoki,1)`/`pop` in `wolfpkcs11/pkcs11.h`, gated on `_WIN32`
  and suppressible with `WOLFPKCS11_NO_PACK` (the posix variant). Fixes Bug 2.
- **CI native/posix × release/debug matrix** (`b4601de`): `win-dll.yml` builds a
  single self-contained DLL per variant (wolfSSL+wolfTPM static-linked, `/MT` CRT),
  with SLSA provenance attestation.
- **NULL-guard in EC attribute getters** (`d2225f4`): Fixes Bug 1.
- **Default token path `%LOCALAPPDATA%\wolfPKCS11`** (`e67db1b`): Fixes Bug 3.
- **Allow empty user PIN** `WP11_MIN_PIN_LEN=0` (`ca20623`): enables the empty-PIN /
  login-less token (the pinless path). Tag `pinless-works`.
- Reverted a first attempt at Bug 4 (`3376876`) — it used a single decode flag and
  regressed the login decode; the correct fix is the two-flag design (Plan 2).

## Bugs found (upstream-worthy)

1. **NULL-deref in `GetEcParams`/`GetEcPoint`** (`src/internal.c`). Both dereference
   `key->dp` unconditionally (even on the `pValue==NULL` size probe). When the EC key
   material isn't loaded yet (`dp==NULL`), `C_GetAttributeValue` for
   `CKA_EC_PARAMS`/`CKA_EC_POINT` crashes (access violation) — reproduced via OpenSSH's
   public-key enumeration. **Fixed** here (return `NOT_AVAILABLE_E` on NULL `dp`).

2. **No Cryptoki struct packing on Windows.** `wolfpkcs11/pkcs11.h` had no
   `#pragma pack`, so a native MSVC build emits naturally-aligned `CK_*` structs and
   crashes native consumers (e.g. `pkcs11-tool -O` AVs on first call through the
   mis-laid-out `CK_FUNCTION_LIST`). Same class as Yubico ykcs11 #59. **Fixed** here.

3. **Broken default token path on Windows.** `src/internal.c` used
   `XGETENV("%APPDIR%")` — no env var is literally named `%APPDIR%`, so the fallback
   never resolved and `C_Initialize` failed unless `WOLFPKCS11_TOKEN_PATH` was set.
   **Fixed** to `%LOCALAPPDATA%\wolfPKCS11` (fallback `%APPDATA%`), created if missing.

4. **Public key material not decoded before login.** `WP11_Slot_*Load` only decodes
   objects at load when the token has an empty PIN; for a PIN'd token *all* decode is
   deferred to `C_Login`. PKCS#11 requires **public** objects to be readable without
   login, so OpenSSH/git-ssh public-key enumeration finds nothing on a PIN'd token.
   **Open — Plan 2.**

5. **Empty-PIN `C_GenerateKeyPair` fails.** With an empty user PIN, key generation
   exits without producing a key (silent failure). Worked around by generating with a
   temporary PIN then `change-pin --new-pin=` to empty. **Open.**

## Plan 2 — public-before-login via two decode states

Replace the single `encoded` flag with two: `pubDecoded` and `privDecoded`.

- **At load:**
  - **Empty-PIN token:** the token key is derivable from the empty PIN, so decode
    *everything* now → set **both** `pubDecoded` and `privDecoded` (this is why pinless
    sign already works — private is available with no explicit login).
  - **PIN'd token:** decode only public material (TPM public area is plaintext; non-TPM
    public keys are unencrypted) → set `pubDecoded`. Leave `privDecoded` unset.
- **At login:** decode private material → set `privDecoded`. The login decode loop must
  key off `privDecoded` (not a single flag) so it doesn't re-init already-public-decoded
  keys (the single-flag version regressed exactly here).
- Public attribute getters succeed once `pubDecoded`; signing requires `privDecoded`.

Result: PIN'd tokens expose `CKA_EC_POINT`/`CKA_EC_PARAMS` before login → Git-for-Windows
`ssh` works (askpass/PIN still needed for signing), and it's correct PKCS#11 behaviour.
