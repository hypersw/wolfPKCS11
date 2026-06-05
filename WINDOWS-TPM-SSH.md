# wolfPKCS11 on Windows: TPM-backed SSH keys (findings & recipe)

Status of this fork's `windows-dll` branch: a self-contained, conformant, dual-ABI
wolfPKCS11 provider DLL that drives a **TPM-backed SSH key** on Windows, built &
provenance-attested in CI (`.github/workflows/win-dll.yml`). It works with **both**
Microsoft Win32-OpenSSH (the `native` DLL) **and stock Git-for-Windows `ssh`** (the
`posix` DLL) — i.e. git-over-ssh works out of the box, no `core.sshCommand` override.
Tag **`pinless-works`** marks the first revision where fully-pinless auth worked with
Microsoft's OpenSSH.

This document records what was changed and the bugs found (for an eventual upstream
filing — that process is interactive, hence captured here first), and how to use it.

## TL;DR recipe

1. Provision a token once with `pkcs11-tool` (native ABI). For a **fully pinless**
   (login-less) token, make the user PIN empty so wolfPKCS11 decodes all objects at
   load with no `C_Login`:
   ```
   pkcs11-tool --module wolfpkcs11-native.dll --init-token --so-pin 12345678 --label ssh
   pkcs11-tool --module wolfpkcs11-native.dll --init-pin   --so-pin 12345678 --pin 123456
   pkcs11-tool --module wolfpkcs11-native.dll --keypairgen --key-type EC:prime256v1 \
                --login --pin 123456 --label github --id 01 --usage-sign
   pkcs11-tool --module wolfpkcs11-native.dll --change-pin --pin 123456 --new-pin=
   ```
   (Direct empty-PIN `keypairgen` currently fails — Bug 5 — so keygen with a temporary
   PIN and null it with `change-pin`. For a PIN'd token, skip the last step.)
2. Point an OpenSSH at it via `PKCS11Provider`, matching the DLL to the client ABI:
   - **Stock Git-for-Windows `ssh`** → `wolfpkcs11-posix.dll`
   - **Microsoft Win32-OpenSSH** (>= 10.0p2) → `wolfpkcs11-native.dll`
   With an empty-PIN token: no PIN, no askpass, no prompt. With a PIN'd token: public
   enumeration works without login; signing prompts for the PIN (ssh-askpass).
   The on-disk store is identical for both DLLs — provision once, use either client.

## ABI split (important, Windows-specific)

Two consumer ABIs exist on Windows and a single DLL can't satisfy both:

| variant | CK_ULONG | struct packing | for |
|---|---|---|---|
| `wolfpkcs11-native.dll` | 4 bytes (LLP64) | 1-byte packed   | Microsoft OpenSSH, pkcs11-tool, NSS, Firefox |
| `wolfpkcs11-posix.dll`  | 8 bytes (LP64)  | natural align   | Git-for-Windows `ssh`/`ssh-keygen` |

Two independent differences had to be matched, not one:
- **Packing.** PKCS#11's Windows convention is `#pragma pack(1)`; native MSVC consumers
  expect it. Cygwin/MSYS-gcc consumers use natural alignment.
- **`CK_ULONG` width.** `pkcs11.h` defines `CK_ULONG` as `unsigned long`, which is
  **4 bytes** under MSVC (LLP64) but **8 bytes** under Git-for-Windows' MSYS-gcc
  OpenSSH (LP64). This affects every `CK_ULONG`-typed struct field *and* the `CK_RV`
  return value: a 4-byte `CKR_OK` returns in EAX while an LP64 caller reads the full
  8-byte RAX (garbage in the top half) — so calls appear to fail.

The on-disk token store is **identical** across both DLLs — verified: a key provisioned
with `native` is read back by `posix` and vice-versa (see Bug 7 for the fix that made
this true once `CK_ULONG` widths diverged).

## Client compatibility

| client | DLL | status |
|---|---|---|
| Microsoft Win32-OpenSSH 10.0p2 + `native` | native | **works** (pinless empty-PIN token; or PIN via askpass) |
| Git-for-Windows `ssh` 10.3p1 (MSYS/gcc) + `posix` | posix | **works** (pinless; or PIN via askpass) |

## Changes made on this branch

- **Conformant 1-byte CK_* packing on native Windows** (`d8f5795`): scoped
  `#pragma pack(push,cryptoki,1)`/`pop` in `wolfpkcs11/pkcs11.h`, gated on `_WIN32`,
  suppressible with `WOLFPKCS11_NO_PACK` (posix). Fixes Bug 2.
- **CI native/posix × release/debug matrix** (`b4601de`): one self-contained DLL per
  variant (wolfSSL+wolfTPM static-linked, `/MT` CRT), SLSA provenance attestation.
- **NULL-guard in EC attribute getters** (`d2225f4`): Fixes Bug 1.
- **Default token path `%LOCALAPPDATA%\wolfPKCS11`** (`e67db1b`): Fixes Bug 3.
- **Allow empty user PIN** `WP11_MIN_PIN_LEN=0` (`ca20623`): the empty-PIN / login-less
  token (pinless path). Tag `pinless-works`.
- **Decode login-free objects at load** (`2be83a5`): public-key/cert/data objects, and
  TPM keys (private part is a TPM-sealed blob, not token-key encrypted), are decoded at
  load even on a PIN'd token. Fixes Bug 4. (A first attempt `146fe4a`/reverted
  `3376876` used the unreliable `encoded` flag; see below.)
- **8-byte `CK_ULONG` for the posix variant** (`e6aa77b`): `WOLFPKCS11_CK_ULONG_8BYTE`
  makes `CK_ULONG`/`CK_LONG` 8-byte on MSVC, matching MSYS-gcc LP64. Fixes Bug 6.
- **Fixed-width store fields** (`34454c8`): `wp11_storage_{read,write}_ulong` now
  serialize a fixed 4 bytes (handle/class/type/mechanism are 32-bit), so the store is
  `CK_ULONG`-width-independent and the 8-byte posix build reads a native-provisioned
  store. Fixes Bug 7.
- **No stdout output** (`9fe1ad8`): the TPM chip banner (and other diagnostics) no
  longer go to stdout. Fixes Bug 8.

## Bugs found (upstream-worthy)

1. **NULL-deref in `GetEcParams`/`GetEcPoint`** (`src/internal.c`): both dereference
   `key->dp` unconditionally, so `C_GetAttributeValue(CKA_EC_PARAMS/CKA_EC_POINT)`
   crashes when the EC key isn't loaded yet (`dp==NULL`). **Fixed** (return
   `NOT_AVAILABLE_E`).

2. **No Cryptoki struct packing on Windows.** `pkcs11.h` had no `#pragma pack`, so a
   native MSVC build emits naturally-aligned `CK_*` and crashes native consumers (e.g.
   `pkcs11-tool -O` AVs). Same class as Yubico ykcs11 #59. **Fixed.**

3. **Broken default token path on Windows.** `XGETENV("%APPDIR%")` — no such env var —
   so `C_Initialize` failed unless `WOLFPKCS11_TOKEN_PATH` was set. **Fixed** to
   `%LOCALAPPDATA%\wolfPKCS11` (fallback `%APPDATA%`), created if missing.

4. **Public key material not decoded before login.** `WP11_Slot_*Load` decoded objects
   at load only for empty-PIN tokens; for a PIN'd token *all* decode was deferred to
   `C_Login`, so public-object enumeration found nothing pre-login (PKCS#11 requires
   public objects to be readable without login). **Fixed** — see "decode states" below.

5. **Empty-PIN `C_GenerateKeyPair` fails.** With an empty user PIN, keygen exits without
   producing a key (silent). Worked around by generating with a temporary PIN then
   `change-pin --new-pin=`. **Open.**

6. **`CK_ULONG` width wrong for MSYS/Cygwin-gcc consumers.** `pkcs11.h` uses
   `unsigned long` (4 bytes on MSVC); Git-for-Windows' MSYS-gcc OpenSSH is LP64
   (8 bytes). The natural-alignment ("posix") build still had a 4-byte `CK_ULONG`, so
   git-ssh misread length/type fields and `CK_RV` return values → "cannot read public
   key from pkcs11". **Fixed** for the posix variant (`WOLFPKCS11_CK_ULONG_8BYTE`).

7. **Store serialization was `CK_ULONG`-width-dependent.**
   `wp11_storage_{read,write}_ulong` wrote `sizeof(CK_ULONG)` bytes, so once the posix
   build became 8-byte it could no longer read a 4-byte (native-provisioned) store —
   `C_Initialize` failed with `CKR_FUNCTION_FAILED`. **Fixed** by pinning those fields
   to 4 bytes (the values are 32-bit PKCS#11 constants), restoring cross-ABI store
   interop and backward compatibility.

8. **Provider writes to stdout.** `wp11_TpmInit` unconditionally `printf`'d the TPM chip
   banner (`Mfg … Vendor … FIPS 140-2 …`) on every `C_Initialize`. A provider DLL is
   loaded into hosts whose stdout is a protocol channel: git-over-ssh aborted with
   `protocol error: bad line length character: Mfg`, regardless of auth. **Fixed** —
   the DLL no longer writes stdout (diagnostics gated and routed to stderr).

## Decode states (how Bug 4 was fixed)

The original idea was two flags (`pubDecoded`/`privDecoded`). In wolfPKCS11 the
public/private split is across **separate** `CKO_PUBLIC_KEY`/`CKO_PRIVATE_KEY` objects,
so per-object decode is atomic — a single reliable "decoded" bit per object suffices:

- At load, decode every object that needs no token key: public-key/cert/data objects,
  and TPM keys (whose private part is a TPM-sealed blob, not token-key encrypted). On an
  empty-PIN token the token key is derivable, so decode *everything* (this is why
  pinless sign works with no explicit login).
- At `C_Login`, decode the remaining login-gated (non-TPM private / secret) objects.
- The decode loops are guarded by a new `decoded` bit that is **0 until a successful
  decode** — unlike the pre-existing `encoded` bit, which is 0 both for a freshly-loaded
  object and after a successful decode, so guarding on it skipped everything (the cause
  of the reverted first attempt `3376876`). `C_Logout` clears the bit so material
  re-encrypted on logout is re-decoded at the next login.

Signing on a PIN'd token is still gated by login state at the PKCS#11 layer, so
decoding the (sealed) private material at load does not weaken the PIN boundary.
