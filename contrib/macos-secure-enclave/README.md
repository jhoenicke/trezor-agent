# Trezor primary key with Secure Enclave subkeys (macOS)

Creates an OpenPGP key where

| key | algorithm | stored |
|---|---|---|
| primary (certify, sign) | Ed25519 | Trezor (same derivation as `trezor-gpg init -e ed25519`) |
| signing subkey | NIST P-256 ECDSA | generated inside the Secure Enclave, not exportable |
| decryption subkey | Curve25519 ECDH | generated on the host, stored wrapped by a Secure Enclave key, backed up encrypted by the Trezor |

Day-to-day signing and decryption need only the Mac (and Touch ID); the
Trezor is needed only to certify other keys and to manage your own subkeys.

## Setup

```sh
pip install trezor-agent          # provides libagent, trezorlib, trezor-gpg-agent
cd contrib/macos-secure-enclave
swiftc -O -o se-helper se-helper.swift
./create_gpg_key.py "Your Name <you@example.com>"
```

This asks for confirmations on the Trezor (primary self-signature, two
subkey bindings, backup encryption and its verification) and for Touch ID
(back-signature of the signing subkey).  It creates:

- `~/.gnupg/secure-enclave`: daily GPG home, its agent (`secure_enclave.py`)
  uses the Secure Enclave subkeys.  Use it with
  `export GNUPGHOME=~/.gnupg/secure-enclave` (or its `env` script).
- `~/.gnupg/trezor`: GPG home whose agent is `trezor-gpg-agent`, for
  `gpg --sign-key`, `--quick-set-expire`, `--quick-revoke-...` etc.
- `./gpg-key-backup/`: `public-key.asc` and `decryption-subkey-backup.json`.

The backup file holds the decryption subkey encrypted with the Trezor's
`CipherKeyValue` (path `m/10016h/0`).  It is useless without the Trezor
(and the passphrase, if you use one), so it can be stored anywhere.  It also
contains a `trezorctl crypto decrypt-keyvalue ...` command that recovers the
secret (hex) without this script.

Publish the public key and keep a copy of it together with the backup file.

## New Mac / lost Mac

```sh
./create_gpg_key.py --from-backup gpg-key-backup/decryption-subkey-backup.json
```

re-derives the primary key on the Trezor, restores the decryption subkey
into the new Secure Enclave and creates a new signing subkey.  Afterwards,
revoke the old signing subkey in `~/.gnupg/trezor`
(`gpg --edit-key <fpr>`, `key N`, `revkey`) and publish the updated key.

## Notes

- With the default access control, every signature and every decryption
  asks for Touch ID (or the login password).  `--no-user-presence` drops
  this, but then any process running as you can use the keys while the Mac
  is unlocked (still without being able to copy them).
- The decryption subkey is in plain memory inside `se-helper` while it is
  being used; malware running as you at that moment could read it.  The
  stored key file is useless on any other machine.
- Subkeys are created without expiry.
- `gpg -K` shows `sec` instead of `sec#` in the daily home directory, as
  the agent claims all keygrips in the keyring; using the primary key there
  fails cleanly.
- `se-helper` must stay next to `secure_enclave.py` (the agent looks for it
  there).
