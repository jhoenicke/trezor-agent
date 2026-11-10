#!/usr/bin/env python3
"""Create a GPG key with a Trezor primary key and Secure Enclave subkeys.

- primary key (certify & sign): Ed25519 on the Trezor, derived exactly like
  `trezor-gpg init -e ed25519`, so `trezor-gpg-agent` can use it,
- signing subkey: NIST P-256 ECDSA, generated inside the Secure Enclave,
- decryption subkey: Curve25519 ECDH, generated on the host, stored wrapped
  by a Secure Enclave key, and backed up encrypted by the Trezor
  (CipherKeyValue, compatible with `trezorctl crypto decrypt-keyvalue`).

Two GPG home directories are created:
- the daily one (default ~/.gnupg/secure-enclave) whose agent uses the
  Secure Enclave subkeys for signing and decryption,
- the Trezor one (default ~/.gnupg/trezor) for certifying other keys and
  managing your own subkeys (expiry, revocation).

With --from-backup the primary and decryption keys are restored from a
previous backup (e.g. on a new Mac) and a new signing subkey is created.
"""
import argparse
import functools
import json
import logging
import os
import sys
import time

import nacl.encoding
import nacl.signing
import secure_enclave
from cryptography.hazmat.primitives.asymmetric import x25519
from trezorlib import misc, tools

from libagent import formats
from libagent import gpg as libgpg
from libagent import util
from libagent.device import ui
from libagent.device.trezor import Trezor
from libagent.gpg import client, encode, protocol

log = logging.getLogger(__name__)

BACKUP_PATH = "m/10016h/0"
BACKUP_FILE = 'decryption-subkey-backup.json'
PUBLIC_KEY_FILE = 'public-key.asc'


class TrezorBackup:
    """Encrypt/decrypt the decryption subkey via Trezor's CipherKeyValue."""

    def __init__(self, trezor):
        """C-tor."""
        self.trezor = trezor

    def encrypt(self, label, value):
        """Encrypt (ASCII) value, asking for confirmation on the Trezor."""
        log.info('please confirm backup encryption on the Trezor')
        return misc.encrypt_keyvalue(self.trezor.session, tools.parse_path(BACKUP_PATH),
                                     label, value, ask_on_encrypt=True,
                                     ask_on_decrypt=True)

    def decrypt(self, label, ciphertext):
        """Decrypt value, asking for confirmation on the Trezor."""
        log.info('please confirm backup decryption on the Trezor')
        return misc.decrypt_keyvalue(self.trezor.session, tools.parse_path(BACKUP_PATH),
                                     label, ciphertext, ask_on_encrypt=True,
                                     ask_on_decrypt=True)


def default_trezor():
    """Return Trezor device and its backup helper."""
    Trezor.ui = ui.UI(device_type=Trezor, config={})
    trezor = Trezor()
    return trezor, TrezorBackup(trezor), util.which('trezor-gpg-agent')


def x25519_public(secret):
    """Return the X25519 public key for the given secret."""
    sk = x25519.X25519PrivateKey.from_private_bytes(secret)
    return sk.public_key().public_bytes_raw()


def decryption_subkey(restored, backup, created, key_dir, presence):
    """Restore or generate the decryption subkey, and wrap it in the Secure Enclave."""
    if restored:
        secret = bytes.fromhex(backup.decrypt(
            restored['trezor_key'], bytes.fromhex(restored['ciphertext'])).decode('ascii'))
        decryption_created = restored['decryption_created']
    else:
        secret = x25519.X25519PrivateKey.generate().private_bytes_raw()
        decryption_created = created
    decryption_public = x25519_public(secret)
    wrapped_public = secure_enclave.run_helper(
        secure_enclave.SecureEnclave.helper, 'import-decryption',
        os.path.join(key_dir, secure_enclave.DECRYPTION_KEY), secret.hex(), presence)
    assert wrapped_public == decryption_public
    decryption = protocol.PublicKey(
        curve_name=formats.ECDH_CURVE25519, created=decryption_created,
        verifying_key=nacl.signing.VerifyKey(decryption_public,
                                             encoder=nacl.encoding.RawEncoder),
        ecdh=True)
    return secret, decryption


def new_backup_info(backup, user_id, fingerprint, created, secret):
    """Encrypt the decryption subkey on the Trezor and return the backup data."""
    label = 'GPG decryption key {}'.format(fingerprint[-16:])
    ciphertext = backup.encrypt(label, secret.hex().encode('ascii'))
    # Verify that the backup can be decrypted before relying on it.
    assert backup.decrypt(label, ciphertext) == secret.hex().encode('ascii')
    return {
        'user_id': user_id,
        'fingerprint': fingerprint,
        'created': created,
        'decryption_created': created,
        'decryption_public': x25519_public(secret).hex(),
        'trezor_path': BACKUP_PATH,
        'trezor_key': label,
        'ciphertext': ciphertext.hex(),
        'restore': 'trezorctl crypto decrypt-keyvalue -n "{}" "{}" {}'.format(
            BACKUP_PATH, label, ciphertext.hex()),
    }


def write_backup(backup_dir, public_key, backup_info):
    """Write public key and Trezor-encrypted decryption subkey."""
    os.makedirs(backup_dir, mode=0o700)
    with open(os.path.join(backup_dir, PUBLIC_KEY_FILE), 'w') as f:
        f.write(public_key)
    with open(os.path.join(backup_dir, BACKUP_FILE), 'w') as f:
        json.dump(backup_info, f, indent=2)
        f.write('\n')


def create_key(args, trezor, backup, trezor_agent):
    """Create (or restore) the key and set up both GPG home directories."""
    # pylint: disable=too-many-locals
    restored = None
    if args.from_backup:
        with open(args.from_backup) as f:
            restored = json.load(f)
        user_id = restored['user_id']
        created = restored['created']
    else:
        if not args.user_id:
            sys.exit('USER_ID is required (unless --from-backup is used)')
        user_id = args.user_id
        created = args.time or int(time.time())

    for path in (args.homedir, args.trezor_homedir, args.backup_dir):
        if os.path.exists(path):
            sys.exit('{} exists, remove it manually if required'.format(path))
    presence = [] if args.user_presence else ['--no-user-presence']

    # Primary key on the Trezor (same derivation as `trezor-gpg init`).
    trezor_client = client.Client(device=trezor)
    trezor_identity = client.create_identity(user_id, formats.CURVE_ED25519)
    primary = protocol.PublicKey(
        curve_name=formats.CURVE_ED25519, created=created,
        verifying_key=trezor_client.pubkey(trezor_identity), ecdh=False)
    fingerprint = util.hexlify(primary.fingerprint())
    log.info('primary key: %s (created %d)', fingerprint, created)
    if restored and restored['fingerprint'] != fingerprint:
        sys.exit('Trezor derived {}, but backup is for {} (wrong seed or passphrase?)'
                 .format(fingerprint, restored['fingerprint']))
    trezor_signer = functools.partial(trezor_client.sign, identity=trezor_identity)
    result = encode.create_primary(user_id=user_id, pubkey=primary,
                                   signer_func=trezor_signer)

    no_args = argparse.Namespace()
    libgpg.setup_homedir(homedir=args.trezor_homedir, agent_cmd=[trezor_agent],
                         default_key=fingerprint, args=no_args)
    libgpg.setup_homedir(homedir=args.homedir,
                         agent_cmd=[sys.executable, os.path.abspath(secure_enclave.__file__)],
                         default_key=fingerprint, args=no_args)
    key_dir = os.path.join(args.homedir, secure_enclave.KEY_DIR)
    os.makedirs(key_dir, mode=0o700)
    secure_enclave.SecureEnclave.key_dir = key_dir
    se_client = client.Client(device=secure_enclave.SecureEnclave())

    secret, decryption = decryption_subkey(restored, backup, created, key_dir, presence)
    # Signing subkey: always freshly generated inside the Secure Enclave.
    log.info('creating signing subkey in the Secure Enclave')
    secure_enclave.run_helper(secure_enclave.SecureEnclave.helper, 'generate-signing',
                              os.path.join(key_dir, secure_enclave.SIGNING_KEY),
                              extra_args=presence)
    se_identity = client.create_identity(user_id, formats.CURVE_NIST256)
    signing = protocol.PublicKey(
        curve_name=formats.CURVE_NIST256, created=int(time.time()),
        verifying_key=se_client.pubkey(se_identity), ecdh=False)

    log.info('please confirm subkey bindings on the Trezor (and Touch ID for the back-signature)')
    result = encode.create_subkey(
        primary_bytes=result, subkey=decryption, signer_func=trezor_signer)
    result = encode.create_subkey(
        primary_bytes=result, subkey=signing, signer_func=trezor_signer,
        subkey_signer_func=functools.partial(se_client.sign, identity=se_identity))
    public_key = protocol.armor(result, 'PUBLIC KEY BLOCK')

    write_backup(args.backup_dir, public_key, restored or new_backup_info(
        backup, user_id, fingerprint, created, secret))
    del secret

    for homedir in (args.trezor_homedir, args.homedir):
        libgpg.import_public_key(homedir=homedir, public_key_bytes=public_key,
                                 fingerprint=fingerprint, user_id=user_id,
                                 verbose=args.verbose)
    log.info('done; backup written to %s', args.backup_dir)


def main():
    """Parse command-line arguments."""
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument('user_id', nargs='?', help='e.g. "Name <email>"')
    p.add_argument('-t', '--time', type=int, default=0,
                   help='primary key creation time (default: now)')
    p.add_argument('--from-backup', metavar='FILE',
                   help='restore primary & decryption key from ' + BACKUP_FILE)
    p.add_argument('--homedir', default=os.path.expanduser('~/.gnupg/secure-enclave'),
                   help='daily GPG home directory (Secure Enclave subkeys)')
    p.add_argument('--trezor-homedir', default=os.path.expanduser('~/.gnupg/trezor'),
                   help='GPG home directory for the Trezor primary key')
    p.add_argument('--backup-dir', default=os.path.abspath('gpg-key-backup'),
                   help='where to write public key and decryption key backup')
    p.add_argument('--no-user-presence', dest='user_presence', action='store_false',
                   help='do not require Touch ID/password for Secure Enclave keys')
    p.add_argument('-v', '--verbose', default=0, action='count')
    args = p.parse_args()
    util.setup_logging(verbosity=args.verbose + 1)
    for name in ('homedir', 'trezor_homedir', 'backup_dir'):
        setattr(args, name, os.path.abspath(getattr(args, name)))

    create_key(args, *default_trezor())


if __name__ == '__main__':
    main()
