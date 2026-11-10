#!/usr/bin/env python3
"""GPG agent for subkeys stored in the macOS Secure Enclave (via se-helper).

The keys are stored in $GNUPGHOME/secure-enclave/{signing,decryption}.json,
created by create_gpg_key.py.  Run as gpg-agent replacement (see run-agent.sh
in the GPG home directory).
"""
import argparse
import json
import logging
import os
import subprocess

import nacl.encoding
import nacl.signing
from cryptography.hazmat.primitives.asymmetric import ec

from libagent import formats, gpg
from libagent.device import interface

log = logging.getLogger(__name__)

HELPER = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'se-helper')
KEY_DIR = 'secure-enclave'
SIGNING_KEY = 'signing.json'
DECRYPTION_KEY = 'decryption.json'


def run_helper(helper, command, keyfile, stdin_hex='', extra_args=()):
    """Run se-helper and return its (hex-decoded) output."""
    args = [helper, command, keyfile] + list(extra_args)
    log.debug('running %s', args)
    result = subprocess.run(args, input=stdin_hex.encode('ascii'),
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            check=False)
    if result.returncode != 0:
        msg = result.stderr.decode('utf-8', 'replace').strip()
        raise interface.DeviceError(msg or 'se-helper failed')
    return bytes.fromhex(result.stdout.decode('ascii').strip())


def load_public_key(keyfile):
    """Load the public key stored next to the Secure Enclave key blob."""
    with open(keyfile) as f:
        info = json.load(f)
    public = bytes.fromhex(info['public'])
    if info['type'] == 'signing':
        return ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), public)
    # libagent represents Curve25519 public keys as (raw) nacl VerifyKey
    return nacl.signing.VerifyKey(public, encoder=nacl.encoding.RawEncoder)


class SecureEnclave(interface.Device):
    """Secure Enclave backed P-256 signing and X25519 decryption subkeys."""

    key_dir = None  # set by main()
    helper = HELPER
    ui = None

    @classmethod
    def package_name(cls):
        """Python package name."""
        return 'trezor-agent'

    def connect(self):
        """Nothing to connect to."""
        return self

    def close(self):
        """Nothing to close."""

    def _keyfile(self, identity, ecdh):
        if not ecdh and identity.curve_name == formats.CURVE_NIST256:
            name = SIGNING_KEY
        elif ecdh and identity.curve_name == formats.ECDH_CURVE25519:
            name = DECRYPTION_KEY
        else:
            # e.g. the Trezor-based primary key
            raise KeyError('{} not stored in Secure Enclave'.format(identity.to_string()))
        path = os.path.join(self.key_dir, name)
        if not os.path.exists(path):
            raise KeyError(path)
        return path

    def pubkey(self, identity, ecdh=False):
        """Return public key."""
        return load_public_key(self._keyfile(identity, ecdh))

    def sign(self, identity, blob):
        """Sign given digest, returning r||s."""
        keyfile = self._keyfile(identity, ecdh=False)
        sig = run_helper(self.helper, 'sign', keyfile, blob.hex())
        assert len(sig) == 64
        return sig

    def ecdh(self, identity, pubkey):
        """Return X25519 shared secret (in Trezor's format)."""
        keyfile = self._keyfile(identity, ecdh=True)
        assert pubkey[:1] == b'\x40' and len(pubkey) == 33
        shared = run_helper(self.helper, 'ecdh', keyfile, pubkey[1:].hex())
        assert len(shared) == 32
        return b'\x04' + shared


def main():
    """Run the GPG agent."""
    p = argparse.ArgumentParser()
    p.add_argument('--homedir', default=os.environ.get('GNUPGHOME'))
    args, _ = p.parse_known_args()
    SecureEnclave.key_dir = os.path.join(args.homedir, KEY_DIR)
    gpg.run_agent(SecureEnclave)


if __name__ == '__main__':
    main()
