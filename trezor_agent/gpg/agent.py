"""Tools for doing signature using gpg-agent."""

import argparse
import binascii
import io
import logging
import os
import re
import socket
import subprocess as sp

import ecdsa

from . import decode
from .. import util
from .. import client, factory, formats, util

log = logging.getLogger(__name__)


def connect(sock_path='~/.gnupg/S.gpg-agent'):
    """Connect to GPG agent's UNIX socket."""
    sock_path = os.path.expanduser(sock_path)
    sp.check_call(['gpg-connect-agent', '/bye'])
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.connect(sock_path)
    return sock


def _communicate(sock, msg):
    sock.sendall(msg + '\n')
    return _recvline(sock)


def _recvline(sock):
    reply = io.BytesIO()

    while True:
        c = sock.recv(1)
        if c == '\n':
            break
        reply.write(c)

    return reply.getvalue()


def _hex(data):
    return binascii.hexlify(data).upper()


def _unescape(s):
    s = bytearray(s)
    i = 0
    while i < len(s):
        if s[i] == ord('%'):
            hex_bytes = s[i+1:i+3]
            value = int(str(hex_bytes), 16)
            s[i:i+3] = [value]
        i += 1
    return bytes(s)


def _parse_term(s):
    size, s = s.split(':', 1)
    size = int(size)
    return s[:size], s[size:]


def _parse(s):
    if s[0] == '(':
        s = s[1:]
        name, s = _parse_term(s)
        values = [name]
        while s[0] != ')':
            value, s = _parse(s)
            values.append(value)
        return values, s[1:]
    else:
        return _parse_term(s)


def _parse_ecdsa_sig(args):
    (r, sig_r), (s, sig_s) = args
    assert r == 'r'
    assert s == 's'
    return (util.bytes2num(sig_r),
            util.bytes2num(sig_s))


def _parse_rsa_sig(args):
    (s, sig_s), = args
    assert s == 's'
    return (util.bytes2num(sig_s),)


def _parse_sig(sig):
    label, sig = sig
    assert label == 'sig-val'
    algo_name = sig[0]
    parser = {'rsa': _parse_rsa_sig, 'ecdsa': _parse_ecdsa_sig}[algo_name]
    return parser(args=sig[1:])


def sign(sock, keygrip, digest):
    """Sign a digest using specified key using GPG agent."""
    hash_algo = 8  # SHA256
    assert len(digest) == 32

    assert _communicate(sock, 'RESET').startswith('OK')

    ttyname = sp.check_output('tty').strip()
    options = ['ttyname={}'.format(ttyname)]  # set TTY for passphrase entry
    for opt in options:
        assert _communicate(sock, 'OPTION {}'.format(opt)) == 'OK'

    assert _communicate(sock, 'SIGKEY {}'.format(keygrip)) == 'OK'
    assert _communicate(sock, 'SETHASH {} {}'.format(hash_algo,
                                                     _hex(digest))) == 'OK'

    desc = ('Please+enter+the+passphrase+to+unlock+the+OpenPGP%0A'
            'secret+key,+to+sign+a+new+TREZOR-based+subkey')
    assert _communicate(sock, 'SETKEYDESC {}'.format(desc)) == 'OK'
    assert _communicate(sock, 'PKSIGN') == 'OK'
    line = _recvline(sock).strip()

    line = _unescape(line)
    log.debug('line: %r', line)
    prefix, sig = line.split(' ', 1)
    if prefix != 'D':
        raise ValueError(line)

    sig, leftover = _parse(sig)
    assert not leftover, leftover
    return _parse_sig(sig)


def get_keygrip(user_id):
    """Get a keygrip of the primary GPG key of the specified user."""
    args = ['gpg2', '--list-keys', '--with-keygrip', user_id]
    output = sp.check_output(args)
    return re.findall(r'Keygrip = (\w+)', output)[0]


def _serialize_point(data):
    data = '{}:'.format(len(data)) + data
    # https://www.gnupg.org/documentation/manuals/assuan/Server-responses.html
    for c in ['%', '\n', '\r']:
        data = data.replace(c, '%{:02X}'.format(ord(c)))
    return '(5:value' + data + ')'


def server(sock_path='~/.gnupg/S.gpg-agent', version='2.1.11', agent_id='TREZOR-GPG'):
    """Run GPG agent on a UNIX socket."""
    client_wrapper = factory.load()
    identity = client_wrapper.identity_type()
    identity.proto = 'gpg'
    identity.host = 'testing'
    curve_name = 'nist256p1'

    sock_path = os.path.expanduser(sock_path)
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    if os.path.exists(sock_path):
        os.remove(sock_path)
    sock.bind(sock_path)
    sock.listen(1)
    while True:
        log.info('waiting on %s', sock_path)
        s, addr = sock.accept()
        s.sendall('OK pleased to see you\n')
        while True:
            line = _recvline(s)
            log.info('got: %r', line)
            if not line:
                break

            reply = 'OK\n'
            if line == 'GETINFO version':
                reply = 'D {}\nOK\n'.format(version)
            if line == 'AGENT_ID':
                reply = 'D {}\nOK\n'.format(agent_id)
            if line == 'PKDECRYPT':
                s.sendall('S INQUIRE_MAXLEN 4096\nINQUIRE CIPHERTEXT\n')
                line = _recvline(s)
                log.info('line: %r', line)
                prefix, line = line.split(' ', 1)
                assert prefix == 'D'
                exp, leftover = _parse(_unescape(line))
                log.info('exp: %s', exp)
                pubkey = dict(exp[1][1:])['e']
                log.info('pubkey: %r', pubkey)

                result = client_wrapper.connection.sign_identity(
                    identity=identity,
                    challenge_hidden=pubkey,
                    challenge_visual='Decrypt?',
                    ecdsa_curve_name=curve_name)
                q = result.signature
                assert len(q) == 65
                assert q[:1] == b'\x04'
                log.info('result: %r', q)
                reply = 'D ' + _serialize_point(q) + '\nOK\n'
                log.info('reply: %r', reply)
                s.sendall(reply)
                break

            s.sendall(reply)


if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG,
                        format='%(asctime)s %(levelname)-10s %(message)-100s '
                        '%(filename)s:%(lineno)d')
    server()
