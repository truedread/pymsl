"""This module holds various utility functions used by the MSL client"""

import base64
import json
import os
import random
import string

from Cryptodome.Cipher import AES
from Cryptodome.Util import Padding


def dumps(data):
    """
    dumps()

    @param data: Data as a dict to use for creating JSON string

    @return: JSON string without whitespace
    """

    return json.dumps(data, separators=(',', ':'))


def msl_encrypt(msl_session, plaintext):
    """
    msl_encrypt()

    @param msl_session: Dict of msl_session created by the client
                        upon initialization
    @param plaintext: Plaintext to encrypt

    @return: JSON byte string of encryption envelope
    """

    cbc_iv = os.urandom(16)
    encryption_envelope = {
        'keyid': '%s_%s' % (
            msl_session['esn'],
            msl_session['session_keys']['sequence_number']
        ),
        'sha256': 'AA==',
        'iv': base64.b64encode(cbc_iv).decode('utf8')
    }

    plaintext = Padding.pad(plaintext.encode('utf8'), 16)
    cipher = AES.new(
        msl_session['session_keys']['encryption_key'],
        AES.MODE_CBC,
        cbc_iv
    )

    ciphertext = cipher.encrypt(plaintext)

    encryption_envelope['ciphertext'] = base64.b64encode(
        ciphertext
    ).decode('utf8')

    return json.dumps(encryption_envelope).encode('utf8')


def generate_esn(prefix):
    """
    generate_esn()

    @param prefix: Prefix of ESN to append generated device ID onto

    @return: ESN to use with MSL API
    """

    return prefix + ''.join(random.choice(
        string.ascii_uppercase + string.digits
    ) for _ in range(30))


def webcrypto_b64decode(b64):
    """
    webcrypto_b64decode()

    @param b64: URL safe encoded base64 string lacking padding
                (most likely from WebCrypto API)

    @return: Bytes from decoding base64 string
    """

    padding = len(b64) % 4
    if padding != 0:
        b64 += '=' * (4 - padding)
    return base64.urlsafe_b64decode(b64.encode('utf8'))
