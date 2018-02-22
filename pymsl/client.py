"""
This module serves as the core client that holds
the various functions needed for the E2E encrypted
API interaction for the Netflix MSL API
"""

import base64
import json
import random
import re
import time

import requests
from Cryptodome.Cipher import AES, PKCS1_OAEP
from Cryptodome.Hash import HMAC, SHA256
from Cryptodome.PublicKey import RSA
from Cryptodome.Util import Padding

import pymsl.utils
from pymsl.exceptions import LicenseError, ManifestError, UserAuthDataError

DEFAULTS = {
    'esn': pymsl.utils.generate_esn('NFCDCH-02-'),
    'drm_system': 'widevine',
    'profiles': [
        'playready-h264mpl30-dash',
        'playready-h264mpl31-dash',
        'playready-h264mpl40-dash',
        'heaac-2-dash',
        'simplesdh',
        'nflx-cmisc',
        'BIF240',
        'BIF320'
    ],
    'languages': ['en-US']
}

ENDPOINTS = {
    'manifest': 'https://www.netflix.com/api/msl/cadmium/manifest',
    'license': 'https://www.netflix.com/api/msl/cadmium/license',
}

VALID_AUTH_SCHEMES = [
    'EMAIL_PASSWORD',
    'EMAIL_PASSWORDHASH',
    'MDX',
    'NETFLIXID',
    'SSO',
    'USER_ID_TOKEN'
]


class MslClient(object):
    """This class holds the functions for MSL API interaction"""

    def __init__(self, user_auth_data, **kwargs):
        if user_auth_data.get('scheme') not in VALID_AUTH_SCHEMES:
            raise UserAuthDataError(
                '%s is not a valid user authentication scheme' %
                user_auth_data.get('scheme')
            )

        self.msl_session = {
            'user_auth_data': user_auth_data,
            'esn': kwargs.get('esn', DEFAULTS['esn']),
            'drm_system': kwargs.get('drm_system', DEFAULTS['drm_system']),
            'profiles': kwargs.get('profiles', DEFAULTS['profiles']),
            'keypair': kwargs.get('keypair', RSA.generate(2048)),
            'message_id': kwargs.get('message_id', random.randint(0, 2**52)),
            'languages': kwargs.get('languages', DEFAULTS['languages']),
            'license_data': []
        }

        self.header = {
            'sender': self.msl_session['esn'],
            'handshake': True,
            'nonreplayable': False,
            'capabilities': {
                'languages': self.msl_session['languages'],
                'compressionalgos': ['']
            },
            'recipient': 'Netflix',
            'renewable': True,
            'messageid': self.msl_session['message_id'],
            'timestamp': time.time(),
            'keyrequestdata': [
                {
                    'scheme': 'ASYMMETRIC_WRAPPED',
                    'keydata': {
                        'publickey': base64.b64encode(
                            self.msl_session['keypair'].publickey()
                            .exportKey('DER')
                        ).decode('utf8'),
                        'mechanism': 'JWK_RSA',
                        'keypairid': 'superKeyPair'
                    }
                }
            ]
        }

        self.msl_session['session_keys'] = self.parse_handshake(
            self.perform_key_handshake()
        )

    def load_manifest(self, viewable_ids):
        """
        load_manifest()

        @param viewable_ids: List of viewable IDs
                             to obtain manifest for

        @return: manifest (dict)

        This function performs a manifest request based on
        the parameters supplied when initalizing the client
        object. If there are no errors, it will return the
        manifest as a dict. If there are errors, it will
        raise a ManifestError exception with the response
        from the MSL API as the body.
        """

        if not isinstance(viewable_ids, list):
            raise TypeError('viewable_ids must be of type list')

        manifest_request_data = {
            'method': 'manifest',
            'lookupType': 'STANDARD',
            'viewableIds': viewable_ids,
            'profiles': self.msl_session['profiles'],
            'drmSystem': self.msl_session['drm_system'],
            'sessionParams': {
                'pinCapableClient': False,
                'uiplaycontext': 'null'
            },
            'appId': '151881512282528171',
            'sessionId': '151881512218179265',
            'trackId': 0,
            'flavor': 'STANDARD',
            'supportPreviewContent': False,
            'forceClearStreams': False,
            'showAllSubDubTracks': False,
            'languages': self.msl_session['languages'],
            'secureUrls': True
        }

        request_data = self.generate_msl_request_data(manifest_request_data)
        resp = requests.post(url=ENDPOINTS['manifest'], data=request_data)

        try:
            resp.json()
        except ValueError:
            manifest = self.decrypt_msl_payload(resp.text)
            if (manifest.get('success') and
                    len(manifest['result']['viewables']) ==
                    len(set(viewable_ids))):
                for viewable in manifest['result']['viewables']:
                    self.msl_session['license_data'].append({
                        'viewable_id': viewable['movieId'],
                        'playback_context_id': viewable['playbackContextId'],
                        'drm_context_id': viewable['drmContextId']
                    })
                return manifest
            raise ManifestError(manifest)
        raise ManifestError(
            json.loads(base64.b64decode(
                resp.json()['errordata']
            ).decode('utf8'))['errormsg']
        )

    def get_license(self, challenges):
        """
        get_license()

        @param challenges: List of dicts with EME license requests
                           as byte strings and session ID strings
                           that will be used to obtain licenses

                           challenges = [{
                               'challenge': EME_BYTE_CHALLENGE,
                               'session_id': SESSION_ID_STRING
                           }]

        @return: licenses (list of dicts)

        This function performs a license request based on
        the parameters supplied when initalizing the client
        object. If there are no errors, it will return the
        license as a list of dicts. If there are errors, it will
        raise a LicenseError exception with the response
        from the MSL API as the body.

        Author's note: Instead of the nice and easy way to obtain
                       manifests with multiple viewable IDs like
                       you can with the manifest endpoint, in order
                       to obtain multiple licenses in one swoop
                       I had to wrap the HTTP requests in a loop.
                       This could be easily fixed to mirror manifest
                       acquisition if Netflix accepted playbackContextIds
                       as a list as they do with drmContextIds and
                       viewableIds. Since they do not do this,
                       to my knowledge it is impossible to obtain
                       multiple licenses for multiple viewable IDs
                       in one HTTP request.
        """

        if not isinstance(challenges, list):
            raise TypeError('challenges must be of type list')

        if not self.msl_session['license_data']:
            raise LicenseError(
                'Manifest must be loaded before license is acquired'
            )

        licenses = []
        for viewable, challenge in zip(self.msl_session['license_data'],
                                       challenges):
            license_request_data = {
                'method': 'license',
                'licenseType': 'STANDARD',
                'languages': self.msl_session['languages'],
                'playbackContextId': viewable['playback_context_id'],
                'drmContextIds': [viewable['drm_context_id']],
                'challenges': [{
                    'dataBase64': base64.b64encode(
                        challenge.get('challenge')
                    ).decode('utf8'),
                    'sessionId': challenge.get('session_id')
                }],
                'clientTime': int(time.time()),
                'xid': int((int(time.time()) + 0.1612) * 1000)
            }

            request_data = self.generate_msl_request_data(license_request_data)
            resp = requests.post(url=ENDPOINTS['license'], data=request_data)

            try:
                resp.json()
            except ValueError:
                msl_license_data = self.decrypt_msl_payload(resp.text)
                if msl_license_data.get('success'):
                    licenses.append(msl_license_data['result']['licenses'][0])
                else:
                    raise LicenseError(msl_license_data)
            else:
                raise LicenseError(resp.text)
        return licenses

    def perform_key_handshake(self):
        """
        perform_key_handshake()

        @return: Key handshake response as a dict

        This function performs the inital key handshake
        based on parameters supplied on class initialization
        and returns the response as a dict
        """

        request = {
            'entityauthdata': {
                'scheme': 'NONE',
                'authdata': {
                    'identity': self.msl_session['esn'],
                }
            },
            'signature': '',
        }

        request['headerdata'] = base64.b64encode(
            json.dumps(self.header).encode('utf8')
        ).decode('utf8')

        resp = requests.post(url=ENDPOINTS['manifest'], json=request)
        return resp.json()

    def parse_handshake(self, response):
        """
        parse_handshake()

        @param response: Key exchange response as a dict

        @return: Parsed key exchange dict containing mastertoken,
                 sequence number, encryption key, and sign key
        """

        headerdata = json.loads(
            base64.b64decode(response['headerdata']).decode('utf8')
        )

        mastertoken = headerdata['keyresponsedata']['mastertoken']
        sequence_number = json.loads(
            base64.b64decode(mastertoken['tokendata']).decode('utf8')
        )['sequencenumber']

        encrypted_encryption_key = base64.b64decode(
            headerdata['keyresponsedata']['keydata']['encryptionkey']
        )

        encrypted_sign_key = base64.b64decode(
            headerdata['keyresponsedata']['keydata']['hmackey']
        )

        oaep_cipher = PKCS1_OAEP.new(self.msl_session['keypair'])
        encryption_key_data = json.loads(
            oaep_cipher.decrypt(encrypted_encryption_key).decode('utf8')
        )

        encryption_key = pymsl.utils.webcrypto_b64decode(
            encryption_key_data['k']
        )

        sign_key_data = json.loads(
            oaep_cipher.decrypt(encrypted_sign_key).decode('utf8')
        )

        sign_key = pymsl.utils.webcrypto_b64decode(sign_key_data['k'])

        return {
            'mastertoken': mastertoken,
            'sequence_number': sequence_number,
            'encryption_key': encryption_key,
            'sign_key': sign_key
        }

    def generate_msl_request_data(self, data):
        """
        generate_msl_request_data()

        @param data: Data to wrap in encryption envelopes so it
                     can be sent to MSL API

        @return: Chunked payload and header of data
        """

        header = self.header.copy()
        header['handshake'] = False
        header['userauthdata'] = self.msl_session['user_auth_data']

        header_envelope = pymsl.utils.msl_encrypt(
            self.msl_session, json.dumps(header)
        )

        header_signature = HMAC.new(
            self.msl_session['session_keys']['sign_key'],
            header_envelope, SHA256
        ).digest()

        encrypted_header = {
            'headerdata': base64.b64encode(header_envelope).decode('utf8'),
            'signature': base64.b64encode(header_signature).decode('utf8'),
            'mastertoken': self.msl_session['session_keys']['mastertoken'],
        }

        serialized_data = [
            {},
            {
                'headers': {},
                'path': '/cbp/cadmium-13',
                'payload': {
                    'data': json.dumps(data).replace('"', '\"')
                },
                'query': ''
            }
        ]

        serialized_data = json.dumps(serialized_data).encode('utf8')

        payload = {
            'messageid': self.msl_session['message_id'],
            'data': base64.b64encode(serialized_data).decode('utf8'),
            'compressionalgos': [''],
            'sequencenumber': 1,
            'endofmsg': True
        }

        payload_envelope = pymsl.utils.msl_encrypt(
            self.msl_session,
            json.dumps(payload)
        )

        payload_signature = HMAC.new(
            self.msl_session['session_keys']['sign_key'],
            payload_envelope,
            SHA256
        ).digest()

        payload_chunk = {
            'payload': base64.b64encode(payload_envelope).decode('utf8'),
            'signature': base64.b64encode(payload_signature).decode('utf8')
        }

        return json.dumps(encrypted_header) + json.dumps(payload_chunk)

    def decrypt_msl_payload(self, payload):
        """
        decrypt_msl_payload()

        @param payload: Chunked payload response as received from MSL API

        @return: Decrypted and assembled payload as a dict
        """

        payloads = re.split(
            r',"signature":"[0-9A-Za-z/+=]+"}',
            payload.split('}}')[1]
        )

        payloads = [x + '}' for x in payloads][:-1]

        payload_chunks = payloads

        chunks = []
        for chunk in payload_chunks:
            payloadchunk = json.loads(chunk)
            encryption_envelope = payloadchunk['payload']
            cipher = AES.new(
                self.msl_session['session_keys']['encryption_key'],
                AES.MODE_CBC,
                base64.b64decode(json.loads(
                    base64.b64decode(encryption_envelope).decode('utf8')
                )['iv'])
            )

            plaintext = cipher.decrypt(
                base64.b64decode(json.loads(
                    base64.b64decode(encryption_envelope).decode('utf8')
                )['ciphertext'])
            )

            plaintext = json.loads(Padding.unpad(plaintext, 16).decode('utf8'))

            data = plaintext['data']
            data = base64.b64decode(data).decode('utf8')
            chunks.append(data)

        decrypted_payload = ''.join(chunks)
        decrypted_payload = json.loads(decrypted_payload)[1]['payload']['data']
        decrypted_payload = json.loads(
            base64.b64decode(decrypted_payload).decode('utf8')
        )

        return decrypted_payload

    def __repr__(self):
        return '<MslClient %s>' % self.msl_session['message_id']
