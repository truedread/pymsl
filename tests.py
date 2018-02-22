"""Unit tests for pymsl"""

import unittest

from Cryptodome.PublicKey import RSA

import pymsl
from pymsl.exceptions import LicenseError, ManifestError, UserAuthDataError


class MslClientTests(unittest.TestCase):
    """Unit tests for the MslClient itself"""

    def test_kwargs(self):
        """
        This function tests the kwargs for the MslClient initialization
        to make sure that they are properly set
        """

        esn = 'NFCDIE-02-TDP0LTTSNSC3EHLL71FRYFOEEAZYQ3'
        drm_system = 'playready'
        profiles = ['ddplus-5.1-dash']
        keypair = RSA.generate(2048)
        message_id = 123456789
        languages = ['de-DE']

        client = pymsl.MslClient(
            {'scheme': 'EMAIL_PASSWORD'},
            esn=esn,
            drm_system=drm_system,
            profiles=profiles,
            keypair=keypair,
            message_id=message_id,
            languages=languages
        )

        self.assertEqual(esn, client.msl_session['esn'])
        self.assertEqual(drm_system, client.msl_session['drm_system'])
        self.assertEqual(profiles, client.msl_session['profiles'])
        self.assertEqual(keypair, client.msl_session['keypair'])
        self.assertEqual(message_id, client.msl_session['message_id'])
        self.assertEqual(languages, client.msl_session['languages'])


class MslExceptionTests(unittest.TestCase):
    """Unit tests for the MslClient exceptions"""

    def test_license_exception(self):
        """Test for LicenseError exception"""
        client = pymsl.MslClient({'scheme': 'EMAIL_PASSWORD'})
        self.assertRaises(LicenseError, client.get_license, [])

    def test_manifest_exception(self):
        """Test for ManifestError exception"""

        client = pymsl.MslClient({'scheme': 'EMAIL_PASSWORD'})
        self.assertRaises(ManifestError, client.load_manifest, [80092521])

    def test_user_auth_exception(self):
        """Test for UserAuthDataError exception"""

        self.assertRaises(UserAuthDataError, pymsl.MslClient, {})

if __name__ == '__main__':
    unittest.main()
