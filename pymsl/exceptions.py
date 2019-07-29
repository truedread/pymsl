"""This module stores various exceptions used by the client"""


class KeyExchangeError(Exception):
    """Exception for key exchange issues"""


class ManifestError(Exception):
    """Exception for manifest parsing issues"""


class LicenseError(Exception):
    """Exception for license parsing issues"""


class UserAuthDataError(Exception):
    """Exception for user_auth_data syntax issues"""
