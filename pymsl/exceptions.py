"""This module stores various exceptions used by the client"""


class KeyExchangeError(Exception):
    """Exception for key exchange issues"""
    pass


class ManifestError(Exception):
    """Exception for manifest parsing issues"""
    pass


class LicenseError(Exception):
    """Exception for license parsing issues"""
    pass


class UserAuthDataError(Exception):
    """Exception for user_auth_data syntax issues"""
    pass
