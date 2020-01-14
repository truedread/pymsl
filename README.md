# pymsl
[![Build Status](https://travis-ci.com/truedread/pymsl.svg?branch=master)](https://travis-ci.com/truedread/pymsl)
[![License: GPL v3](https://img.shields.io/badge/License-GPL%20v3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)

Python library for interacting with the Netflix MSL API

# Usage

### Basic Usage

```python
>>> import pymsl
>>> user_auth_data = {
...     'scheme': 'EMAIL_PASSWORD',
...     'authdata': {
...         'email': email,
...         'password': password
...     }
... }
>>> client = pymsl.MslClient(user_auth_data)
>>> client.load_manifest(80092521)
{'version': 2, ...
```

All user authentication schemes are defined in the MSL wiki: https://github.com/Netflix/msl/wiki/User-Authentication-(Configuration)

### Custom Kwargs

`pymsl.MslClient()` takes additional kwargs as well to override the defaults; the only required arg for initialization is user_auth_data:

```python
>>> pymsl.MslClient(
...     user_auth_data,
...     esn=CUSTOM_ESN, # default is NFCDCH-02-[random device ID]
...     drm_system=CUSTOM_DRM_SYSTEM, # default is 'widevine', you can use 'playready', 'fps', etc.
...     profiles=LIST_OF_PROFILES, # default is ['playready-h264mpl30-dash', 'playready-h264mpl31-dash', 'playready-h264mpl40-dash', 'heaac-2-dash', 'simplesdh', 'nflx-cmisc', 'BIF240', 'BIF320']
...     keypair=CUSTOM_CRYPTODOME_RSA_KEYPAIR, # default is a random 2048-bit keypair
...     message_id=CUSTOM_MESSAGE_ID, # default is a random integer between 0 and 2^52
...     languages=LIST_OF_LANGUAGES, # default is ['en_US']
...     proxies=PROXIES, # default is None
...     key_request_data=CUSTOM_KEY_REQUEST_DATA, # default is ASYMMETRIC_WRAPPED
...     extra_manifest_params=EXTRA_MANIFEST_PARAMS # default is a blank dict
... )
```

- `esn` is the identity used for communicating with MSL. Different ESNs have different privileges.
- `drm_system` will determine what kind of initialization data you will receive in the manifest.
- `profiles` is a list of profiles used for telling MSL what you want to receive in the manifest.
- `keypair` is the RSA keypair used in the initial key exchange.
- `message_id` is a random integer used for identifying the MSL client session.
- `languages` is a list of languages used for determining the language of the manifest received.
- `proxies` is a proxy dict passed the same way you would pass it to the [requests](https://2.python-requests.org/en/master/user/advanced/#proxies) library.
- `key_request_data` is a dict passed to override the normal `ASYMMETRIC_WRAPPED` key request dict in order to enable using other key exchange mechanisms. Note that you may have to monkey patch the `parse_handshake` function in order for it to work with your specified key exchange mechanism.
- `extra_manifest_params` is a dict of extra manifest params. Here's the default manifest params sent in a manifest request:

```python
'params': {
    'type': 'standard',
    'viewableId': viewable_id,
    'profiles': self.msl_session['profiles'],
    'flavor': 'STANDARD',
    'drmType': self.msl_session['drm_system'],
    'drmVersion': 25,
    'usePsshBox': True,
    'isBranching': False,
    'useHttpsStreams': True,
    'imageSubtitleHeight': 720,
    'uiVersion': 'shakti-v4bf615c3',
    'clientVersion': '6.0011.511.011',
    'supportsPreReleasePin': True,
    'supportsWatermark': True,
    'showAllSubDubTracks': False,
    'videoOutputInfo': [
        {
            'type': 'DigitalVideoOutputDescriptor',
            'outputType': 'unknown',
            'supportedHdcpVersions': [],
            'isHdcpEngaged': False
        }
    ],
    'preferAssistiveAudio': False,
    'isNonMember': False
}
```

By using this kwarg you can add any values you want to this param dict. For example, if you wanted `showAllSubDubTracks` to be true, you would set `extra_manifest_params` to `{'showAllSubDubTracks': True}`. The manifest param dict is simply `.update()`'ed with `extra_manifest_params`, so you can overwrite default values or add new ones.

### Methods

#### `load_manifest(viewable_id)`

```
@param viewable_ids: Int of viewable ID
                     to obtain manifest for

@return: manifest (dict)

This function performs a manifest request based on
the parameters supplied when initalizing the client
object. If there are no errors, it will return the
manifest as a dict. If there are errors, it will
raise a ManifestError exception with the response
from the MSL API as the body.
```

#### `get_license(challenge, session_id)`

```
@param challenge:  EME license request as a byte string
                   that will be used to obtain a license

@param session_id: DRM specific session ID passed as a string

@return: license (dict)

This function performs a license request based on
the parameters supplied when initalizing the client
object. If there are no errors, it will return the
licenses as a list of dicts. If there are errors, it will
raise a LicenseError exception with the response
from the MSL API as the body.
```

# Installation

To install, you can either clone the repository and run `python setup.py install` or you can run `pip install pymsl`

# To-Do

- [x] Implement license acquisition
- [ ] Clean up chunked payload parsing
