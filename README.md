# pymsl
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
>>> client.load_manifest([80092521])
{'success': True, ...
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
...     languages=LIST_OF_LANGUAGES # default is ['en_US']
... )
```


### Methods

#### `load_manifest(viewable_ids)`

```
@param viewable_ids: List of viewable IDs
                     to obtain manifest for

@return: manifest (dict)

This function performs a manifest request based on
the parameters supplied when initalizing the client
object. If there are no errors, it will return the
manifest as a dict. If there are errors, it will
raise a ManifestError exception with the response
from the MSL API as the body.
```

#### `get_license(challenges)`

```
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
licenses as a list of dicts. If there are errors, it will
raise a LicenseError exception with the response
from the MSL API as the body.
```

# Installation

To install, you can either clone the repository and run `python setup.py install` or you can run `pip install pymsl`

# To-Do

- [x] Implement license acquisition
- [ ] Clean up chunked payload parsing