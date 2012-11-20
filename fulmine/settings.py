from django.conf import settings
from fulmine.tokens import b64_length

__all__ = []

def setup_defaults():
    """
    Define settings that can be overriden in Django settings file.

    Settings names are in the form "FULMINE_" + local setting name.
    For example to override AUTH_CODE_BYTES to be 48 you have to add
    a line like this in your settings file:

    FULMINE_AUTH_CODE_BYTES = 48

    """

    # The number of bytes that make a decoded access token.
    # If you override this make sure to also override ACCESS_TOKEN_LENGTH.
    ACCESS_TOKEN_BYTES = 36

    # The size of an encoded access token string. This is the number of
    # characters that is actually transmitted.
    # Make sure this is consistent with ACCESS_TOKEN_BYTES
    ACCESS_TOKEN_LENGTH = b64_length(ACCESS_TOKEN_BYTES)

    # The number of bytes that make a decoded authorization code.
    # If you override this make sure to also override AUTH_CODE_LENGTH.    
    AUTH_CODE_BYTES = 24

    # The size of an encoded authorization code string.This is the number of
    # characters that is actually transmitted.
    # Make sure this is consistent with AUTH_CODE_BYTES
    AUTH_CODE_LENGTH = b64_length(AUTH_CODE_BYTES)

    # The duration of an authorization code before it expires, in seconds.
    AUTH_CODE_EXPIRE_SECONDS = 60 * 5

    # The size of the client_id string.
    CLIENT_ID_LENGTH = 16

    # The size of the deploy_id string
    DEPLOY_ID_LENGTH = 32

    # How many bytes of the access token make the Django session key.
    # This is limited to 30 bytes for Django DB session backend. Django
    # by default uses 16, but employs a check to avoid key collision.
    SESSION_KEY_BYTES = 24

    # Maximum size of a space separated list of all scope keywords.
    SCOPE_LENGTH = 120

    # override settings with those specified in Django settings file
    # and update django.conf.settings
    for key, value in locals().items():
        globals()[key] = getattr(settings, 'FULMINE_' + key, value)
        setattr(settings, 'FULMINE_' + key, globals()[key])
        __all__.append(key)

setup_defaults()
