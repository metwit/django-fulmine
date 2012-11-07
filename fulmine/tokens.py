from base64 import urlsafe_b64decode, urlsafe_b64encode
from os import urandom
import re

__all__ = [
    'Token',
    'random_bytes',
    'random_hex',
    'random_b64',
    'b64_length',
    'parse_authorization',
    'parse_bearer',
]

class Token(bytes):
    def __new__(cls, data):
        if not isinstance(data, bytes):
            data = random_bytes(data)
        return super(Token, cls).__new__(cls, data)

    def base64(self):
        return urlsafe_b64encode(self)

    def __str__(self):
        return self.base64()

    def __repr__(self):
        return 'Token(%s)' % self

    def __getitem__(self, key):
        return Token(super(Token, self).__getitem__(key))

    def __getslice__(self, i, j):
        return Token(super(Token, self).__getslice__(i, j))


def random_bytes(n):
    return urandom(n)

def random_hex(n):
    return random_bytes(n).encode('hex')

def random_b64(n):
    return urlsafe_b64encode(random_bytes(n))

def b64_length(input_size):
    adjustment = 3 - (input_size % 3) if (input_size % 3) else 0
    code_padded_size = ((input_size + adjustment) / 3) * 4
    return code_padded_size

def parse_authorization(header,
                        _pattern=re.compile('^Bearer\s+([a-zA-Z0-9-_=]+)$')):
    """
    Extracts the access_token from an Authorization HTTP header
    with the Bearer authentication scheme.
    """
    m = _pattern.match(header)
    if m is None:
        return None
    else:
        b64token, = m.groups()
        b64token = b64token.encode('ascii')
        try:
            token = urlsafe_b64decode(b64token)
        except TypeError:
            # token is not valid base64
            return None
        return token

def parse_bearer(token, session_key_bytes):
    # bearer_token -> sessionid + hashed_key
    session_key = urlsafe_b64encode(token[:session_key_bytes])
    salt = token[session_key_bytes:]
    return session_key, salt
