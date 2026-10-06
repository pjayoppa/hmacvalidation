"""Pure signing helpers shared by the server and the reference client.

Canonical string (newline-separated):
    METHOD
    PATH
    CANONICAL_QUERY      (params sorted, re-encoded)
    TIMESTAMP            (unix seconds)
    NONCE
    SHA256_HEX(BODY)

Signature = HMAC-SHA256(secret, canonical_string), hex-encoded.
Binding method, path, query, body, time and nonce means changing ANY of them
invalidates the signature.
"""
import hashlib
import hmac
from urllib.parse import parse_qsl, urlencode


def body_hash(body: bytes) -> str:
    return hashlib.sha256(body).hexdigest()


def canonical_query(query: str) -> str:
    pairs = sorted(parse_qsl(query, keep_blank_values=True))
    return urlencode(pairs)


def canonical_string(method: str, path: str, query: str,
                     timestamp: int | str, nonce: str, body: bytes) -> str:
    return "\n".join([
        method.upper(),
        path,
        canonical_query(query),
        str(timestamp),
        nonce,
        body_hash(body),
    ])


def sign(secret: str, method: str, path: str, query: str,
         timestamp: int | str, nonce: str, body: bytes) -> str:
    msg = canonical_string(method, path, query, timestamp, nonce, body)
    return hmac.new(secret.encode(), msg.encode(), hashlib.sha256).hexdigest()
