"""Request-signature verification as a FastAPI dependency."""
import hmac
import logging
import os
import re
import threading
import time
from collections import defaultdict, deque

from fastapi import HTTPException, Request

from .signing import sign

log = logging.getLogger("signed_api.security")

MAX_SKEW_SECONDS = 300                 # accepted clock drift
NONCE_TTL_SECONDS = MAX_SKEW_SECONDS * 2
NONCE_RE = re.compile(r"^[A-Za-z0-9_\-]{16,64}$")
_DUMMY_SECRET = "dummy-secret-for-constant-work"


def _load_keys() -> dict[str, str]:
    """API_KEYS='client-a:secretA,client-b:secretB'. Demo default only."""
    raw = os.getenv("API_KEYS", "demo-client:demo-secret-change-me")
    return dict(pair.split(":", 1) for pair in raw.split(",") if ":" in pair)


class NonceStore:
    """Remembers (key_id, nonce) so a captured request can't be replayed.
    In-memory for the demo; use Redis SET NX EX in production so it works
    across multiple instances."""

    def __init__(self, ttl: int = NONCE_TTL_SECONDS):
        self._ttl = ttl
        self._seen: dict[tuple[str, str], float] = {}
        self._lock = threading.Lock()

    def check_and_add(self, key: tuple[str, str]) -> bool:
        now = time.time()
        with self._lock:
            for k in [k for k, exp in self._seen.items() if exp <= now]:
                del self._seen[k]
            if key in self._seen:
                return False
            self._seen[key] = now + self._ttl
            return True


class RateLimiter:
    """Sliding-window limiter per authenticated key."""

    def __init__(self, limit: int = 60, window: int = 60):
        self.limit, self.window = limit, window
        self._hits: dict[str, deque] = defaultdict(deque)
        self._lock = threading.Lock()

    def allow(self, key: str) -> bool:
        now = time.time()
        with self._lock:
            q = self._hits[key]
            while q and q[0] <= now - self.window:
                q.popleft()
            if len(q) >= self.limit:
                return False
            q.append(now)
            return True


KEYS: dict[str, str] = _load_keys()
nonce_store = NonceStore()
limiter = RateLimiter()


def reset_state(keys: dict[str, str] | None = None) -> None:
    """Used by tests."""
    global KEYS, nonce_store, limiter
    KEYS = keys if keys is not None else _load_keys()
    nonce_store = NonceStore()
    limiter = RateLimiter()


def _deny(reason: str) -> None:
    # Log the real reason; return the same generic 401 for every failure so
    # attackers can't tell which check they tripped.
    log.warning("auth denied: %s", reason)
    raise HTTPException(status_code=401, detail="invalid request signature")


async def verify_signature(request: Request) -> str:
    """Returns the authenticated key_id or raises 401/429."""
    h = request.headers
    key_id = h.get("x-key-id")
    ts = h.get("x-timestamp")
    nonce = h.get("x-nonce")
    sig = h.get("x-signature")

    if not (key_id and ts and nonce and sig):
        _deny("missing_headers")
    if not NONCE_RE.match(nonce):
        _deny("bad_nonce_format")
    try:
        ts_int = int(ts)
    except ValueError:
        _deny("bad_timestamp")
    if abs(time.time() - ts_int) > MAX_SKEW_SECONDS:
        _deny("stale_timestamp")

    secret = KEYS.get(key_id)
    body = await request.body()
    expected = sign(secret or _DUMMY_SECRET, request.method,
                    request.url.path, request.url.query, ts_int, nonce, body)

    # constant-time compare; same work whether or not the key exists
    ok = hmac.compare_digest(expected.encode(), sig.lower().encode())
    if secret is None:
        _deny("unknown_key")
    if not ok:
        _deny("bad_signature")

    # Only burn a nonce AFTER the signature is valid, so unauthenticated
    # traffic can't fill the nonce store.
    if not nonce_store.check_and_add((key_id, nonce)):
        _deny("replay")
    if not limiter.allow(key_id):
        raise HTTPException(status_code=429, detail="rate limit exceeded")
    return key_id
