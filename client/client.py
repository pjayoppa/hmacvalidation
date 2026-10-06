"""Reference client + attack demo.  Run the server first:
    uvicorn app.main:app --reload
then:  python -m client.client
"""
import json
import os
import secrets
import time

import httpx

from app.signing import sign

BASE = os.getenv("BASE_URL", "http://127.0.0.1:8000")
KEY_ID = os.getenv("KEY_ID", "demo-client")
SECRET = os.getenv("SECRET", "demo-secret-change-me")


def signed_headers(method, path, query, body: bytes, ts=None, nonce=None):
    ts = ts if ts is not None else int(time.time())
    nonce = nonce or secrets.token_urlsafe(16)
    return {
        "X-Key-Id": KEY_ID,
        "X-Timestamp": str(ts),
        "X-Nonce": nonce,
        "X-Signature": sign(SECRET, method, path, query, ts, nonce, body),
        "Content-Type": "application/json",
    }


def main():
    payload = {"account": "1234567890", "amount": "250.00", "reference": "invoice-001"}
    body = json.dumps(payload).encode()
    hdrs = signed_headers("POST", "/payments", "", body)

    r = httpx.post(f"{BASE}/payments", content=body, headers=hdrs)
    print("1. valid request          ->", r.status_code, r.json())

    r = httpx.post(f"{BASE}/payments", content=body, headers=hdrs)
    print("2. replayed request       ->", r.status_code, r.json())

    evil = json.dumps({**payload, "amount": "99999.00"}).encode()
    r = httpx.post(f"{BASE}/payments", content=evil, headers=hdrs)
    print("3. tampered body          ->", r.status_code, r.json())

    old = signed_headers("POST", "/payments", "", body, ts=int(time.time()) - 3600)
    r = httpx.post(f"{BASE}/payments", content=body, headers=old)
    print("4. stale timestamp        ->", r.status_code, r.json())

    sqli = json.dumps({**payload, "reference": "x'; DROP TABLE payments;--"}).encode()
    h = signed_headers("POST", "/payments", "", sqli)
    r = httpx.post(f"{BASE}/payments", content=sqli, headers=h)
    print("5. signed SQLi attempt    ->", r.status_code, r.json())

    h = signed_headers("GET", "/payments", "", b"")
    r = httpx.get(f"{BASE}/payments", headers=h)
    print("6. list own payments      ->", r.status_code, r.json())


if __name__ == "__main__":
    main()
