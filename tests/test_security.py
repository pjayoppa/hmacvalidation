import json
import secrets
import time

import pytest
from fastapi.testclient import TestClient

from app import main, security
from app.security import RateLimiter
from app.signing import sign

KEY, SECRET = "client-a", "secret-a"
PAYLOAD = {"account": "1234567890", "amount": "100.50", "reference": "inv-1"}


@pytest.fixture(autouse=True)
def fresh_state():
    security.reset_state({KEY: SECRET, "client-b": "secret-b"})
    main.init_db()


@pytest.fixture
def client():
    return TestClient(main.app)


def make_headers(method="POST", path="/payments", query="", body=b"",
                 key=KEY, secret=SECRET, ts=None, nonce=None):
    ts = int(time.time()) if ts is None else ts
    nonce = nonce or secrets.token_urlsafe(16)
    return {
        "X-Key-Id": key, "X-Timestamp": str(ts), "X-Nonce": nonce,
        "X-Signature": sign(secret, method, path, query, ts, nonce, body),
        "Content-Type": "application/json",
    }


def post(client, payload=PAYLOAD, **kw):
    body = json.dumps(payload).encode()
    return client.post("/payments", content=body, headers=make_headers(body=body, **kw))


def test_valid_request_accepted(client):
    assert post(client).status_code == 201


def test_tampered_body_rejected(client):
    body = json.dumps(PAYLOAD).encode()
    headers = make_headers(body=body)
    evil = json.dumps({**PAYLOAD, "amount": "99999.00"}).encode()
    assert client.post("/payments", content=evil, headers=headers).status_code == 401


def test_signature_for_other_path_rejected(client):
    headers = make_headers("POST", "/other", body=b"{}")
    assert client.post("/payments", content=b"{}", headers=headers).status_code == 401


def test_signature_for_other_method_rejected(client):
    headers = make_headers("POST", "/payments")
    assert client.get("/payments", headers=headers).status_code == 401


def test_tampered_query_rejected(client):
    headers = make_headers("GET", "/payments", query="limit=1")
    assert client.get("/payments?limit=1000", headers=headers).status_code == 401


def test_query_param_order_does_not_matter(client):
    headers = make_headers("GET", "/payments", query="a=1&b=2")
    assert client.get("/payments?b=2&a=1", headers=headers).status_code == 200


def test_replay_rejected(client):
    body = json.dumps(PAYLOAD).encode()
    headers = make_headers(body=body)
    assert client.post("/payments", content=body, headers=headers).status_code == 201
    assert client.post("/payments", content=body, headers=headers).status_code == 401


def test_stale_timestamp_rejected(client):
    assert post(client, ts=int(time.time()) - 3600).status_code == 401


def test_future_timestamp_rejected(client):
    assert post(client, ts=int(time.time()) + 3600).status_code == 401


def test_unknown_key_rejected(client):
    assert post(client, key="nobody", secret="whatever").status_code == 401


def test_wrong_secret_rejected(client):
    assert post(client, secret="not-the-secret").status_code == 401


def test_missing_headers_rejected(client):
    assert client.post("/payments", json=PAYLOAD).status_code == 401


def test_bad_nonce_format_rejected(client):
    assert post(client, nonce="short").status_code == 401


def test_auth_errors_are_uniform(client):
    a = post(client, secret="wrong").json()
    b = post(client, key="nobody").json()
    assert a == b


def test_unauthenticated_gets_no_schema_info(client):
    r = client.post("/payments", content=b"not json",
                    headers={"Content-Type": "application/json"})
    assert r.status_code == 401


def test_signed_sql_injection_rejected_and_table_survives(client):
    bad = {**PAYLOAD, "reference": "x'; DROP TABLE payments;--"}
    assert post(client, bad).status_code == 422
    assert post(client).status_code == 201
    rows = client.get("/payments", headers=make_headers("GET", "/payments")).json()
    assert len(rows) == 1


def test_extra_fields_rejected(client):
    assert post(client, {**PAYLOAD, "is_admin": True}).status_code == 422


def test_clients_only_see_their_own_payments(client):
    assert post(client).status_code == 201
    h = make_headers("GET", "/payments", key="client-b", secret="secret-b")
    assert client.get("/payments", headers=h).json() == []


def test_rate_limit(client):
    security.limiter = RateLimiter(limit=2, window=60)
    assert post(client).status_code == 201
    assert post(client).status_code == 201
    assert post(client).status_code == 429
