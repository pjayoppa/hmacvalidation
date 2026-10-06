# Signed API Demo (HMAC request signing)

A small FastAPI service showing how to protect a public API against payload
tampering, replay, and abuse using HMAC-SHA256 request signing. Fully
self-contained demo. No real data, no third-party services.

## How it works

Each request carries four headers:

| Header | Purpose |
|---|---|
| `X-Key-Id` | Which client is calling |
| `X-Timestamp` | Unix seconds; rejected if outside a 5-minute window |
| `X-Nonce` | Random per request; rejected if seen before |
| `X-Signature` | `HMAC-SHA256(secret, canonical_string)` as hex |

Canonical string:

```
METHOD \n PATH \n SORTED_QUERY \n TIMESTAMP \n NONCE \n SHA256(BODY)
```

Method, path, query, body, time, and nonce are all bound into the signature, so
changing any of them invalidates it.

## Threat model

| Threat | Mitigation | Test |
|---|---|---|
| Payload modified in transit / by a proxy | Body hash inside signed string | `test_tampered_body_rejected` |
| Request re-targeted (other path, method, query) | Method/path/query signed | `test_signature_for_other_*`, `test_tampered_query_rejected` |
| Replay of a captured valid request | Nonce store + timestamp window | `test_replay_rejected`, `test_stale_timestamp_rejected` |
| Forged requests / key guessing | Per-client secrets, constant-time compare, dummy work for unknown keys | `test_wrong_secret_rejected`, `test_unknown_key_rejected` |
| Learning which check failed | One generic 401 for all auth failures (real reason is logged) | `test_auth_errors_are_uniform` |
| Probing the schema without credentials | Signature checked **before** body parsing | `test_unauthenticated_gets_no_schema_info` |
| Nonce-store flooding by unauthenticated traffic | Nonce recorded only after signature is valid | by design |
| Traffic abuse by an authenticated client | Per-key sliding-window rate limit | `test_rate_limit` |
| Reading another client's data | Queries scoped to the authenticated key | `test_clients_only_see_their_own_payments` |

### What HMAC does NOT do (important)

- **It does not stop SQL injection.** A valid client can still send a malicious
  string and sign it correctly. HMAC proves *who sent it and that it wasn't
  altered*, not that the content is safe. Injection is handled separately here
  with strict input validation (regex/decimal constraints) **and** parameterized
  queries. See `test_signed_sql_injection_rejected_and_table_survives`.
- It does not hide data. Use TLS. Signing is integrity + authenticity, not secrecy.
- It does not protect a leaked secret. Rotate keys; store them in a secrets manager.

## Run it

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
pytest -q                          # 19 tests
uvicorn app.main:app --reload      # terminal 1
python -m client.client            # terminal 2: valid / replay / tamper / stale / SQLi demo
```

Keys come from `API_KEYS="client-a:secretA,client-b:secretB"`
(a demo default is used if unset. Never ship it.)

## Production notes

- Nonce store: Redis `SET key NX EX <ttl>` so replay protection works across instances.
- Rate limiting: move to the gateway or a Redis-backed limiter.
- Secrets: per-client keys in a vault/KMS, with rotation and a key-id overlap period.
- Consider asymmetric signatures (Ed25519) if you can't safely share a secret with the client.
- Ship the logged denial reasons to your SIEM for alerting.
