import sqlite3
import threading
from decimal import Decimal

from fastapi import Depends, FastAPI, HTTPException, Request
from pydantic import BaseModel, Field, ValidationError

from .security import verify_signature

app = FastAPI(title="Signed API demo")

_db: sqlite3.Connection
_lock = threading.Lock()


def init_db() -> None:
    global _db
    _db = sqlite3.connect(":memory:", check_same_thread=False)
    _db.execute(
        "CREATE TABLE payments ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT, client TEXT NOT NULL, "
        "account TEXT NOT NULL, amount TEXT NOT NULL, reference TEXT NOT NULL)"
    )
    _db.commit()


init_db()


class PaymentIn(BaseModel):
    model_config = {"extra": "forbid"}
    account: str = Field(pattern=r"^[0-9]{8,16}$")
    amount: Decimal = Field(gt=0, max_digits=12, decimal_places=2)
    reference: str = Field(pattern=r"^[A-Za-z0-9 _.\-]{1,64}$")


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/payments", status_code=201)
async def create_payment(request: Request,
                         client_id: str = Depends(verify_signature)):
    # Signature is verified BEFORE the body is parsed or validated, so
    # unauthenticated callers learn nothing about the schema.
    raw = await request.body()
    try:
        p = PaymentIn.model_validate_json(raw)
    except ValidationError as e:
        fields = [".".join(map(str, err["loc"])) for err in e.errors()]
        raise HTTPException(422, {"detail": "invalid payload", "fields": fields})

    with _lock:
        # Parameterized query: this is what stops SQL injection, not the HMAC.
        cur = _db.execute(
            "INSERT INTO payments (client, account, amount, reference) "
            "VALUES (?, ?, ?, ?)",
            (client_id, p.account, str(p.amount), p.reference),
        )
        _db.commit()
    return {"id": cur.lastrowid, "status": "accepted"}


@app.get("/payments")
async def list_payments(client_id: str = Depends(verify_signature)):
    # Object-level authorization: a client only ever sees its own rows.
    with _lock:
        rows = _db.execute(
            "SELECT id, account, amount, reference FROM payments "
            "WHERE client = ? ORDER BY id", (client_id,)
        ).fetchall()
    return [{"id": r[0], "account": r[1], "amount": r[2], "reference": r[3]}
            for r in rows]
