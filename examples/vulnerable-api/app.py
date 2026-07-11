"""A deliberately BOLA-vulnerable API — the AuthzTrace demo target.

    python app.py             # vulnerable: any user can read/delete any invoice
    SECURE=1 python app.py    # patched:   the server checks ownership first

Two users, two invoices. In vulnerable mode this is the textbook IDOR/BOLA
(OWASP API #1): authentication works, but nothing checks that the caller owns
the object they asked for.
"""
import os

from flask import Flask, jsonify, request

app = Flask(__name__)
SECURE = os.environ.get("SECURE") == "1"

TOKENS = {"alice-token": "alice", "bob-token": "bob"}
PASSWORDS = {"alice": "alice-password", "bob": "bob-password"}
INVOICES = {
    "inv_alice_001": {
        "id": "inv_alice_001",
        "owner": "alice",
        "amount": 4200,
        "note": "Alice private invoice",
    },
    "inv_bob_002": {
        "id": "inv_bob_002",
        "owner": "bob",
        "amount": 1337,
        "note": "Bob private invoice",
    },
}


@app.get("/healthz")
def healthz():
    return jsonify(status="ok", secure=SECURE), 200


def current_user():
    auth = request.headers.get("Authorization", "")
    token = auth[7:] if auth.startswith("Bearer ") else request.cookies.get("session", "")
    return TOKENS.get(token)


@app.post("/api/login")
def login():
    payload = request.get_json(silent=True) or {}
    username = str(payload.get("username") or "")
    if not username or PASSWORDS.get(username) != payload.get("password"):
        return jsonify(error="invalid credentials"), 401
    token = next(token for token, user in TOKENS.items() if user == username)
    return jsonify(session={"access_token": token}), 200


@app.post("/api/login-cookie")
def login_cookie():
    payload = request.get_json(silent=True) or {}
    username = str(payload.get("username") or "")
    if not username or PASSWORDS.get(username) != payload.get("password"):
        return jsonify(error="invalid credentials"), 401
    token = next(token for token, user in TOKENS.items() if user == username)
    response = jsonify(authenticated=True)
    response.set_cookie("session", token, httponly=True, samesite="Lax")
    return response, 200


def _load(user, invoice_id):
    """Shared auth/ownership logic. Returns (invoice, error_response)."""
    if not user:
        return None, (jsonify(error="unauthenticated"), 401)
    invoice = INVOICES.get(invoice_id)
    if not invoice:
        return None, (jsonify(error="not found"), 404)
    if SECURE and invoice["owner"] != user:
        return None, (jsonify(error="forbidden"), 403)   # <-- the one-line fix
    return invoice, None


@app.get("/api/invoices/<invoice_id>")
def get_invoice(invoice_id):
    invoice, err = _load(current_user(), invoice_id)
    if err:
        return err
    return jsonify(invoice), 200


@app.get("/api/invoices")
def get_invoice_by_query():
    invoice, err = _load(current_user(), request.args.get("id", ""))
    if err:
        return err
    return jsonify(invoice), 200


@app.post("/api/invoices/lookup")
def lookup_invoice():
    payload = request.get_json(silent=True) or {}
    invoice, err = _load(current_user(), payload.get("invoice_id", ""))
    if err:
        return err
    return jsonify(invoice), 200


@app.delete("/api/invoices/<invoice_id>")
def delete_invoice(invoice_id):
    invoice, err = _load(current_user(), invoice_id)
    if err:
        return err
    return jsonify(deleted=invoice_id), 200            # (demo: does not mutate state)


if __name__ == "__main__":
    mode = "SECURE" if SECURE else "VULNERABLE"
    print(f"[demo] invoice API running on :3000  mode={mode}")
    app.run(port=3000, debug=False)
