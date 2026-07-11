import json

import pytest
import requests

from authztrace.engine import run
from authztrace.models import Actor, Check, Contract, Policy, Resource
from authztrace.report import to_json


class FakeResponse:
    def __init__(self, status_code, text="", body=None, headers=None, cookies=None):
        self.status_code = status_code
        self.text = text
        self._body = body
        self.headers = headers or {}
        self.cookies = cookies or {}

    def json(self):
        if self._body is None:
            raise ValueError("no json")
        return self._body


class FakeSession:
    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = []
        self.cookies = {}
        self.closed = False

    def close(self):
        self.closed = True

    def request(self, method, url, **kwargs):
        self.calls.append((method, url, kwargs))
        response = self.responses.pop(0)
        if isinstance(response, requests.RequestException):
            raise response
        return response


def _contract():
    return Contract(
        base_url="http://api.test",
        actors={
            "alice": Actor("alice", {"type": "bearer", "token": "bad-token"}),
            "bob": Actor("bob", {"type": "bearer", "token": "bob-token"}),
        },
        resources={
            "invoice": Resource(
                name="invoice",
                endpoints=[],
                ids={"alice": "inv_a", "bob": "inv_b"},
            )
        },
        policy=Policy(),
    )


def _login_auth(extract, credential):
    return {
        "type": "login",
        "request": {
            "method": "POST",
            "path": "/login",
            "query": {},
            "headers": {},
            "json": {"username": "user", "password": "secret"},
            "data": None,
            "follow_redirects": True,
        },
        "extract": extract,
        "credential": credential,
        "expect_status": [],
    }


def _check(actor, owner, expect):
    return Check(
        name=f"{actor} -> {owner}",
        resource="invoice",
        actor=actor,
        method="GET",
        path=f"/invoices/inv_{owner[0]}",
        path_template="/invoices/{id}",
        target_owner=owner,
        object_id=f"inv_{owner[0]}",
        expect=expect,
    )


def test_preflight_failure_skips_attack_rows(monkeypatch):
    session = FakeSession([FakeResponse(401, "unauthenticated")])
    monkeypatch.setattr("authztrace.engine.requests.Session", lambda: session)
    checks = [
        Check(
            name="alice own invoice",
            resource="invoice",
            actor="alice",
            method="GET",
            path="/invoices/inv_a",
            path_template="/invoices/{id}",
            target_owner="alice",
            object_id="inv_a",
            expect="allow",
            assertions={"allow_contains": ["Alice private"]},
        ),
        Check(
            name="alice attacks bob invoice",
            resource="invoice",
            actor="alice",
            method="GET",
            path="/invoices/inv_b",
            path_template="/invoices/{id}",
            target_owner="bob",
            object_id="inv_b",
            expect="deny",
        ),
    ]

    results = run(_contract(), checks)

    assert [(r.outcome, r.category) for r in results] == [
        ("error", "setup"),
        ("skipped", "setup"),
    ]
    assert len(session.calls) == 1


def test_allow_contains_does_not_turn_setup_failure_into_finding(monkeypatch):
    session = FakeSession([FakeResponse(401, "unauthenticated")])
    monkeypatch.setattr("authztrace.engine.requests.Session", lambda: session)
    checks = [
        Check(
            name="alice own invoice",
            resource="invoice",
            actor="alice",
            method="GET",
            path="/invoices/inv_a",
            path_template="/invoices/{id}",
            target_owner="alice",
            object_id="inv_a",
            expect="allow",
            assertions={"allow_contains": ["Alice private"]},
        )
    ]

    result = run(_contract(), checks)[0]

    assert result.outcome == "error"
    assert result.category == "setup"
    assert "allowed response missed" not in result.note


def test_unsafe_methods_are_skipped_in_read_only_mode(monkeypatch):
    session = FakeSession([FakeResponse(200, "Alice private")])
    monkeypatch.setattr("authztrace.engine.requests.Session", lambda: session)
    checks = [
        Check(
            name="alice own invoice",
            resource="invoice",
            actor="alice",
            method="GET",
            path="/invoices/inv_a",
            path_template="/invoices/{id}",
            target_owner="alice",
            object_id="inv_a",
            expect="allow",
            assertions={"allow_contains": ["Alice private"]},
        ),
        Check(
            name="delete bob invoice",
            resource="invoice",
            actor="alice",
            method="DELETE",
            path="/invoices/inv_b",
            path_template="/invoices/{id}",
            target_owner="bob",
            object_id="inv_b",
            expect="deny",
            safe=False,
        ),
    ]

    results = run(_contract(), checks)

    assert [(r.outcome, r.category) for r in results] == [
        ("pass", "ok"),
        ("skipped", "unsafe_skipped"),
    ]
    assert [call[0] for call in session.calls] == ["GET"]


def test_include_unsafe_executes_unsafe_methods(monkeypatch):
    session = FakeSession([FakeResponse(200, "Alice private"), FakeResponse(403, "forbidden")])
    monkeypatch.setattr("authztrace.engine.requests.Session", lambda: session)
    checks = [
        Check(
            name="alice own invoice",
            resource="invoice",
            actor="alice",
            method="GET",
            path="/invoices/inv_a",
            target_owner="alice",
            object_id="inv_a",
            expect="allow",
        ),
        Check(
            name="delete bob invoice",
            resource="invoice",
            actor="alice",
            method="DELETE",
            path="/invoices/inv_b",
            target_owner="bob",
            object_id="inv_b",
            expect="deny",
            safe=False,
        ),
    ]

    results = run(_contract(), checks, include_unsafe=True)

    assert [result.outcome for result in results] == ["pass", "pass"]
    assert [call[0] for call in session.calls] == ["GET", "DELETE"]


def test_login_json_credentials_use_isolated_actor_sessions(monkeypatch):
    contract = _contract()
    contract.actors = {
        "alice": Actor(
            "alice",
            _login_auth(
                {"from": "json", "path": "session.access_token"},
                {"type": "bearer"},
            ),
        ),
        "bob": Actor(
            "bob",
            _login_auth(
                {"from": "json", "path": "session.access_token"},
                {"type": "bearer"},
            ),
        ),
    }
    alice_session = FakeSession(
        [
            FakeResponse(200, body={"session": {"access_token": "alice-runtime-token"}}),
            FakeResponse(200),
            FakeResponse(403),
        ]
    )
    bob_session = FakeSession(
        [
            FakeResponse(200, body={"session": {"access_token": "bob-runtime-token"}}),
            FakeResponse(200),
            FakeResponse(403),
        ]
    )
    sessions = iter([alice_session, bob_session])
    monkeypatch.setattr("authztrace.engine.requests.Session", lambda: next(sessions))
    checks = [
        _check("alice", "alice", "allow"),
        _check("bob", "bob", "allow"),
        _check("alice", "bob", "deny"),
        _check("bob", "alice", "deny"),
    ]

    results = run(contract, checks)

    assert [result.outcome for result in results] == ["pass", "pass", "pass", "pass"]
    assert alice_session is not bob_session
    assert alice_session.calls[1][2]["headers"] == {
        "Authorization": "Bearer alice-runtime-token"
    }
    assert alice_session.calls[2][2]["headers"] == {
        "Authorization": "Bearer alice-runtime-token"
    }
    assert bob_session.calls[1][2]["headers"] == {
        "Authorization": "Bearer bob-runtime-token"
    }
    assert bob_session.calls[2][2]["headers"] == {
        "Authorization": "Bearer bob-runtime-token"
    }
    report = to_json(results)
    assert "alice-runtime-token" not in report
    assert "bob-runtime-token" not in report
    assert json.loads(report)["summary"]["error"] == 0


@pytest.mark.parametrize(
    ("extract", "credential", "login_response", "expected_header"),
    [
        (
            {"from": "header", "name": "X-Login-Token"},
            {"type": "header", "name": "X-API-Key", "template": "Token {value}"},
            FakeResponse(200, headers={"X-Login-Token": "header-runtime-token"}),
            {"X-API-Key": "Token header-runtime-token"},
        ),
        (
            {"from": "cookie", "name": "session"},
            {"type": "cookie", "name": "session"},
            FakeResponse(200, cookies={"session": "cookie-runtime-token"}),
            {},
        ),
    ],
)
def test_login_extracts_header_and_cookie_credentials(
    monkeypatch, extract, credential, login_response, expected_header
):
    contract = _contract()
    contract.actors = {"alice": Actor("alice", _login_auth(extract, credential))}
    session = FakeSession([login_response, FakeResponse(200)])
    monkeypatch.setattr("authztrace.engine.requests.Session", lambda: session)

    result = run(contract, [_check("alice", "alice", "allow")])[0]

    assert result.outcome == "pass"
    assert session.calls[1][2]["headers"] == expected_header
    assert session.closed is True


def test_login_supports_external_oauth_url_and_custom_bearer_scheme(monkeypatch):
    contract = _contract()
    auth = _login_auth(
        {"from": "json", "path": "access_token"},
        {"type": "bearer", "scheme": "Token"},
    )
    auth["request"].update(
        {
            "path": "https://identity.example.test/oauth/token",
            "json": None,
            "data": {"grant_type": "password", "password": "login-secret"},
            "follow_redirects": False,
        }
    )
    contract.actors = {"alice": Actor("alice", auth)}
    session = FakeSession(
        [FakeResponse(200, body={"access_token": "runtime-token"}), FakeResponse(200)]
    )
    monkeypatch.setattr("authztrace.engine.requests.Session", lambda: session)

    result = run(contract, [_check("alice", "alice", "allow")])[0]

    assert result.outcome == "pass"
    login_call = session.calls[0]
    assert login_call[1] == "https://identity.example.test/oauth/token"
    assert login_call[2]["data"] == {
        "grant_type": "password",
        "password": "login-secret",
    }
    assert login_call[2]["allow_redirects"] is False
    assert session.calls[1][2]["headers"] == {"Authorization": "Token runtime-token"}
    assert session.closed is True


def test_login_failure_aborts_preflight_and_hides_response_body(monkeypatch):
    contract = _contract()
    contract.actors = {
        "alice": Actor(
            "alice",
            _login_auth(
                {"from": "json", "path": "access_token"}, {"type": "bearer"}
            ),
        )
    }
    session = FakeSession([FakeResponse(401, text="sensitive-login-response")])
    monkeypatch.setattr("authztrace.engine.requests.Session", lambda: session)

    results = run(
        contract,
        [
            _check("alice", "alice", "allow"),
            _check("alice", "bob", "deny"),
        ],
    )

    assert [(result.outcome, result.category) for result in results] == [
        ("error", "setup"),
        ("skipped", "setup"),
    ]
    assert results[0].status == 401
    assert "sensitive-login-response" not in results[0].note
    assert len(session.calls) == 1


@pytest.mark.parametrize(
    "login_response",
    [
        FakeResponse(200, body={}),
        requests.ConnectionError("identity service unavailable"),
    ],
)
def test_missing_or_unreachable_login_is_a_setup_error(monkeypatch, login_response):
    contract = _contract()
    contract.actors = {
        "alice": Actor(
            "alice",
            _login_auth(
                {"from": "json", "path": "access_token"}, {"type": "bearer"}
            ),
        )
    }
    session = FakeSession([login_response])
    monkeypatch.setattr("authztrace.engine.requests.Session", lambda: session)

    result = run(contract, [_check("alice", "alice", "allow")])[0]

    assert result.outcome == "error"
    assert result.category == "setup"
    assert result.note.startswith("setup: login for actor 'alice' failed:")
    assert "identity service unavailable" not in result.note
