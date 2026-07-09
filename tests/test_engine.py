from authztrace.engine import run
from authztrace.models import Actor, Check, Contract, Policy, Resource


class FakeResponse:
    def __init__(self, status_code, text="", body=None):
        self.status_code = status_code
        self.text = text
        self._body = body

    def json(self):
        if self._body is None:
            raise ValueError("no json")
        return self._body


class FakeSession:
    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = []

    def request(self, method, url, **kwargs):
        self.calls.append((method, url, kwargs))
        return self.responses.pop(0)


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
