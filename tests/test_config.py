import pytest

from authztrace.config import load_contract


def test_loads_structured_endpoints_and_explicit_contracts(tmp_path):
    contract_file = tmp_path / "authztrace.yaml"
    contract_file.write_text(
        """
base_url: http://example.test
actors:
  alice: { auth: { type: bearer, token: alice-token } }
  bob: { auth: { type: bearer, token: bob-token } }
resources:
  invoice:
    ids:
      alice: inv_a
      bob: inv_b
    markers:
      alice: "Alice private"
    endpoints:
      - name: lookup
        method: POST
        path: /api/invoices/lookup
        json:
          invoice_id: "{id}"
contracts:
  - name: bob cannot read alice invoice
    as: bob
    resource: invoice
    target_owner: alice
    request: GET /api/invoices/{id}
    expect: deny
policy:
  deny_status: [401, 403, 404]
""",
        encoding="utf-8",
    )

    contract = load_contract(str(contract_file))

    assert contract.resources["invoice"].endpoints[0].json == {"invoice_id": "{id}"}
    assert contract.checks[0].path == "/api/invoices/inv_a"
    assert contract.checks[0].actor == "bob"


def test_explicit_string_request_keeps_sibling_request_fields(tmp_path):
    contract_file = tmp_path / "authztrace.yaml"
    contract_file.write_text(
        """
base_url: http://example.test
actors:
  alice: { auth: { type: bearer, token: alice-token } }
  bob: { auth: { type: bearer, token: bob-token } }
resources:
  invoice:
    ids:
      alice: 123
    endpoints:
      - GET /api/invoices/{id}
contracts:
  - name: body id survives
    as: bob
    resource: invoice
    target_owner: alice
    request: POST /api/invoices/lookup
    query:
      debug: true
    json:
      invoice_id: "{id}"
    headers:
      X-Test-Actor: "{actor}"
    expect: deny
""",
        encoding="utf-8",
    )

    check = load_contract(str(contract_file)).checks[0]

    assert check.path == "/api/invoices/lookup"
    assert check.query == {"debug": True}
    assert check.json == {"invoice_id": 123}
    assert check.headers == {"X-Test-Actor": "bob"}


def test_endpoint_safe_overrides_method_defaults(tmp_path):
    contract_file = tmp_path / "authztrace.yaml"
    contract_file.write_text(
        """
base_url: http://example.test
actors:
  alice: { auth: { type: bearer, token: alice-token } }
resources:
  invoice:
    ids:
      alice: inv_a
    endpoints:
      - name: lookup is read-like
        request: POST /api/invoices/lookup
        safe: true
      - name: side effecting get
        request: GET /api/invoices/{id}/recalculate
        safe: false
contracts:
  - name: explicit read-like post
    as: alice
    request: POST /api/invoices/lookup
    safe: true
    expect: allow
""",
        encoding="utf-8",
    )

    contract = load_contract(str(contract_file))
    endpoints = contract.resources["invoice"].endpoints

    assert endpoints[0].safe is True
    assert endpoints[1].safe is False
    assert contract.checks[0].safe is True


def test_unknown_actor_fails_at_load_time(tmp_path):
    contract_file = tmp_path / "authztrace.yaml"
    contract_file.write_text(
        """
base_url: http://example.test
actors:
  alice: { auth: { type: bearer, token: alice-token } }
resources:
  invoice:
    ids:
      alice: inv_a
    endpoints:
      - GET /api/invoices/{id}
contracts:
  - name: typo actor
    as: alcie
    resource: invoice
    target_owner: alice
    request: GET /api/invoices/{id}
""",
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="unknown actor"):
        load_contract(str(contract_file))


def test_unknown_resource_fails_at_load_time(tmp_path):
    contract_file = tmp_path / "authztrace.yaml"
    contract_file.write_text(
        """
base_url: http://example.test
actors:
  alice: { auth: { type: bearer, token: alice-token } }
resources:
  invoice:
    ids:
      alice: inv_a
    endpoints:
      - GET /api/invoices/{id}
contracts:
  - name: typo resource
    as: alice
    resource: invocie
    request: GET /api/invoices/{id}
""",
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="unknown resource"):
        load_contract(str(contract_file))


def test_loads_and_normalizes_login_auth(tmp_path, monkeypatch):
    monkeypatch.setenv("ALICE_PASSWORD", "demo-password")
    contract_file = tmp_path / "authztrace.yaml"
    contract_file.write_text(
        """
base_url: http://example.test
actors:
  alice:
    auth:
      type: login
      request: POST /api/login
      headers: { X-Login-Client: authztrace }
      json: { username: alice, password: "${ALICE_PASSWORD}" }
      extract: { from: json, path: session.access_token }
      credential: bearer
      expect_status: [200, 201]
resources:
  invoice:
    ids: { alice: inv_a }
    endpoints:
      - GET /api/invoices/{id}
""",
        encoding="utf-8",
    )

    auth = load_contract(str(contract_file)).actors["alice"].auth

    assert auth == {
        "type": "login",
        "request": {
            "method": "POST",
            "path": "/api/login",
            "query": {},
            "headers": {"X-Login-Client": "authztrace"},
            "json": {"username": "alice", "password": "demo-password"},
            "data": None,
            "follow_redirects": True,
        },
        "extract": {"from": "json", "path": "session.access_token"},
        "credential": {"type": "bearer"},
        "expect_status": [200, 201],
    }


@pytest.mark.parametrize(
    ("auth_yaml", "message"),
    [
        (
            """request: POST /api/login
      credential: bearer""",
            "extract object",
        ),
        (
            """request: POST /api/login
      extract: { from: body, path: token }
      credential: bearer""",
            "extract.from",
        ),
        (
            """request: POST ftp://identity.example.test/login
      extract: { from: json, path: token }
      credential: bearer""",
            "relative path or HTTP",
        ),
        (
            """request:
        method: POST
        path: /api/login
        follow_redirects: sometimes
      extract: { from: json, path: token }
      credential: bearer""",
            "follow_redirects",
        ),
        (
            """request: POST /api/login
      extract: { from: json, path: token }
      credential:
        type: header
        name: Authorization
        template: Token""",
            "template must contain",
        ),
        (
            """request: POST /api/login
      extract: { from: json, path: token }
      credential: bearer
      expect_status: [99]""",
            "invalid HTTP status",
        ),
        (
            """request: POST /api/login
      follow_redirect: false
      extract: { from: json, path: token }
      credential: bearer""",
            "unknown field",
        ),
        (
            """request:
        method: POST
        path: /api/login
        query: { client: web }
        params: { tenant: one }
      extract: { from: json, path: token }
      credential: bearer""",
            "query and params",
        ),
    ],
)
def test_rejects_invalid_login_auth(tmp_path, auth_yaml, message):
    contract_file = tmp_path / "authztrace.yaml"
    contract_file.write_text(
        f"""
base_url: http://example.test
actors:
  alice:
    auth:
      type: login
      {auth_yaml}
resources:
  invoice:
    ids: {{ alice: inv_a }}
    endpoints:
      - GET /api/invoices/{{id}}
""",
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match=message):
        load_contract(str(contract_file))


def test_login_supports_external_oauth_form_and_custom_header(tmp_path):
    contract_file = tmp_path / "authztrace.yaml"
    contract_file.write_text(
        """
base_url: https://api.example.test
actors:
  service_user:
    auth:
      type: login
      request:
        method: POST
        url: https://identity.example.test/oauth/token
        data: { grant_type: password, username: service-user, password: secret }
        follow_redirects: false
      extract: { from: json, path: access_token }
      credential:
        type: header
        name: Authorization
        template: "Token {value}"
resources:
  invoice:
    ids: { service_user: inv_a }
    endpoints:
      - GET /api/invoices/{id}
""",
        encoding="utf-8",
    )

    auth = load_contract(str(contract_file)).actors["service_user"].auth

    assert auth["request"] == {
        "method": "POST",
        "path": "https://identity.example.test/oauth/token",
        "query": {},
        "headers": {},
        "json": None,
        "data": {
            "grant_type": "password",
            "username": "service-user",
            "password": "secret",
        },
        "follow_redirects": False,
    }
    assert auth["credential"] == {
        "type": "header",
        "name": "Authorization",
        "template": "Token {value}",
    }
