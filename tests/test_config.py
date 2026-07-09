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
