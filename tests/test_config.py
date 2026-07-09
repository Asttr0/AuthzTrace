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
