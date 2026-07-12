from authztrace.config import load_contract
from authztrace.openapi import generate_contract, write_contract


def test_generates_contract_from_single_id_openapi_path(tmp_path):
    spec_file = tmp_path / "openapi.yaml"
    spec_file.write_text(
        """
openapi: 3.1.0
servers:
  - url: http://api.example.test
paths:
  /api/invoices/{invoice_id}:
    get:
      operationId: getInvoice
      parameters:
        - name: invoice_id
          in: path
          required: true
          schema: { type: string }
    delete:
      operationId: deleteInvoice
      parameters:
        - name: invoice_id
          in: path
          required: true
          schema: { type: string }
""",
        encoding="utf-8",
    )

    contract = generate_contract(str(spec_file))

    assert contract["base_url"] == "http://api.example.test"
    assert "invoice" in contract["resources"]
    endpoints = contract["resources"]["invoice"]["endpoints"]
    assert endpoints == [
        {"name": "getInvoice", "request": "GET /api/invoices/{id}"},
        {"name": "deleteInvoice", "request": "DELETE /api/invoices/{id}"},
    ]


def test_generates_contract_from_query_id_openapi_param(tmp_path):
    spec_file = tmp_path / "openapi.yaml"
    spec_file.write_text(
        """
openapi: 3.1.0
paths:
  /api/invoices:
    get:
      operationId: queryInvoice
      parameters:
        - name: id
          in: query
          schema: { type: string }
""",
        encoding="utf-8",
    )

    contract = generate_contract(str(spec_file), base_url="http://localhost:8000")

    endpoint = contract["resources"]["invoice"]["endpoints"][0]
    assert contract["base_url"] == "http://localhost:8000"
    assert endpoint == {
        "name": "queryInvoice",
        "method": "GET",
        "path": "/api/invoices",
        "query": {"id": "{id}"},
    }


def test_resource_name_only_removes_one_plural_suffix(tmp_path):
    spec_file = tmp_path / "openapi.yaml"
    spec_file.write_text(
        """
openapi: 3.1.0
paths:
  /api/access/{access_id}:
    get:
      operationId: getAccess
      parameters:
        - name: access_id
          in: path
          required: true
          schema: { type: string }
""",
        encoding="utf-8",
    )

    contract = generate_contract(str(spec_file), base_url="http://localhost:8000")

    assert "access" in contract["resources"]


def test_generates_loadable_named_ids_for_nested_openapi_path(tmp_path, monkeypatch):
    spec_file = tmp_path / "openapi.yaml"
    spec_file.write_text(
        """
openapi: 3.1.0
paths:
  /orgs/{org_id}/users/{user_id}:
    get:
      operationId: getOrganizationUser
      parameters:
        - { name: org_id, in: path, required: true, schema: { type: string } }
        - { name: user_id, in: path, required: true, schema: { type: string } }
""",
        encoding="utf-8",
    )

    generated = generate_contract(str(spec_file), base_url="http://localhost:8000")
    resource = generated["resources"]["user_by_org_id_user_id"]

    assert resource == {
        "target_id": "user_id",
        "ids": {
            "alice": {
                "org_id": "${ALICE_USER_ORG_ID}",
                "user_id": "${ALICE_USER_USER_ID}",
            },
            "bob": {
                "org_id": "${BOB_USER_ORG_ID}",
                "user_id": "${BOB_USER_USER_ID}",
            },
        },
        "endpoints": [
            {
                "name": "getOrganizationUser",
                "request": "GET /orgs/{org_id}/users/{user_id}",
            }
        ],
    }

    for name, value in {
        "ALICE_USER_ORG_ID": "org_a",
        "ALICE_USER_USER_ID": "user_a",
        "BOB_USER_ORG_ID": "org_b",
        "BOB_USER_USER_ID": "user_b",
    }.items():
        monkeypatch.setenv(name, value)
    contract_file = tmp_path / "authztrace.yaml"
    write_contract(generated, str(contract_file))

    loaded = load_contract(str(contract_file))

    assert loaded.resources["user_by_org_id_user_id"].target_id == "user_id"
