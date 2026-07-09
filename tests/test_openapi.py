from authztrace.openapi import generate_contract


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
