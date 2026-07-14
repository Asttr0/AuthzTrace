import json

import pytest

from authztrace.config import load_contract
from authztrace.inference import (
    UnresolvedPolicyError,
    compile_contract,
    discover_source,
    read_decisions,
    review_policies,
    write_evidence,
)
from authztrace.openapi import write_contract


def _write_fastapi_app(tmp_path, handler_body, *, route="/{invoice_id}"):
    source = tmp_path / "app.py"
    source.write_text(
        f"""
from fastapi import APIRouter, Depends, HTTPException

router = APIRouter(prefix="/api/invoices")

def get_current_user(): ...
def get_db(): ...

@router.get("{route}", operation_id="getInvoice")
def get_invoice(invoice_id: str, current_user=Depends(get_current_user), db=Depends(get_db)):
{handler_body}
""",
        encoding="utf-8",
    )
    return source


def test_discovers_fastapi_route_authentication_resource_and_ownership(tmp_path):
    _write_fastapi_app(
        tmp_path,
        """    invoice = db.query(Invoice).filter(Invoice.id == invoice_id).first()
    if invoice.owner_id != current_user.id:
        raise HTTPException(403)
    return invoice""",
    )

    discovery = discover_source(str(tmp_path))
    route = discovery.routes[0]

    assert discovery.framework == "fastapi"
    assert discovery.files_scanned == 1
    assert route.key == "GET /api/invoices/{invoice_id}"
    assert route.resource == "invoice"
    assert route.id_fields == ["invoice_id"]
    assert route.id_locations == {"invoice_id": "path"}
    assert route.principal == "current_user"
    assert route.auth_dependencies == ["get_current_user"]
    assert route.resource_model == "Invoice"
    assert route.owner_field == "invoice.owner_id"
    assert route.principal_field == "current_user.id"
    assert route.policy_state == "probable"
    assert route.suggested_allow == ["owner"]
    assert route.evidence[-1].source.path == "app.py"


def test_missing_ownership_guard_stays_unresolved_even_when_authenticated(tmp_path):
    _write_fastapi_app(
        tmp_path,
        """    return db.query(Invoice).filter(Invoice.id == invoice_id).first()""",
    )

    discovery = discover_source(str(tmp_path))
    route = discovery.routes[0]

    assert route.auth_dependencies == ["get_current_user"]
    assert route.resource_model == "Invoice"
    assert route.policy_state == "unresolved"
    assert route.suggested_allow is None
    with pytest.raises(UnresolvedPolicyError, match="GET /api/invoices"):
        review_policies(discovery, accept_probable=True, interactive=False)


def test_unused_ownership_comparison_is_not_treated_as_an_authorization_guard(tmp_path):
    _write_fastapi_app(
        tmp_path,
        """    invoice = db.query(Invoice).filter(Invoice.id == invoice_id).first()
    is_owner = invoice.owner_id == current_user.id
    return {"invoice": invoice, "is_owner": is_owner}""",
    )

    route = discover_source(str(tmp_path)).routes[0]

    assert route.policy_state == "unresolved"
    assert route.suggested_allow is None
    assert route.owner_field == ""


def test_compiles_confirmed_source_policy_into_loadable_contract(tmp_path, monkeypatch):
    _write_fastapi_app(
        tmp_path,
        """    invoice = db.query(Invoice).filter(Invoice.id == invoice_id).first()
    if invoice.owner_id != current_user.id:
        raise HTTPException(403)
    return invoice""",
    )
    discovery = discover_source(str(tmp_path), base_url="http://api.example.test")
    decisions = review_policies(discovery, accept_probable=True, interactive=False)

    generated = compile_contract(discovery, decisions)

    assert generated["resources"]["invoice"]["endpoints"] == [
        {
            "name": "getInvoice",
            "request": "GET /api/invoices/{id}",
            "allow": ["owner"],
        }
    ]
    for name, value in {
        "ALICE_TOKEN": "alice-token",
        "BOB_TOKEN": "bob-token",
        "ALICE_INVOICE_ID": "inv_a",
        "BOB_INVOICE_ID": "inv_b",
    }.items():
        monkeypatch.setenv(name, value)
    contract_path = tmp_path / "authztrace.yaml"
    write_contract(generated, str(contract_path))

    loaded = load_contract(str(contract_path))

    assert loaded.base_url == "http://api.example.test"
    assert loaded.resources["invoice"].ids == {"alice": "inv_a", "bob": "inv_b"}
    assert loaded.resources["invoice"].endpoints[0].allow == ["owner"]


def test_discovers_nested_routes_and_compiles_named_id_fixtures(tmp_path):
    source = tmp_path / "app.py"
    source.write_text(
        """
from fastapi import APIRouter, Depends

router = APIRouter(prefix="/api")

@router.get("/orgs/{org_id}/users/{user_id}")
def get_org_user(
    org_id: str,
    user_id: str,
    current_user=Depends(get_current_user),
    db=Depends(get_db),
):
    membership = db.query(Membership).filter(Membership.id == user_id).first()
    if membership.user_id != current_user.id:
        raise Forbidden()
    return membership
""",
        encoding="utf-8",
    )

    discovery = discover_source(str(tmp_path))
    route = discovery.routes[0]
    contract = compile_contract(discovery, {route.key: ["owner"]})

    assert route.resource == "user_by_org_id_user_id"
    resource = contract["resources"][route.resource]
    assert resource["target_id"] == "user_id"
    assert resource["ids"]["alice"] == {
        "org_id": "${ALICE_USER_ORG_ID}",
        "user_id": "${ALICE_USER_USER_ID}",
    }
    assert resource["endpoints"][0]["request"] == (
        "GET /api/orgs/{org_id}/users/{user_id}"
    )


def test_resolves_imported_router_include_prefixes(tmp_path):
    package = tmp_path / "api"
    package.mkdir()
    (package / "__init__.py").write_text("", encoding="utf-8")
    (package / "invoices.py").write_text(
        """
from fastapi import APIRouter, Depends

router = APIRouter(prefix="/invoices")

@router.get("/{invoice_id}")
def get_invoice(invoice_id: str, current_user=Depends(get_current_user)):
    if Invoice.owner_id != current_user.id:
        raise Forbidden()
    return Invoice
""",
        encoding="utf-8",
    )
    (tmp_path / "main.py").write_text(
        """
from fastapi import FastAPI
from api.invoices import router as invoice_router

app = FastAPI()
app.include_router(invoice_router, prefix="/v1")
""",
        encoding="utf-8",
    )

    discovery = discover_source(str(tmp_path))

    assert [route.path for route in discovery.routes] == ["/v1/invoices/{invoice_id}"]


def test_openapi_reconciliation_supplies_public_prefix_and_server_url(tmp_path):
    _write_fastapi_app(
        tmp_path,
        """    invoice = db.query(Invoice).filter(Invoice.id == invoice_id).first()
    if invoice.owner_id != current_user.id:
        raise HTTPException(403)
    return invoice""",
        route="/invoices/{invoice_id}",
    )
    spec = tmp_path / "openapi.yaml"
    spec.write_text(
        """
openapi: 3.1.0
servers: [{ url: "http://api.example.test" }]
paths:
  /v1/api/invoices/invoices/{invoice_id}:
    get:
      operationId: getInvoice
      parameters:
        - { name: invoice_id, in: path, required: true, schema: { type: string } }
""",
        encoding="utf-8",
    )

    discovery = discover_source(str(tmp_path), openapi=str(spec))
    route = discovery.routes[0]

    assert discovery.base_url == "http://api.example.test"
    assert route.path == "/v1/api/invoices/invoices/{invoice_id}"
    assert route.policy_state == "probable"
    assert {item.kind for item in route.evidence} >= {"openapi_route", "ownership"}


def test_openapi_inventory_survives_when_source_route_is_dynamic_or_undiscovered(tmp_path):
    (tmp_path / "app.py").write_text(
        """
from fastapi import FastAPI

app = FastAPI()
register_routes_dynamically(app)
""",
        encoding="utf-8",
    )
    spec = tmp_path / "openapi.yaml"
    spec.write_text(
        """
openapi: 3.1.0
paths:
  /invoices/{invoice_id}:
    get:
      operationId: getInvoice
      parameters:
        - { name: invoice_id, in: path, required: true, schema: { type: string } }
""",
        encoding="utf-8",
    )

    discovery = discover_source(str(tmp_path), openapi=str(spec))
    route = discovery.routes[0]

    assert route.key == "GET /invoices/{invoice_id}"
    assert route.policy_state == "unresolved"
    assert route.suggested_allow is None
    assert [item.kind for item in route.evidence] == ["openapi_route"]


def test_query_identifier_is_emitted_in_structured_endpoint(tmp_path):
    source = tmp_path / "app.py"
    source.write_text(
        """
from fastapi import FastAPI, Depends

app = FastAPI()

@app.get("/api/invoices/search")
def find_invoice(invoice_id: str, current_user=Depends(get_current_user)):
    if Invoice.owner_id != current_user.id:
        raise Forbidden()
    return Invoice
""",
        encoding="utf-8",
    )

    discovery = discover_source(str(tmp_path))
    route = discovery.routes[0]
    contract = compile_contract(discovery, {route.key: ["owner"]})

    assert route.id_locations == {"invoice_id": "query"}
    assert contract["resources"]["invoice"]["endpoints"][0] == {
        "name": "find_invoice",
        "request": "GET /api/invoices/search",
        "allow": ["owner"],
        "query": {"invoice_id": "{id}"},
    }


def test_openapi_parameter_alias_is_preserved_as_http_query_name(tmp_path):
    source = tmp_path / "app.py"
    source.write_text(
        """
from fastapi import FastAPI, Depends, Query

app = FastAPI()

@app.get("/api/invoices/search", operation_id="findInvoice")
def find_invoice(
    invoice_id: str = Query(alias="invoice-id"),
    current_user=Depends(get_current_user),
):
    if Invoice.owner_id != current_user.id:
        raise Forbidden()
    return Invoice
""",
        encoding="utf-8",
    )
    spec = tmp_path / "openapi.yaml"
    spec.write_text(
        """
openapi: 3.1.0
paths:
  /api/invoices/search:
    get:
      operationId: findInvoice
      parameters:
        - { name: invoice-id, in: query, schema: { type: string } }
""",
        encoding="utf-8",
    )

    discovery = discover_source(str(tmp_path), openapi=str(spec))
    route = discovery.routes[0]
    contract = compile_contract(discovery, {route.key: ["owner"]})

    assert route.id_fields == ["invoice_id"]
    assert route.id_request_names == {"invoice_id": "invoice-id"}
    assert contract["resources"]["invoice"]["endpoints"][0]["query"] == {
        "invoice-id": "{id}"
    }


def test_role_dependency_is_evidence_but_not_an_inferred_owner_policy(tmp_path):
    (tmp_path / "app.py").write_text(
        """
from fastapi import FastAPI, Depends

app = FastAPI()

@app.get("/admin/users/{user_id}", dependencies=[Depends(require_role("admin"))])
def get_admin_user(user_id: str):
    return db.get(User, user_id)
""",
        encoding="utf-8",
    )

    route = discover_source(str(tmp_path)).routes[0]

    assert route.policy_state == "unresolved"
    assert route.suggested_allow is None
    assert "require_role" in route.auth_dependencies
    assert "authorization_guard" in {item.kind for item in route.evidence}


def test_static_discovery_never_executes_target_module(tmp_path):
    marker = tmp_path / "imported.txt"
    (tmp_path / "app.py").write_text(
        f"""
from pathlib import Path
from fastapi import FastAPI, Depends

Path({str(marker)!r}).write_text("executed")
app = FastAPI()

@app.get("/invoices/{{invoice_id}}")
def get_invoice(invoice_id: str, current_user=Depends(get_current_user)):
    if Invoice.owner_id != current_user.id:
        raise Forbidden()
    return Invoice
""",
        encoding="utf-8",
    )

    discovery = discover_source(str(tmp_path))

    assert discovery.routes
    assert not marker.exists()


def test_interactive_review_requires_explicit_choice_for_unresolved_route(tmp_path):
    _write_fastapi_app(
        tmp_path,
        """    return db.query(Invoice).filter(Invoice.id == invoice_id).first()""",
    )
    discovery = discover_source(str(tmp_path))
    answers = iter(["o"])

    decisions = review_policies(
        discovery,
        input_fn=lambda _: next(answers),
        output=lambda _: None,
    )

    assert decisions == {"GET /api/invoices/{invoice_id}": ["owner"]}


def test_evidence_output_is_deterministic_and_contains_no_source_text(tmp_path):
    _write_fastapi_app(
        tmp_path,
        """    invoice = db.query(Invoice).filter(Invoice.id == invoice_id).first()
    if invoice.owner_id != current_user.id:
        raise HTTPException(403)
    return invoice""",
    )
    discovery = discover_source(str(tmp_path))
    route = discovery.routes[0]
    first = tmp_path / "first.json"
    second = tmp_path / "second.json"

    write_evidence(discovery, str(first), {route.key: ["owner"]})
    write_evidence(discovery, str(second), {route.key: ["owner"]})

    assert first.read_bytes() == second.read_bytes()
    data = json.loads(first.read_text(encoding="utf-8"))
    assert data["root"] == "."
    assert data["routes"][0]["decision"] == ["owner"]
    assert "alice-token" not in first.read_text(encoding="utf-8")


def test_reviewed_decisions_can_be_reused_but_do_not_cover_new_routes(tmp_path):
    _write_fastapi_app(
        tmp_path,
        """    invoice = db.query(Invoice).filter(Invoice.id == invoice_id).first()
    if invoice.owner_id != current_user.id:
        raise HTTPException(403)
    return invoice""",
    )
    initial = discover_source(str(tmp_path))
    initial_route = initial.routes[0]
    evidence = tmp_path / "evidence.json"
    write_evidence(initial, str(evidence), {initial_route.key: ["owner"]})
    with (tmp_path / "app.py").open("a", encoding="utf-8") as source:
        source.write(
            """

@router.get("/{invoice_id}/audit")
def get_invoice_audit(invoice_id: str, current_user=Depends(get_current_user)):
    return db.query(Invoice).filter(Invoice.id == invoice_id).first()
"""
        )

    changed = discover_source(str(tmp_path))
    existing = read_decisions(str(evidence))

    assert existing == {initial_route.key: ["owner"]}
    with pytest.raises(UnresolvedPolicyError) as error:
        review_policies(changed, existing=existing, interactive=False)
    assert error.value.routes == ["GET /api/invoices/{invoice_id}/audit"]
