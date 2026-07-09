from authztrace.matrix import generate
from authztrace.models import Actor, Contract, Endpoint, Policy, Resource


def _contract():
    actors = {n: Actor(n) for n in ("alice", "bob", "anon", "admin")}
    resources = {
        "invoice": Resource(
            name="invoice",
            endpoints=[Endpoint(name="read", method="GET", path="/api/invoices/{id}")],
            ids={"alice": "a1", "bob": "b1"},
        )
    }
    return Contract("http://x", actors, resources, Policy())


def test_matrix_is_full_cross_product():
    # 1 endpoint x 2 objects x 4 actors
    assert len(generate(_contract())) == 8


def test_only_owner_is_allowed():
    for chk in generate(_contract()):
        expected = "allow" if chk.actor == chk.target_owner else "deny"
        assert chk.expect == expected


def test_ids_are_substituted_into_path():
    paths = {chk.path for chk in generate(_contract())}
    assert paths == {"/api/invoices/a1", "/api/invoices/b1"}


def test_query_and_json_body_are_templated():
    contract = _contract()
    contract.resources["invoice"].endpoints = [
        Endpoint(
            name="lookup",
            method="POST",
            path="/api/invoices/lookup",
            query={"actor": "{actor}"},
            json={"invoice_id": "{id}", "owner": "{owner}"},
        )
    ]

    check = next(
        chk for chk in generate(contract) if chk.actor == "bob" and chk.target_owner == "alice"
    )

    assert check.query == {"actor": "bob"}
    assert check.json == {"invoice_id": "a1", "owner": "alice"}


def test_named_actor_can_be_allowed_for_all_objects():
    contract = _contract()
    contract.resources["invoice"].endpoints = [
        Endpoint(
            name="admin read",
            method="GET",
            path="/api/invoices/{id}",
            allow=["owner", "admin"],
        )
    ]

    admin_checks = [chk for chk in generate(contract) if chk.actor == "admin"]

    assert admin_checks
    assert {chk.expect for chk in admin_checks} == {"allow"}
