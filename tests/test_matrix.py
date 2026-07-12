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


def test_generated_checks_keep_endpoint_safety_and_template():
    contract = _contract()
    contract.resources["invoice"].endpoints = [
        Endpoint(
            name="lookup",
            method="POST",
            path="/api/invoices/lookup",
            safe=True,
        )
    ]

    check = generate(contract)[0]

    assert check.safe is True
    assert check.path_template == "/api/invoices/lookup"
    assert check.endpoint_name == "lookup"


def _nested_contract():
    return Contract(
        "http://x",
        {name: Actor(name) for name in ("alice", "bob")},
        {
            "org_user": Resource(
                name="org_user",
                target_id="user_id",
                ids={
                    "alice": {"org_id": "org_a", "user_id": "user_a"},
                    "bob": {"org_id": "org_b", "user_id": "user_b"},
                },
                endpoints=[
                    Endpoint(
                        name="read org user",
                        method="GET",
                        path="/orgs/{org_id}/users/{user_id}",
                        query={"subject": "{user_id}"},
                        headers={"X-Organization": "{org_id}"},
                        json={"organization": "{org_id}", "user": "{user_id}"},
                        data={"target": "{id}"},
                    )
                ],
            )
        },
        Policy(),
    )


def test_named_ids_generate_every_parent_child_ownership_permutation():
    checks = [check for check in generate(_nested_contract()) if check.actor == "alice"]

    assert len(checks) == 4
    assert {
        check.relationship: (check.target_owner, check.expect)
        for check in checks
    } == {
        "org_id=alice,user_id=alice": ("alice", "allow"),
        "org_id=alice,user_id=bob": ("bob", "deny"),
        "org_id=bob,user_id=alice": ("alice", "deny"),
        "org_id=bob,user_id=bob": ("bob", "deny"),
    }


def test_named_ids_render_in_every_request_location_and_keep_sources():
    check = next(
        check
        for check in generate(_nested_contract())
        if check.actor == "alice"
        and check.relationship == "org_id=bob,user_id=alice"
    )

    assert check.path == "/orgs/org_b/users/user_a"
    assert check.query == {"subject": "user_a"}
    assert check.headers == {"X-Organization": "org_b"}
    assert check.json == {"organization": "org_b", "user": "user_a"}
    assert check.data == {"target": "user_a"}
    assert check.object_id == "user_a"
    assert check.ids == {"org_id": "org_b", "user_id": "user_a"}
    assert check.id_sources == {"org_id": "bob", "user_id": "alice"}
    assert check.name.endswith("[org_id=bob,user_id=alice]")
