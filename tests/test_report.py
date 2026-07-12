import json

from authztrace.models import Check, Result
from authztrace.report import to_json, to_sarif


def _bola_result(object_id: str) -> Result:
    return Result(
        check=Check(
            name="bob attacks invoice",
            resource="invoice",
            actor="bob",
            method="GET",
            path=f"/api/invoices/{object_id}",
            path_template="/api/invoices/{id}",
            target_owner="alice",
            object_id=object_id,
            expect="deny",
        ),
        status=200,
        outcome="fail",
        category="bola",
        note="BOLA: bob accessed alice's invoice",
    )


def test_json_output_includes_category_without_auth_tokens():
    result = _bola_result("inv_alice_001")

    output = to_json([result])
    data = json.loads(output)

    assert data["results"][0]["category"] == "bola"
    assert "Authorization" not in output
    assert "alice-token" not in output
    assert "bob-token" not in output


def test_sarif_fingerprint_uses_endpoint_identity_not_fixture_id():
    first = _bola_result("inv_alice_001")
    second = _bola_result("inv_alice_rotated_999")

    doc = json.loads(to_sarif([first, second]))
    results = doc["runs"][0]["results"]
    fingerprints = [
        result["partialFingerprints"]["authztraceFinding/v1"]
        for result in results
    ]

    assert fingerprints[0] == fingerprints[1]
    assert results[0]["locations"][0]["physicalLocation"]["region"]["startLine"] == 1


def _nested_bola_result(org_id: str, user_id: str, relationship: str) -> Result:
    return Result(
        check=Check(
            name=f"alice attacks nested user [{relationship}]",
            resource="org_user",
            actor="alice",
            method="GET",
            path=f"/orgs/{org_id}/users/{user_id}",
            path_template="/orgs/{org_id}/users/{user_id}",
            target_owner="bob",
            object_id=user_id,
            ids={"org_id": org_id, "user_id": user_id},
            id_sources={"org_id": "alice", "user_id": "bob"},
            relationship=relationship,
            expect="deny",
        ),
        status=200,
        outcome="fail",
        category="bola",
        note="BOLA: alice accessed bob's nested user",
    )


def test_nested_json_exposes_ids_and_relationship_without_credentials():
    result = _nested_bola_result(
        "org_alice_001", "user_bob_001", "org_id=alice,user_id=bob"
    )

    data = json.loads(to_json([result]))["results"][0]

    assert data["ids"] == {"org_id": "org_alice_001", "user_id": "user_bob_001"}
    assert data["id_sources"] == {"org_id": "alice", "user_id": "bob"}
    assert data["relationship"] == "org_id=alice,user_id=bob"


def test_nested_fingerprint_is_stable_across_ids_and_unique_per_relationship():
    first = _nested_bola_result(
        "org_alice_001", "user_bob_001", "org_id=alice,user_id=bob"
    )
    rotated = _nested_bola_result(
        "org_alice_999", "user_bob_999", "org_id=alice,user_id=bob"
    )
    other_relationship = _nested_bola_result(
        "org_bob_999", "user_bob_999", "org_id=bob,user_id=bob"
    )

    findings = json.loads(to_sarif([first, rotated, other_relationship]))["runs"][0][
        "results"
    ]
    fingerprints = [
        finding["partialFingerprints"]["authztraceFinding/v1"]
        for finding in findings
    ]

    assert fingerprints[0] == fingerprints[1]
    assert fingerprints[0] != fingerprints[2]
