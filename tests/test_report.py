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
