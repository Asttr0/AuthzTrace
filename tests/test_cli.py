import json

from authztrace.cli import main


def _source(tmp_path, with_owner=True):
    owner_guard = "Invoice.owner_id == current_user.id" if with_owner else "True"
    (tmp_path / "app.py").write_text(
        f"""
from fastapi import FastAPI, Depends

app = FastAPI()

@app.get("/invoices/{{invoice_id}}")
def get_invoice(invoice_id: str, current_user=Depends(get_current_user)):
    invoice = db.query(Invoice).filter(Invoice.id == invoice_id).first()
    if not ({owner_guard}):
        raise Forbidden()
    return invoice
""",
        encoding="utf-8",
    )


def test_source_init_non_interactive_compiles_only_probable_policies(tmp_path):
    _source(tmp_path)
    output = tmp_path / "authztrace.yaml"
    evidence = tmp_path / "evidence.json"

    code = main(
        [
            "init",
            "--from-source",
            str(tmp_path),
            "--non-interactive",
            "--accept-probable",
            "--output",
            str(output),
            "--evidence",
            str(evidence),
        ]
    )

    assert code == 0
    assert output.exists()
    assert json.loads(evidence.read_text(encoding="utf-8"))["summary"] == {
        "diagnostics": 0,
        "object_routes": 1,
        "probable_policies": 1,
        "unresolved_policies": 0,
    }


def test_source_init_does_not_write_contract_for_unresolved_policy(tmp_path):
    _source(tmp_path, with_owner=False)
    output = tmp_path / "authztrace.yaml"
    evidence = tmp_path / "authztrace.evidence.json"

    code = main(
        [
            "init",
            "--from-source",
            str(tmp_path),
            "--non-interactive",
            "--accept-probable",
            "--output",
            str(output),
        ]
    )

    assert code == 2
    assert not output.exists()
    assert evidence.exists()
    route = json.loads(evidence.read_text(encoding="utf-8"))["routes"][0]
    assert route["policy"]["state"] == "unresolved"
    assert route["decision"] == "unresolved"
