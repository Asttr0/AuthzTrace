"""Replay every check against the live API and grade it against the contract."""
from __future__ import annotations

import base64
import time
from typing import Any

import requests

from .models import Check, Contract, Result


def _headers(auth: dict) -> dict:
    kind = (auth or {}).get("type", "none")
    if kind == "bearer":
        return {"Authorization": f"Bearer {auth.get('token', '')}"}
    if kind == "header":
        return {auth.get("name", "X-API-Key"): auth.get("value", "")}
    if kind == "cookie":
        return {"Cookie": f"{auth.get('name', 'session')}={auth.get('value', '')}"}
    if kind == "basic":
        raw = f"{auth.get('username', '')}:{auth.get('password', '')}".encode()
        return {"Authorization": "Basic " + base64.b64encode(raw).decode("ascii")}
    return {}


def _is_allowed_status(contract: Contract, status: int) -> bool:
    if contract.policy.allow_status:
        return status in contract.policy.allow_status
    return 200 <= status < 300


def _field_exists(value: Any, path: str) -> bool:
    current = value
    for part in path.split("."):
        if isinstance(current, dict) and part in current:
            current = current[part]
            continue
        if isinstance(current, list) and part.isdigit() and int(part) < len(current):
            current = current[int(part)]
            continue
        return False
    return True


def _assertions(resp: requests.Response, check: Check) -> list[str]:
    failures: list[str] = []
    assertions = check.assertions or {}

    if check.expect == "deny":
        denied_markers = assertions.get("deny_not_contains") or assertions.get("not_contains") or []
        if isinstance(denied_markers, str):
            denied_markers = [denied_markers]
        for marker in denied_markers:
            marker = str(marker)
            if marker and marker in resp.text:
                failures.append(f"denied response leaked forbidden marker {marker!r}")

    no_fields = assertions.get("no_fields") or []
    if isinstance(no_fields, str):
        no_fields = [no_fields]
    if no_fields:
        try:
            body = resp.json()
        except ValueError:
            body = None
        if body is not None:
            for field_path in no_fields:
                if _field_exists(body, str(field_path)):
                    failures.append(f"response contains forbidden JSON field {field_path!r}")

    return failures


def run(contract: Contract, checks: list[Check], timeout: float = 10.0) -> list[Result]:
    results: list[Result] = []
    session = requests.Session()

    for chk in checks:
        actor = contract.actors[chk.actor]
        url = contract.base_url + chk.path
        headers = _headers(actor.auth)
        headers.update(chk.headers)
        started = time.monotonic()
        try:
            resp = session.request(
                chk.method,
                url,
                params=chk.query or None,
                headers=headers,
                json=chk.json,
                data=chk.data,
                timeout=timeout,
            )
            elapsed_ms = int((time.monotonic() - started) * 1000)
            status = resp.status_code
        except requests.RequestException as exc:
            results.append(Result(check=chk, status=None, outcome="error", note=str(exc)))
            continue

        allowed = _is_allowed_status(contract, status)

        if chk.expect == "allow":
            if allowed:
                outcome, note = "pass", ""
            else:
                outcome = "warn"
                note = f"owner '{chk.actor}' got {status}, expected 2xx (over-restrictive?)"
        else:  # expect == "deny"
            if allowed:
                outcome = "fail"
                note = (
                    f"BOLA: '{chk.actor}' accessed {chk.target_owner}'s "
                    f"{chk.resource} ({chk.object_id}) - HTTP {status}"
                )
            elif status in contract.policy.deny_status:
                outcome, note = "pass", ""
            else:
                outcome = "warn"
                note = f"denied with {status}, not in deny_status {contract.policy.deny_status}"

        assertion_failures = _assertions(resp, chk)
        if assertion_failures:
            details = "; ".join(assertion_failures)
            note = f"{note}; {details}" if note else details
            if outcome != "fail":
                outcome = "fail"

        results.append(
            Result(
                check=chk,
                status=status,
                outcome=outcome,
                note=note,
                elapsed_ms=elapsed_ms,
            )
        )

    return results
