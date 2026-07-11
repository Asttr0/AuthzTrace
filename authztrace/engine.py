"""Replay every check against the live API and grade it against the contract."""
from __future__ import annotations

import base64
import time
from dataclasses import dataclass
from typing import Any

import requests

from .models import Check, Contract, Result

_MISSING = object()


@dataclass
class _LoginResult:
    auth: dict | None
    status: int | None = None
    note: str = ""
    elapsed_ms: int | None = None


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


def _field_value(value: Any, path: str) -> Any:
    current = value
    for part in path.split("."):
        if isinstance(current, dict) and part in current:
            current = current[part]
            continue
        if isinstance(current, list) and part.isdigit() and int(part) < len(current):
            current = current[int(part)]
            continue
        return _MISSING
    return current


def _field_exists(value: Any, path: str) -> bool:
    return _field_value(value, path) is not _MISSING


def _login_credential(
    session: requests.Session,
    resp: requests.Response,
    auth: dict,
) -> tuple[Any, str]:
    extract = auth["extract"]
    source = extract["from"]
    if source == "json":
        try:
            body = resp.json()
        except ValueError:
            return _MISSING, "response was not valid JSON"
        value = _field_value(body, extract["path"])
        location = f"JSON path {extract['path']!r}"
    elif source == "header":
        value = resp.headers.get(extract["name"], _MISSING)
        location = f"response header {extract['name']!r}"
    else:
        try:
            value = resp.cookies.get(extract["name"], _MISSING)
            if value is _MISSING:
                value = session.cookies.get(extract["name"], _MISSING)
        except requests.cookies.CookieConflictError:
            return _MISSING, f"response cookie {extract['name']!r} was ambiguous"
        location = f"response cookie {extract['name']!r}"

    if value is _MISSING or value is None or value == "":
        return _MISSING, f"{location} was missing or empty"
    return value, ""


def _resolved_credential(auth: dict, value: Any) -> dict:
    credential = auth["credential"]
    kind = credential["type"]
    if kind == "bearer":
        scheme = credential.get("scheme", "Bearer")
        if scheme != "Bearer":
            return {
                "type": "header",
                "name": "Authorization",
                "value": f"{scheme} {value}",
            }
        return {"type": "bearer", "token": str(value)}
    if kind == "header":
        rendered = credential.get("template", "{value}").replace("{value}", str(value))
        return {"type": "header", "name": credential["name"], "value": rendered}
    if auth["extract"]["from"] == "cookie" and credential["name"] == auth["extract"]["name"]:
        return {"type": "none"}
    return {"type": kind, "name": credential["name"], "value": str(value)}


def _login_actor(
    session: requests.Session,
    contract: Contract,
    actor_name: str,
    timeout: float,
) -> _LoginResult:
    auth = contract.actors[actor_name].auth
    if (auth or {}).get("type", "none") != "login":
        return _LoginResult(auth=auth)

    request = auth["request"]
    target = request["path"]
    url = target if target.startswith(("http://", "https://")) else contract.base_url + target
    started = time.monotonic()
    try:
        resp = session.request(
            request["method"],
            url,
            params=request["query"] or None,
            headers=request["headers"] or None,
            json=request["json"],
            data=request["data"],
            timeout=timeout,
            allow_redirects=request["follow_redirects"],
        )
        elapsed_ms = int((time.monotonic() - started) * 1000)
    except requests.RequestException as exc:
        elapsed_ms = int((time.monotonic() - started) * 1000)
        return _LoginResult(
            auth=None,
            note=(
                f"setup: login for actor {actor_name!r} failed: "
                f"request error ({type(exc).__name__})"
            ),
            elapsed_ms=elapsed_ms,
        )

    expected = auth["expect_status"]
    if (expected and resp.status_code not in expected) or (
        not expected and not 200 <= resp.status_code < 300
    ):
        expectation = str(expected) if expected else "a 2xx response"
        return _LoginResult(
            auth=None,
            status=resp.status_code,
            note=(
                f"setup: login for actor {actor_name!r} returned HTTP {resp.status_code}; "
                f"expected {expectation}"
            ),
            elapsed_ms=elapsed_ms,
        )

    value, extraction_error = _login_credential(session, resp, auth)
    if extraction_error:
        return _LoginResult(
            auth=None,
            status=resp.status_code,
            note=f"setup: login for actor {actor_name!r} failed: {extraction_error}",
            elapsed_ms=elapsed_ms,
        )

    return _LoginResult(
        auth=_resolved_credential(auth, value),
        status=resp.status_code,
        elapsed_ms=elapsed_ms,
    )


def _no_field_failures(resp: requests.Response, check: Check) -> list[str]:
    failures: list[str] = []
    assertions = check.assertions or {}

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


def _allow_assertions(resp: requests.Response, check: Check) -> list[str]:
    failures: list[str] = []
    assertions = check.assertions or {}

    allowed_markers = assertions.get("allow_contains") or []
    if isinstance(allowed_markers, str):
        allowed_markers = [allowed_markers]
    for marker in allowed_markers:
        marker = str(marker)
        if marker and marker not in resp.text:
            failures.append(f"allowed response missed required marker {marker!r}")

    failures.extend(_no_field_failures(resp, check))
    return failures


def _deny_assertions(resp: requests.Response, check: Check) -> list[str]:
    failures: list[str] = []
    assertions = check.assertions or {}

    denied_markers = assertions.get("deny_not_contains") or assertions.get("not_contains") or []
    if isinstance(denied_markers, str):
        denied_markers = [denied_markers]
    for marker in denied_markers:
        marker = str(marker)
        if marker and marker in resp.text:
            failures.append(f"denied response leaked forbidden marker {marker!r}")

    failures.extend(_no_field_failures(resp, check))
    return failures


def _setup_target(check: Check) -> str:
    target = check.resource or "resource"
    if check.object_id:
        target = f"{target} ({check.object_id})"
    if check.target_owner:
        target = f"{check.target_owner}'s {target}"
    return target


def _grade_allow(
    contract: Contract,
    check: Check,
    resp: requests.Response,
    elapsed_ms: int,
) -> Result:
    status = resp.status_code
    allowed = _is_allowed_status(contract, status)
    if not allowed:
        return Result(
            check=check,
            status=status,
            outcome="error",
            category="setup",
            note=(
                f"setup: expected '{check.actor}' to access {_setup_target(check)} "
                f"but got HTTP {status}; authorization fixtures or credentials are not trustworthy"
            ),
            elapsed_ms=elapsed_ms,
        )

    assertion_failures = _allow_assertions(resp, check)
    if assertion_failures:
        return Result(
            check=check,
            status=status,
            outcome="error",
            category="setup",
            note="setup: " + "; ".join(assertion_failures),
            elapsed_ms=elapsed_ms,
        )

    return Result(
        check=check,
        status=status,
        outcome="pass",
        category="ok",
        elapsed_ms=elapsed_ms,
    )


def _grade_deny(
    contract: Contract,
    check: Check,
    resp: requests.Response,
    elapsed_ms: int,
) -> Result:
    status = resp.status_code
    allowed = _is_allowed_status(contract, status)

    if allowed:
        outcome = "fail"
        category = "bola"
        note = (
            f"BOLA: '{check.actor}' accessed {check.target_owner}'s "
            f"{check.resource} ({check.object_id}) - HTTP {status}"
        )
    elif status in contract.policy.deny_status:
        outcome, category, note = "pass", "ok", ""
    else:
        outcome = "warn"
        category = "over_restrictive"
        note = f"denied with {status}, not in deny_status {contract.policy.deny_status}"

    assertion_failures = _deny_assertions(resp, check)
    if assertion_failures:
        details = "; ".join(assertion_failures)
        note = f"{note}; {details}" if note else details
        if outcome != "fail":
            outcome = "fail"
            category = "leak"

    return Result(
        check=check,
        status=status,
        outcome=outcome,
        category=category,
        note=note,
        elapsed_ms=elapsed_ms,
    )


def _execute_check(
    session: requests.Session,
    contract: Contract,
    check: Check,
    timeout: float,
    auth: dict | None = None,
) -> Result:
    url = contract.base_url + check.path
    headers = _headers(auth if auth is not None else contract.actors[check.actor].auth)
    headers.update(check.headers)
    started = time.monotonic()
    try:
        resp = session.request(
            check.method,
            url,
            params=check.query or None,
            headers=headers,
            json=check.json,
            data=check.data,
            timeout=timeout,
        )
        elapsed_ms = int((time.monotonic() - started) * 1000)
    except requests.RequestException as exc:
        elapsed_ms = int((time.monotonic() - started) * 1000)
        return Result(
            check=check,
            status=None,
            outcome="error",
            category="setup",
            note=f"setup: request failed ({type(exc).__name__})",
            elapsed_ms=elapsed_ms,
        )

    if check.expect == "allow":
        return _grade_allow(contract, check, resp, elapsed_ms)
    return _grade_deny(contract, check, resp, elapsed_ms)


def _unsafe_skipped(check: Check) -> Result:
    return Result(
        check=check,
        status=None,
        outcome="skipped",
        category="unsafe_skipped",
        note=(
            f"unsafe {check.method} skipped in read-only mode; mark the endpoint "
            "safe: true or pass --include-unsafe to execute it"
        ),
    )


def _setup_skipped(check: Check) -> Result:
    return Result(
        check=check,
        status=None,
        outcome="skipped",
        category="setup",
        note="skipped because preflight failed; fix setup errors before trusting attack rows",
    )


def _run_with_sessions(
    contract: Contract,
    checks: list[Check],
    timeout: float,
    executable_indices: list[int],
    results_by_index: dict[int, Result],
    sessions: dict[str, requests.Session],
) -> list[Result]:
    resolved_auth: dict[str, dict] = {}
    login_failed = False
    for actor_name, session in sessions.items():
        login = _login_actor(session, contract, actor_name, timeout)
        if login.auth is not None:
            resolved_auth[actor_name] = login.auth
            continue

        login_failed = True
        actor_indices = [idx for idx in executable_indices if checks[idx].actor == actor_name]
        failure_idx = next(
            (idx for idx in actor_indices if checks[idx].expect == "allow"), actor_indices[0]
        )
        results_by_index[failure_idx] = Result(
            check=checks[failure_idx],
            status=login.status,
            outcome="error",
            category="setup",
            note=login.note,
            elapsed_ms=login.elapsed_ms,
        )

    if login_failed:
        for idx in executable_indices:
            if idx not in results_by_index:
                results_by_index[idx] = _setup_skipped(checks[idx])
        return [results_by_index[idx] for idx in range(len(checks))]

    preflight_indices = [idx for idx in executable_indices if checks[idx].expect == "allow"]
    for idx in preflight_indices:
        check = checks[idx]
        results_by_index[idx] = _execute_check(
            sessions[check.actor], contract, check, timeout, resolved_auth[check.actor]
        )

    preflight_failed = any(
        result.outcome == "error" and result.category == "setup"
        for result in results_by_index.values()
    )
    if preflight_failed:
        for idx in executable_indices:
            if idx not in results_by_index:
                results_by_index[idx] = _setup_skipped(checks[idx])
        return [results_by_index[idx] for idx in range(len(checks))]

    for idx in executable_indices:
        if idx not in results_by_index:
            check = checks[idx]
            results_by_index[idx] = _execute_check(
                sessions[check.actor], contract, check, timeout, resolved_auth[check.actor]
            )

    return [results_by_index[idx] for idx in range(len(checks))]


def run(
    contract: Contract,
    checks: list[Check],
    timeout: float = 10.0,
    include_unsafe: bool = False,
) -> list[Result]:
    results_by_index: dict[int, Result] = {}
    executable_indices: list[int] = []

    for idx, check in enumerate(checks):
        if not include_unsafe and not check.safe:
            results_by_index[idx] = _unsafe_skipped(check)
        else:
            executable_indices.append(idx)

    actor_names = [
        name
        for name in contract.actors
        if any(checks[idx].actor == name for idx in executable_indices)
    ]
    sessions: dict[str, requests.Session] = {}
    try:
        for actor_name in actor_names:
            sessions[actor_name] = requests.Session()
        return _run_with_sessions(
            contract,
            checks,
            timeout,
            executable_indices,
            results_by_index,
            sessions,
        )
    finally:
        for session in sessions.values():
            session.close()
