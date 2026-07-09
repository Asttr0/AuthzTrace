"""Render results as a terminal matrix and as SARIF for GitHub code scanning."""
from __future__ import annotations

import json
import urllib.parse
import xml.etree.ElementTree as ET

from .models import Result

_TAG = {"pass": "PASS", "fail": "FAIL", "warn": "WARN", "error": "ERR "}
_COLOR = {"pass": "\033[32m", "fail": "\033[31m", "warn": "\033[33m", "error": "\033[35m"}
_RESET = "\033[0m"
_HELP_URI = (
    "https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/"
)


def counts(results: list[Result]) -> dict:
    out = {"pass": 0, "fail": 0, "warn": 0, "error": 0}
    for r in results:
        out[r.outcome] += 1
    return out


def _display_path(result: Result) -> str:
    check = result.check
    if not check.query:
        return check.path
    return check.path + "?" + urllib.parse.urlencode(check.query, doseq=True)


def to_terminal(results: list[Result], color: bool = True) -> str:
    lines = [
        f"{'RESULT':<6} {'ACTOR':<10} {'TARGET':<10} {'EXPECT':<7} {'STATUS':<7} METHOD  PATH",
        "-" * 96,
    ]
    for r in results:
        c = r.check
        tag = _TAG[r.outcome]
        plain_tag = tag
        if color:
            tag = f"{_COLOR[r.outcome]}{tag}{_RESET}"
        status = str(r.status) if r.status is not None else "-"
        lines.append(
            f"{tag}{' ' * (6 - len(plain_tag))} {c.actor:<10} {c.target_owner:<10} "
            f"{c.expect:<7} {status:<7} {c.method:<7} {_display_path(r)}"
        )
        if r.note:
            lines.append(f"         -> {r.note}")

    c = counts(results)
    lines.append("-" * 96)
    lines.append(
        f"{c['pass']} passed, {c['fail']} FAILED (BOLA), "
        f"{c['warn']} warnings, {c['error']} errors, {len(results)} checks"
    )
    return "\n".join(lines)


def to_json(results: list[Result]) -> str:
    data = {
        "summary": counts(results) | {"total": len(results)},
        "results": [
            {
                "name": r.check.name,
                "outcome": r.outcome,
                "note": r.note,
                "status": r.status,
                "elapsed_ms": r.elapsed_ms,
                "actor": r.check.actor,
                "target_owner": r.check.target_owner,
                "resource": r.check.resource,
                "object_id": r.check.object_id,
                "expect": r.check.expect,
                "request": {
                    "method": r.check.method,
                    "path": r.check.path,
                    "query": r.check.query,
                    "headers": r.check.headers,
                    "json": r.check.json,
                    "data": r.check.data,
                },
            }
            for r in results
        ],
    }
    return json.dumps(data, indent=2)


def to_junit(results: list[Result]) -> str:
    summary = counts(results)
    suite = ET.Element(
        "testsuite",
        {
            "name": "authztrace",
            "tests": str(len(results)),
            "failures": str(summary["fail"]),
            "errors": str(summary["error"]),
            "skipped": "0",
        },
    )
    for result in results:
        case = ET.SubElement(
            suite,
            "testcase",
            {
                "classname": "authztrace",
                "name": result.check.name,
                "time": str((result.elapsed_ms or 0) / 1000),
            },
        )
        if result.outcome == "fail":
            failure = ET.SubElement(case, "failure", {"message": result.note})
            failure.text = result.note
        elif result.outcome == "error":
            error = ET.SubElement(case, "error", {"message": result.note})
            error.text = result.note
        elif result.outcome == "warn":
            props = ET.SubElement(case, "properties")
            ET.SubElement(props, "property", {"name": "warning", "value": result.note})

    return ET.tostring(suite, encoding="unicode")


def to_sarif(results: list[Result]) -> str:
    rule = {
        "id": "authztrace/bola",
        "name": "BrokenObjectLevelAuthorization",
        "shortDescription": {"text": "Broken Object Level Authorization (IDOR/BOLA)"},
        "helpUri": _HELP_URI,
    }
    findings = [
        {
            "ruleId": "authztrace/bola",
            "level": "error",
            "message": {
                "text": (
                    f"{r.check.name}: {r.note} "
                    f"({r.check.method} {_display_path(r)} as {r.check.actor})"
                )
            },
            "locations": [
                {
                    "physicalLocation": {"artifactLocation": {"uri": "authztrace.yaml"}},
                    "logicalLocations": [
                        {"fullyQualifiedName": f"{r.check.method} {_display_path(r)}"}
                    ],
                }
            ],
        }
        for r in results
        if r.outcome == "fail"
    ]
    doc = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "AuthzTrace",
                        "informationUri": "https://github.com/Asttr0/authztrace",
                        "rules": [rule],
                    }
                },
                "results": findings,
            }
        ],
    }
    return json.dumps(doc, indent=2)
