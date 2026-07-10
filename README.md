<p align="center">
  <img src="https://raw.githubusercontent.com/Asttr0/AuthzTrace/main/docs/assets/authztrace-larry3d.svg" alt="AuthzTrace" width="1000">
</p>

<p align="center">
  <strong>Authorization tests for the #1 API vulnerability.</strong><br>
  Prove in CI that user A can't touch user B's data.
</p>

<p align="center">
  <a href="https://pypi.org/project/authztrace/"><img src="https://img.shields.io/pypi/v/authztrace?color=1f6feb&label=pypi" alt="PyPI"></a>
  <a href="https://pypi.org/project/authztrace/"><img src="https://img.shields.io/pypi/pyversions/authztrace?color=1f6feb" alt="Python"></a>
  <a href="https://github.com/Asttr0/AuthzTrace/actions/workflows/ci.yml"><img src="https://github.com/Asttr0/AuthzTrace/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <img src="https://img.shields.io/badge/OWASP%20API-%231%20BOLA-d1242f" alt="OWASP API #1">
  <a href="https://github.com/marketplace/actions/authztrace"><img src="https://img.shields.io/badge/Marketplace-Action-2088FF?logo=githubactions&logoColor=white" alt="Marketplace"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-1f6feb" alt="MIT"></a>
  <a href="https://github.com/Asttr0/AuthzTrace/stargazers"><img src="https://img.shields.io/github/stars/Asttr0/AuthzTrace?style=social" alt="Stars"></a>
</p>

<p align="center">
  <img src="https://raw.githubusercontent.com/Asttr0/AuthzTrace/main/docs/assets/authztrace-demo.gif" alt="AuthzTrace detects a BOLA, then passes after the API is fixed" width="900">
</p>

---

Scanners see `GET /api/invoices/inv_123` but never learn that `inv_123` is Alice's and must stay off-limits to Bob. Ownership lives in your business logic, which is exactly why BOLA has stayed #1 on the OWASP API Top 10. AuthzTrace makes you declare it, then generates every cross-user request and fails the build when authorization breaks.

```
contract  ->  every actor x object check  ->  replayed on your live API  ->  owner allowed, everyone else denied, or CI fails
```

## The demo

Point it at an API where anyone can read anyone's invoice - green is correctly enforced, red is a proven BOLA:

```diff
  ACTOR  TARGET  EXPECT  STATUS  METHOD  PATH
+ alice  alice   allow   200     GET     /api/invoices/inv_alice_001
- bob    alice   deny    200     GET     /api/invoices/inv_alice_001     <-- BOLA, leaks "Alice private"
- alice  bob     deny    200     POST    /api/invoices/lookup            <-- BOLA, leaks "Bob private"
+ anon   alice   deny    401     GET     /api/invoices/inv_alice_001
+ bob    bob     allow   200     GET     /api/invoices/inv_bob_002
```

```
12 passed, 6 failed, 6 skipped, 24 checks   ->  exit 1, pull request blocked
```

Add the one-line ownership check to your API and run again: `18 passed, 0 failed` -> exit 0. That red-to-green flip is the whole point - a regression test that fails the PR the moment an IDOR comes back.

## Quickstart

```bash
pip install authztrace
authztrace init --from openapi.yaml          # scaffold a contract from your spec
authztrace run  -c authztrace.yaml --sarif authztrace.sarif
```

In CI:

```yaml
- uses: Asttr0/AuthzTrace@v0.3.1
  with:
    config: authztrace.yaml
    sarif: authztrace.sarif
    strict: "true"
```

Exit `0` clean · `1` finding · `2` broken setup (bad token, unreachable API). A preflight checks that each owner can reach their *own* object first, so an expired token can't fake an all-clear. Safe by default: only `GET / HEAD / OPTIONS` run - `POST / PUT / PATCH / DELETE` are skipped unless you set `safe: true` or pass `--include-unsafe`.

## What it catches

```
▸  Horizontal IDOR / BOLA        A reads or edits B's object
▸  Anonymous access              unauthenticated reads of owned objects
▸  IDs anywhere                  path · query · header · JSON / form body
▸  Silent data leaks             a 403 that still ships the object
▸  Admin / shared rules          allow: [admin] · allow: [authenticated]
▸  Expired-credential false-greens   preflight aborts instead of passing
```

Planned: nested parent-child ownership · login-flow auth · GraphQL BOLA - roadmap in [docs/CORPUS.md](docs/CORPUS.md).

<details>
<summary><b>The contract - one file, every check</b></summary>

```yaml
base_url: https://api.example.com
actors:
  alice: { auth: { type: bearer, token: "${ALICE_TOKEN}" } }
  bob:   { auth: { type: bearer, token: "${BOB_TOKEN}" } }
  anon:  { auth: { type: none } }
resources:
  invoice:
    ids:     { alice: inv_alice_001, bob: inv_bob_002 }
    markers: { alice: "Alice private", bob: "Bob private" }
    endpoints:
      - request: GET /api/invoices/{id}
        assertions:
          allow_contains:    ["{marker}"]   # owner must see it
          deny_not_contains: ["{marker}"]   # nobody else may
```

Owners must pass, everyone else must be denied, and a denied response must never contain the owner's marker. IDs can live in the path, query, headers, or JSON / form body, and numeric IDs keep their type. Working example: [examples/authztrace.yaml](examples/authztrace.yaml).

</details>

## Why not a scanner

A crawler can't infer ownership, so it can't tell a `200` that's correct from a `200` that's a breach. AuthzTrace tests over HTTP against a contract that lives next to your code, runs on every pull request, and won't mutate your API by accident. Authorization is business logic - the moat is letting you declare it and proving it every commit.

Reports emit SARIF (GitHub code scanning, with stable fingerprints), JSON, and JUnit: `--sarif` `--json` `--junit`.

---

<p align="center">
  <sub>If AuthzTrace could catch a bug in your API, star the repo so other teams find it.<br>
  MIT © 2026 Mohamed Taha Slimani · <a href="https://github.com/Asttr0">@Asttr0</a></sub>
</p>
