<p align="center">
  <img src="https://raw.githubusercontent.com/Asttr0/AuthzTrace/main/docs/assets/authztrace-demo.gif" alt="AuthzTrace red to green demo" width="820">
</p>

<h1 align="center">AuthzTrace</h1>

<p align="center">
  <strong>Authorization tests for IDOR/BOLA bugs.</strong><br>
  Prove in CI that user A cannot access user B's objects.
</p>

<p align="center">
  <a href="https://pypi.org/project/authztrace/"><img src="https://img.shields.io/pypi/v/authztrace?color=blue" alt="PyPI"></a>
  <a href="https://pypi.org/project/authztrace/"><img src="https://img.shields.io/pypi/pyversions/authztrace" alt="Python versions"></a>
  <a href="https://github.com/Asttr0/AuthzTrace/actions/workflows/ci.yml"><img src="https://github.com/Asttr0/AuthzTrace/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="https://github.com/marketplace/actions/authztrace"><img src="https://img.shields.io/badge/GitHub%20Marketplace-AuthzTrace-2088FF?logo=githubactions&logoColor=white" alt="GitHub Marketplace"></a>
  <a href="https://github.com/Asttr0/AuthzTrace/blob/main/LICENSE"><img src="https://img.shields.io/badge/license-MIT-blue" alt="MIT license"></a>
</p>

---

Most API scanners can crawl endpoints, but they do not know ownership. They can see `GET /api/invoices/inv_123`; they cannot know that `inv_123` belongs to Alice and must not be readable by Bob.

AuthzTrace adds that missing business context. You declare actors, object owners, and endpoints. AuthzTrace generates the cross-user attack matrix and fails the build when authorization breaks.

```text
alice owns inv_alice_001     bob owns inv_bob_002

AuthzTrace proves:
  alice -> alice invoice  allowed
  bob   -> alice invoice  denied
  anon  -> alice invoice  denied
```

## Quickstart

Install from PyPI:

```bash
pip install authztrace
```

Create or scaffold a contract:

```bash
authztrace init --from openapi.yaml --output authztrace.yaml
```

Run it against your API:

```bash
authztrace run -c authztrace.yaml --sarif authztrace.sarif
```

Use it in GitHub Actions:

```yaml
- uses: Asttr0/AuthzTrace@v0.3.1
  with:
    config: authztrace.yaml
    sarif: authztrace.sarif
    strict: "true"
```

Exit codes are built for CI:

| Code | Meaning |
|---:|---|
| `0` | clean |
| `1` | BOLA/leak finding, or warning in `--strict` mode |
| `2` | setup failure: broken token, unreachable API, invalid fixture |

## Contract Example

```yaml
base_url: http://localhost:3000

actors:
  alice: { auth: { type: bearer, token: "${ALICE_TOKEN}" } }
  bob:   { auth: { type: bearer, token: "${BOB_TOKEN}" } }
  anon:  { auth: { type: none } }

resources:
  invoice:
    ids:
      alice: inv_alice_001
      bob: inv_bob_002
    markers:
      alice: "Alice private invoice"
      bob: "Bob private invoice"
    endpoints:
      - name: read invoice
        request: GET /api/invoices/{id}
        assertions:
          allow_contains: ["{marker}"]
          deny_not_contains: ["{marker}"]

policy:
  default: owner-only
  deny_status: [401, 403, 404]
```

That small file expands into every actor x object check. Owners must pass. Everyone else must be denied. Denied responses must not leak the owner's marker.

## Endpoint Shapes

Object IDs can be tested in paths, query strings, headers, JSON bodies, and form bodies:

```yaml
endpoints:
  - request: GET /api/invoices/{id}

  - method: GET
    path: /api/invoices
    query:
      id: "{id}"

  - method: POST
    path: /api/invoices/lookup
    safe: true
    json:
      invoice_id: "{id}"
```

Exact placeholders preserve their type. If an ID is numeric, `invoice_id: "{id}"` sends a number, not a string.

Shared or privileged endpoints can override owner-only authorization:

```yaml
- request: GET /api/admin/invoices/{id}
  allow: [owner, admin]

- request: GET /api/team/invoices/{id}
  allow: [authenticated]
```

## Safe By Default

AuthzTrace is meant to run in CI, so it does not execute mutating endpoints unless you opt in.

| Method | Default |
|---|---|
| `GET`, `HEAD`, `OPTIONS` | executed |
| `POST`, `PUT`, `PATCH`, `DELETE` | skipped |

Mark read-like POST endpoints as safe:

```yaml
- method: POST
  path: /api/search
  safe: true
```

Run unsafe endpoints only against disposable test data:

```bash
authztrace run -c authztrace.yaml --include-unsafe
```

Skipped endpoints are reported as `SKIP`, not counted as passes.

## What It Catches

| Pattern | Status |
|---|---|
| Horizontal IDOR/BOLA | supported |
| Anonymous object access | supported |
| IDs in path/query/header/body | supported |
| Denied response leaks | supported |
| Wrong allowed response body | supported |
| Admin/shared access rules | supported |
| Broken credential false-green prevention | supported |
| Nested parent-child ownership | planned |
| Login-flow auth | planned |
| GraphQL BOLA | planned |

Full roadmap: [docs/CORPUS.md](docs/CORPUS.md).

## Demo Locally

```bash
git clone https://github.com/Asttr0/AuthzTrace.git
cd AuthzTrace
pip install -e .
pip install -r examples/vulnerable-api/requirements.txt

python examples/vulnerable-api/app.py
```

In another terminal:

```bash
export ALICE_TOKEN=alice-token
export BOB_TOKEN=bob-token
authztrace run -c examples/authztrace.yaml
```

Against the vulnerable API:

```text
12 passed, 6 failed, 0 warnings, 0 errors, 6 skipped, 24 checks
categories: bola=6, unsafe_skipped=6
```

Against the fixed API:

```bash
SECURE=1 python examples/vulnerable-api/app.py
```

```text
18 passed, 0 failed, 0 warnings, 0 errors, 6 skipped, 24 checks
categories: unsafe_skipped=6
```

## Output Formats

```bash
authztrace run -c authztrace.yaml \
  --sarif authztrace.sarif \
  --json authztrace.json \
  --junit authztrace.xml
```

SARIF results include stable fingerprints so GitHub Code Scanning can track findings across runs.

## Why Not A Normal Scanner?

| Capability | Generic scanner | AuthzTrace |
|---|:---:|:---:|
| Knows object ownership | no | yes |
| Tests cross-user access | weak | yes |
| Fails CI on BOLA | sometimes | yes |
| Uses contracts next to code | no | yes |
| Avoids mutating APIs by default | varies | yes |

Authorization is business logic. AuthzTrace lets you declare that logic and test it on every pull request.

## Status

Alpha, but usable. PyPI package, Marketplace Action, SARIF/JSON/JUnit output, OpenAPI starter generation, read-only safety, setup preflight, and the vulnerable demo are working end to end.

Next priorities:

- login-flow auth
- nested parent-child ownership
- GraphQL BOLA checks
- baselines for accepted deviations

## License

MIT (c) 2026 Mohamed Taha Slimani ([@Asttr0](https://github.com/Asttr0))
