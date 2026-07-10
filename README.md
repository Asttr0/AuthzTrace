<p align="center">
  <img src="https://raw.githubusercontent.com/Asttr0/AuthzTrace/main/docs/assets/authztrace-banner.svg?v=3" alt="AuthzTrace - authorization contract testing for IDOR and BOLA" width="1000">
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
  <a href="#quickstart">Quickstart</a> &middot;
  <a href="#the-contract">Contract</a> &middot;
  <a href="#built-for-trustworthy-ci">CI guarantees</a> &middot;
  <a href="docs/CORPUS.md">Roadmap</a>
</p>

<p align="center">
  <img src="https://raw.githubusercontent.com/Asttr0/AuthzTrace/main/docs/assets/authztrace-showcase.svg?v=1" alt="AuthzTrace turns an ownership contract into cross-user API checks and a CI verdict" width="1000">
</p>

## What AuthzTrace does

**AuthzTrace is an authorization contract test runner for REST APIs.** You describe test identities, object ownership, and expected access once. AuthzTrace expands that contract into owner, cross-user, and anonymous requests against your running API.

> `GET /invoices/inv_A -> 200` means nothing by itself. When the contract says `inv_A` belongs to Alice, the same `200` for Bob is a proven BOLA.

| You declare | AuthzTrace generates | CI receives |
| --- | --- | --- |
| Actors and credentials | Every actor x object request | A reproducible authorization verdict |
| Owners and fixture IDs | Owner, cross-user, and anonymous checks | SARIF findings with stable fingerprints |
| Endpoints and access rules | Status and response-leak assertions | Exit codes that separate findings from broken setup |

## Quickstart

Install the CLI and scaffold a contract from an OpenAPI document:

```bash
pip install authztrace
authztrace init --from openapi.yaml
```

Point `base_url` at a running **non-production** API, then add stable test-object IDs and actor credentials. Secrets can stay in environment variables:

```bash
export ALICE_TOKEN="..."
export BOB_TOKEN="..."

authztrace run -c authztrace.yaml --sarif authztrace.sarif
```

No OpenAPI document? Start from the [working example](examples/authztrace.yaml).

<details>
<summary><b>Run it in GitHub Actions</b></summary>

```yaml
permissions:
  security-events: write

steps:
  - uses: actions/checkout@v4

  - uses: Asttr0/AuthzTrace@v0.3.1
    env:
      ALICE_TOKEN: ${{ secrets.ALICE_TOKEN }}
      BOB_TOKEN: ${{ secrets.BOB_TOKEN }}
    with:
      config: authztrace.yaml
      sarif: authztrace.sarif

  - uses: github/codeql-action/upload-sarif@v4
    if: always()
    with:
      sarif_file: authztrace.sarif
```

</details>

## The contract

This contract says Alice and Bob each own one invoice. Owners may read their own invoice; every other identity must be denied without receiving the owner's marker.

```yaml
base_url: https://api.test.example.com

actors:
  alice: { auth: { type: bearer, token: "${ALICE_TOKEN}" } }
  bob:   { auth: { type: bearer, token: "${BOB_TOKEN}" } }
  anon:  { auth: { type: none } }

resources:
  invoice:
    ids:     { alice: inv_A, bob: inv_B }
    markers: { alice: "Alice private", bob: "Bob private" }
    endpoints:
      - request: GET /api/invoices/{id}
        assertions:
          allow_contains: ["{marker}"]
          deny_not_contains: ["{marker}"]

policy:
  default: owner-only
  deny_status: [401, 403, 404]
```

That single endpoint becomes six checks: three actors x two objects. Alice and Bob must retrieve their own marker; the other user and `anon` must receive a deny status and never see it.

Object IDs can also live in query parameters, headers, JSON, or form bodies. Endpoints may allow named actors, `authenticated`, `anonymous`, `owner`, or everyone.

## Built for trustworthy CI

| Behavior | Guarantee |
| --- | --- |
| Credential preflight | Owners must reach their own fixtures before attack rows run. Broken tokens cannot produce a false green. |
| Read-only default | Only `GET`, `HEAD`, and `OPTIONS` execute automatically. Other methods are visibly skipped unless marked `safe: true` or enabled with `--include-unsafe`. |
| Leak detection | A denied response still fails if it contains a forbidden marker or JSON field. |
| CI-native reports | Terminal, SARIF, JSON, and JUnit output; SARIF includes stable fingerprints for GitHub code scanning. |
| Flexible authentication | Bearer tokens, custom headers, cookies, Basic auth, and anonymous actors. Tokens are applied at request time and excluded from reports. |

| Exit | Meaning |
| ---: | --- |
| `0` | Contract proven; no findings |
| `1` | BOLA, response leak, or strict warning |
| `2` | Untrustworthy setup: bad credentials, unreadable owner fixture, invalid contract, or unreachable API |

## Current scope

AuthzTrace `0.3.x` is alpha software focused on REST authorization regression testing with stable fixtures and static credentials. Next priorities are login-flow authentication, nested parent/child ownership, and GraphQL BOLA coverage. See the [authorization test corpus](docs/CORPUS.md) for supported and planned cases.

---

<p align="center">
  <sub>Found AuthzTrace useful? Star the repository so more API teams can find it.<br>
  MIT &copy; 2026 Mohamed Taha Slimani &middot; <a href="https://github.com/Asttr0">@Asttr0</a> &middot; <a href="https://github.com/Asttr0/AuthzTrace/issues">Issues</a></sub>
</p>
