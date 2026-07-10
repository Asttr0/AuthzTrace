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
  <a href="#how-it-works">How it works</a> &middot;
  <a href="#quickstart">Quickstart</a> &middot;
  <a href="#the-contract">Contract</a> &middot;
  <a href="#built-for-trustworthy-ci">CI guarantees</a> &middot;
  <a href="docs/CORPUS.md">Roadmap</a>
</p>

## How it works

```mermaid
flowchart TB
    subgraph Contract["1. Authorization contract"]
        direction LR
        Actors["Declared actors<br/>and actor authentication"]
        Objects["Owned fixture IDs<br/>and response markers"]
        Endpoints["Endpoints, allow rules<br/>and assertions"]
    end

    Load{"Contract valid?"}
    Matrix["2. Generate matrix<br/>endpoint x object x declared actor"]
    Filter["Read-only filter<br/>unsafe checks become visible skips"]
    Preflight{"3. Executable allow rows pass?<br/>status and assertions"}
    Replay["4. Replay deny rows<br/>against the live API"]
    Grade{"Status and response body<br/>match the contract?"}

    LoadError["Exit 2<br/>contract cannot load"]
    Setup["Exit 2<br/>executed results are untrustworthy"]
    Finding["Exit 1<br/>BOLA, leak, or strict warning"]
    Clean["Exit 0<br/>no failing executed checks<br/>warnings and skips remain visible"]
    Reports["Terminal output<br/>optional SARIF / JSON / JUnit"]

    Actors --> Load
    Objects --> Load
    Endpoints --> Load
    Load -->|valid| Matrix
    Load -->|invalid| LoadError
    Matrix --> Filter
    Filter --> Preflight
    Filter -. skipped checks .-> Reports
    Preflight -->|no| Setup
    Preflight -->|yes| Replay
    Replay -->|response| Grade
    Replay -->|request error| Setup
    Grade -->|violation or strict warning| Finding
    Grade -->|pass or non-strict warning| Clean
    Setup --> Reports
    Finding --> Reports
    Clean --> Reports

    classDef input fill:#161b22,stroke:#58a6ff,color:#f0f6fc,stroke-width:2px;
    classDef process fill:#1f2937,stroke:#8b949e,color:#f0f6fc;
    classDef decision fill:#221b2e,stroke:#d2a8ff,color:#f0f6fc,stroke-width:2px;
    classDef failure fill:#3d1519,stroke:#f85149,color:#ff7b72,stroke-width:2px;
    classDef success fill:#102a18,stroke:#3fb950,color:#56d364,stroke-width:2px;
    classDef output fill:#0d2238,stroke:#58a6ff,color:#79c0ff;

    class Actors,Objects,Endpoints input;
    class Matrix,Filter,Replay process;
    class Load,Preflight,Grade decision;
    class LoadError,Setup,Finding failure;
    class Clean success;
    class Reports output;
```

## What AuthzTrace does

**AuthzTrace is an authorization contract test runner for REST APIs.** You describe test identities, object ownership, and expected access once. AuthzTrace expands every endpoint across each owned object and declared actor, including anonymous actors you explicitly define.

> `GET /invoices/inv_A -> 200` means nothing by itself. When the contract says `inv_A` belongs to Alice, the same `200` for Bob is a proven BOLA.

| You declare | AuthzTrace generates | CI receives |
| --- | --- | --- |
| Actors and credentials | Every endpoint x object x declared actor request | A reproducible authorization verdict |
| Owners and fixture IDs | Owner, cross-user, and declared anonymous checks | SARIF findings with stable fingerprints |
| Endpoints and access rules | Status and response-leak assertions | Exit codes that separate findings from broken setup |

## Quickstart

Install the CLI and scaffold a contract from an OpenAPI document:

```bash
pip install authztrace
authztrace init --from openapi.yaml
```

The OpenAPI command is a starting point, not authorization inference. It scaffolds single-object routes with one path parameter, or query parameters named `id` / `object_id`; review the result and add unsupported or nested routes manually.

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
  contents: read
  actions: read
  security-events: write

steps:
  - uses: actions/checkout@v4

  # Start your API here, or point base_url at a reachable test environment.
  - uses: Asttr0/AuthzTrace@v0.3.1
    env:
      ALICE_TOKEN: ${{ secrets.ALICE_TOKEN }}
      BOB_TOKEN: ${{ secrets.BOB_TOKEN }}
    with:
      config: authztrace.yaml
      sarif: authztrace.sarif

  - uses: github/codeql-action/upload-sarif@v4
    if: ${{ always() && (github.event_name != 'pull_request' || github.event.pull_request.head.repo.full_name == github.repository) }}
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
        allow: [owner]
        assertions:
          allow_contains: ["{marker}"]
          deny_not_contains: ["{marker}"]

policy:
  deny_status: [401, 403, 404]
```

That single endpoint becomes six checks: one endpoint x two owned objects x three declared actors. Alice and Bob must retrieve their own marker; the other user and `anon` must receive a deny status and never see it.

Object IDs can also live in query parameters, headers, JSON, or form bodies. Endpoint `allow` rules accept `owner`, named actors, `authenticated`, `anonymous`, `all`, or `*`.

## Built for trustworthy CI

| Behavior | Guarantee |
| --- | --- |
| Credential preflight | Every executable `allow` row must pass before deny rows run. Broken credentials or fixtures cannot produce a false green. |
| Read-only default | Only `GET`, `HEAD`, and `OPTIONS` execute automatically. Other methods are visibly skipped unless marked `safe: true` or enabled with `--include-unsafe`. |
| Leak detection | A denied response still fails if it contains a forbidden marker or JSON field. |
| CI-native reports | Terminal, SARIF, JSON, and JUnit output; SARIF includes stable fingerprints for GitHub code scanning. |
| Flexible authentication | Bearer tokens, custom headers, cookies, Basic auth, and anonymous actors. Actor-auth credentials are applied at request time and excluded from reports. |

| Exit | Meaning |
| ---: | --- |
| `0` | No failing findings among executed checks; warnings and skipped unsafe rows remain visible |
| `1` | BOLA, response leak, or strict warning |
| `2` | Untrustworthy setup: bad credentials, unreadable owner fixture, invalid contract, or unreachable API |

## Current scope

AuthzTrace `0.3.x` is alpha software focused on REST authorization regression testing with stable fixtures and static credentials. Next priorities are login-flow authentication, nested parent/child ownership, and GraphQL BOLA coverage. See the [authorization test corpus](docs/CORPUS.md) for supported and planned cases.

---

<p align="center">
  <sub>Found AuthzTrace useful? Star the repository so more API teams can find it.<br>
  MIT &copy; 2026 Mohamed Taha Slimani &middot; <a href="https://github.com/Asttr0">@Asttr0</a> &middot; <a href="https://github.com/Asttr0/AuthzTrace/issues">Issues</a></sub>
</p>
