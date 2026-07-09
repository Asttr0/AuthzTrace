# AuthzTrace

**Authorization contract testing for IDOR/BOLA. Prove, in CI, that user A can't touch user B's objects.**

![status](https://img.shields.io/badge/status-alpha-orange)
![license](https://img.shields.io/badge/license-MIT-blue)
![OWASP API](https://img.shields.io/badge/OWASP_API-%231_BOLA-red)
![Python](https://img.shields.io/badge/python-3.9%2B-3776AB?logo=python&logoColor=white)

Broken Object Level Authorization (**BOLA**, the IDOR family) is the **#1 vulnerability in the OWASP API Security Top 10** — and it's still #1 because scanners can't find it. Authorization is *business logic*: only your app knows that invoice `inv_123` belongs to Alice. So a DAST tool can crawl every endpoint and never notice that Bob can read Alice's invoice by changing one number.

AuthzTrace closes that gap. You write a short **authorization contract** — who the users are, which objects they own, what the policy is — and AuthzTrace generates the full cross-identity attack matrix and replays it against your running API. Owner gets in, everyone else gets `403`/`404`, or the build goes red.

Think **unit tests for "who can touch what."** Or *Pact, but for authorization.*

---

## The 60-second demo (red → green)

```bash
# 1. install
pip install -e .                       # from this repo (PyPI release coming)

# 2. start the deliberately-vulnerable demo API
pip install -r examples/vulnerable-api/requirements.txt
python examples/vulnerable-api/app.py &      # VULNERABLE mode

# 3. run the contract
export ALICE_TOKEN=alice-token BOB_TOKEN=bob-token
authztrace run -c examples/authztrace.yaml
```

Against the vulnerable API you get **FAIL** — AuthzTrace proves the BOLA:

```
RESULT ACTOR    EXPECT  STATUS  METHOD  PATH
--------------------------------------------------------------------------
PASS   alice    allow   200     GET     /api/invoices/inv_alice_001
FAIL   bob      deny    200     GET     /api/invoices/inv_alice_001
         -> BOLA: 'bob' accessed alice's invoice (inv_alice_001) — HTTP 200
PASS   anon     deny    401     GET     /api/invoices/inv_alice_001
...
8 passed, 4 FAILED (BOLA), 0 warnings, 0 errors, 12 checks
```

Now restart the API with the one-line ownership fix and run again:

```bash
kill %1; SECURE=1 python examples/vulnerable-api/app.py &
authztrace run -c examples/authztrace.yaml       # all green, exit code 0
```

That red→green flip is the whole product: **a regression test that fails the pull request the moment someone reintroduces an IDOR.**

---

## The contract

```yaml
base_url: http://localhost:3000

actors:
  alice: { auth: { type: bearer, token: "${ALICE_TOKEN}" } }
  bob:   { auth: { type: bearer, token: "${BOB_TOKEN}" } }
  anon:  { auth: { type: none } }

resources:
  invoice:
    ids:
      alice: inv_alice_001     # belongs to alice
      bob:   inv_bob_002       # belongs to bob
    markers:
      alice: "Alice private invoice"
      bob: "Bob private invoice"
    endpoints:
      - name: read invoice by path id
        request: GET /api/invoices/{id}
        assertions:
          deny_not_contains: ["{marker}"]
      - name: read invoice by query id
        method: GET
        path: /api/invoices
        query:
          id: "{id}"
      - name: lookup invoice by JSON body id
        method: POST
        path: /api/invoices/lookup
        json:
          invoice_id: "{id}"

policy:
  default: owner-only          # only the owner may access an object
  deny_status: [401, 403, 404]
```

From those few lines AuthzTrace expands **every (actor x object x endpoint)** combination and asserts *owner = allow, everyone else = deny*. You never hand-write the permutations — that's the part it automates.

Structured endpoints support object IDs in paths, query params, headers, JSON bodies, and form bodies. Endpoint `allow` rules can also include named actors such as `admin` when a privileged role should access every object.

---

## Run it in your CI

AuthzTrace speaks **SARIF**, so findings land in the GitHub Security tab and annotate the PR:

```bash
authztrace run -c authztrace.yaml --sarif authztrace.sarif
```

It also emits JSON and JUnit XML for generic CI systems:

```bash
authztrace run -c authztrace.yaml --json authztrace.json --junit authztrace.xml
```

A ready-to-copy workflow is in [`.github/workflows/authztrace-example.yml`](.github/workflows/authztrace-example.yml). Exit code is non-zero when a BOLA is proven, so the pipeline fails on real findings.

---

## Why not just use a scanner?

| | DAST scanners (ZAP, Nuclei…) | Commercial API security (StackHawk, Invicti) | **AuthzTrace** |
|---|:---:|:---:|:---:|
| Finds BOLA/IDOR | ✗ (can't infer ownership) | ~ (proprietary, heuristic) | ✅ (you declare ownership) |
| Open source & dev-first | varies | ✗ | ✅ |
| Language/framework agnostic | ✅ | ✅ | ✅ (tests over HTTP) |
| Runs in CI on every PR | ~ | ✅ | ✅ |
| Contract lives next to your code | ✗ | ✗ | ✅ |

Authorization is logic, so the fix isn't a smarter crawler — it's letting the developer *declare intent* and proving it. That declaration is the moat.

---

## Roadmap

The IDOR/BOLA pattern library and what's implemented vs. planned lives in [`docs/CORPUS.md`](docs/CORPUS.md). Next up: first-class GraphQL support, nested object ownership, method-override bypasses, and a contract generator from OpenAPI.

## Status

Alpha. The engine, contract format, terminal/SARIF/JSON/JUnit output, and the demo are working end to end. Contributions and real-world contracts welcome — especially IDOR patterns you've seen in the wild.

## License

MIT © 2026 Mohamed Taha Slimani ([@Asttr0](https://github.com/Asttr0))
