# The IDOR / BOLA attack corpus

This is the roadmap and the knowledge base: the authorization-bypass patterns a
human bug-hunter checks by hand, turned into things AuthzTrace can generate and
assert automatically. Each pattern lists what it is, how AuthzTrace tests it, and
whether the MVP covers it yet.

Reference: [OWASP API Security Top 10 — API1:2023 Broken Object Level Authorization](https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/).

| # | Pattern | What it is | How AuthzTrace tests it | Status |
|---|---------|-----------|--------------------------|--------|
| 1 | **Horizontal IDOR** | User B reads/edits User A's object by using A's object id | Cross-actor matrix: every non-owner must be denied the owner's id | ✅ MVP |
| 2 | **Unauthenticated object access** | The anonymous caller reaches a private object | `anon` actor included in the matrix, must be denied | ✅ MVP |
| 3 | **Read/write asymmetry** | `GET` is protected but `DELETE`/`PUT` is not | Every method in `endpoints` is tested independently; mutating verbs are skipped by default unless marked `safe: true` or run with `--include-unsafe` | ✅ MVP |
| 4 | **Deny-status info leak** | Denied with `403` (object exists) instead of `404` (existence hidden) | `deny_status` policy; strict mode flags `403` where `404` expected | 🔶 warn only |
| 5 | **Vertical privilege escalation** | A normal user reaches an admin-only object/endpoint | `allow: [admin]` covers named actors today; first-class roles are next | 🔶 partial |
| 6 | **IDOR outside the path** | The id lives in a query param, body, or header, not `/{id}` | Structured endpoints with `query`, `json`, `data`, and `headers` templates | ✅ MVP |
| 7 | **Object-in-object (nested) IDOR** | `/orgs/{a}/users/{b}` — only the outer id is checked | Named ID fixtures generate coherent and mixed-owner permutations for every request location | ✅ MVP |
| 8 | **Response-body leak or missing object body** | A denied response leaks object data, or an allowed response returns the wrong body | `deny_not_contains`, `allow_contains`, and `no_fields` response assertions | ✅ MVP |
| 9 | **Predictable id enumeration** | Sequential/guessable ids invite mass IDOR | Detect integer/sequential ids and warn; optional fuzz sweep | 🔜 roadmap |
| 10 | **Mass assignment of owner** | Caller sets `owner_id` in the body to hijack/plant objects | Send tampered ownership fields, assert rejection | 🔜 roadmap |
| 11 | **GraphQL node IDOR** | `node(id:)` / global-id lookups bypass object checks | GraphQL adapter reusing the same contract model | 🔜 roadmap |
| 12 | **Method override bypass** | `X-HTTP-Method-Override` flips a denied verb to an allowed one | Replay denied checks with override headers | 🔜 roadmap |

## Test identity setup

Actors can use static Bearer, custom-header, cookie, or Basic credentials, or an API login request that extracts a runtime credential from JSON, a response header, or a cookie. Runtime logins support same-origin paths and separate OAuth/identity-provider URLs, happen before authorization preflight in isolated actor sessions, and preserve cookie-jar semantics. A failed login or missing credential is a setup error, so deny rows never run with an untrustworthy identity. See the [authentication guide](AUTHENTICATION.md).

## Nested ownership

For routes with more than one object ID, each owner fixture names every ID and `target_id` identifies the protected child. AuthzTrace generates the Cartesian product of ID owners, so it tests the coherent owner path plus valid-parent/foreign-child, foreign-parent/valid-child, and foreign/foreign combinations. Mixed-owner combinations always expect denial, even when the actor owns the target child, because the declared parent-child relationship is invalid.

Concrete IDs appear in JSON output for debugging. SARIF fingerprints use the endpoint template and owner relationship instead, so rotating fixtures does not create new alerts.

## Design principle

AuthzTrace never silently guesses your authorization *rules*. Source inference
can confirm structural facts and identify probable ownership comparisons, but
authorization intent remains a reviewed decision. In particular, a missing guard
is unresolved rather than evidence that cross-user access is intended. Once that
policy is confirmed, AuthzTrace does the tedious, error-prone part: the full
cross-identity permutation on every endpoint, every run, in CI.
