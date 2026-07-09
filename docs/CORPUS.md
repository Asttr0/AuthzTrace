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
| 3 | **Read/write asymmetry** | `GET` is protected but `DELETE`/`PUT` is not | Every method in `endpoints` is tested independently | ✅ MVP |
| 4 | **Deny-status info leak** | Denied with `403` (object exists) instead of `404` (existence hidden) | `deny_status` policy; strict mode flags `403` where `404` expected | 🔶 warn only |
| 5 | **Vertical privilege escalation** | A normal user reaches an admin-only object/endpoint | Roles + per-endpoint required-role in the contract | 🔜 roadmap |
| 6 | **IDOR outside the path** | The id lives in a query param, body, or header, not `/{id}` | Structured endpoints with `query`, `json`, `data`, and `headers` templates | ✅ MVP |
| 7 | **Object-in-object (nested) IDOR** | `/orgs/{a}/users/{b}` — only the outer id is checked | Multi-id endpoints and per-segment ownership | 🔜 roadmap |
| 8 | **Response-body leak on denial** | The API returns an error status but still leaks object data in the body | `deny_not_contains` and `no_fields` response assertions | ✅ MVP |
| 9 | **Predictable id enumeration** | Sequential/guessable ids invite mass IDOR | Detect integer/sequential ids and warn; optional fuzz sweep | 🔜 roadmap |
| 10 | **Mass assignment of owner** | Caller sets `owner_id` in the body to hijack/plant objects | Send tampered ownership fields, assert rejection | 🔜 roadmap |
| 11 | **GraphQL node IDOR** | `node(id:)` / global-id lookups bypass object checks | GraphQL adapter reusing the same contract model | 🔜 roadmap |
| 12 | **Method override bypass** | `X-HTTP-Method-Override` flips a denied verb to an allowed one | Replay denied checks with override headers | 🔜 roadmap |

## Design principle

AuthzTrace never guesses your authorization *rules* — authorization is business
logic and a scanner can't infer it. You declare ownership and policy in a few
lines; AuthzTrace does the tedious, error-prone part: the full cross-identity
permutation, on every endpoint, every run, in CI. That declaration is also the
moat — it is exactly why generic DAST scanners miss BOLA and why this stays useful.
