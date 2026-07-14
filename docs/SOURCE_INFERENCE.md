# Source inference

`authztrace init --from-source` turns supported API source patterns into a reviewed AuthzTrace contract. It is a static contract compiler, not a claim that arbitrary business policy can be recovered from implementation code.

## FastAPI workflow

Run from the API repository root:

```bash
authztrace init --from-source . --openapi openapi.yaml
```

OpenAPI is optional. When supplied, its method/path inventory and first server URL take precedence, while matched source handlers provide authentication, resource, and ownership evidence.

For each object endpoint, the review shows the detected resource, authentication dependencies, probable ownership comparison, and source location. Choose:

| Choice | Generated `allow` rule |
| --- | --- |
| Owner only | `[owner]` |
| Authenticated | `[authenticated]` |
| Public | `[all]` |
| Custom | The entered actor/rule names |
| Skip | No endpoint is generated |

The finished files are:

- `authztrace.yaml`: an ordinary executable contract with no inference metadata.
- `authztrace.evidence.json`: deterministic provenance, decisions, diagnostics, and repository-relative source locations.

## Non-interactive generation

Ownership evidence can be accepted explicitly:

```bash
authztrace init --from-source . \
  --accept-probable \
  --non-interactive
```

This accepts only a direct supported comparison such as `invoice.owner_id == current_user.id`. Authentication by itself is not ownership evidence. If any route remains unresolved, AuthzTrace exits `2`, writes the evidence document, and does not write a runnable contract.

Reuse earlier reviewed decisions when regenerating:

```bash
authztrace init --from-source . \
  --decisions authztrace.evidence.json \
  --non-interactive \
  --force
```

Decisions are matched by HTTP method and route template. Removed decisions are discarded, while new or renamed endpoints remain unresolved and stop non-interactive generation.

## Recognized patterns

The FastAPI adapter currently recognizes:

- `FastAPI` and `APIRouter` declarations.
- Static router prefixes and imported `include_router(..., prefix=...)` composition.
- Static `get`, `post`, `put`, `patch`, `delete`, `head`, and `options` decorators.
- Path identifiers and query arguments named `id`, `object_id`, or ending in `_id`.
- `Depends(...)` and `Security(...)` authentication/authorization dependencies.
- Common `query(Model)`, `select(Model)`, and `session.get(Model, id)` resource lookups.
- Direct owner/principal comparisons using fields such as `owner_id`, `user_id`, or `created_by_id` against the authenticated principal ID.
- Nested path identifiers, compiled into named multi-ID fixtures.

Source analysis uses Python's AST and never imports the target application. Hidden directories, virtual environments, dependencies, generated build directories, symlinks, and oversized source files are skipped.

## Deliberate limitations

The current adapter does not claim to understand:

- Dynamically generated routes or non-literal route paths.
- Arbitrary authorization hidden behind service/repository calls.
- Complex tenant, group, relationship, or attribute-based policy.
- Request-body/header object-ID inference.
- Fixture values, login passwords, or test-account provisioning.
- Frameworks other than FastAPI.

These cases remain unresolved or undiscovered rather than being assigned permissive defaults. Use OpenAPI to improve route coverage and review `authztrace.evidence.json` before trusting a generated contract.

## Evidence states

| State | Meaning |
| --- | --- |
| `confirmed` | Directly observed route, dependency, or resource fact |
| `probable` | A supported ownership comparison suggests owner-only policy |
| `unresolved` | The intended access rule cannot be established safely |

The important distinction is between implementation and intent. A missing ownership check may be the vulnerability AuthzTrace is meant to expose, so absence of a guard never becomes `authenticated` or `public` automatically.
