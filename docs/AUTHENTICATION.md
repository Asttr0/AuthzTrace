# Authentication

AuthzTrace supports static credentials and runtime API login flows. Authentication is configured per actor, and every actor receives an isolated HTTP session.

## Static credentials

Use environment variables for real secrets:

~~~yaml
actors:
  bearer_user:
    auth: { type: bearer, token: "${BEARER_TOKEN}" }
  api_key_user:
    auth: { type: header, name: X-API-Key, value: "${API_KEY}" }
  cookie_user:
    auth: { type: cookie, name: session, value: "${SESSION_COOKIE}" }
  basic_user:
    auth:
      type: basic
      username: "${BASIC_USERNAME}"
      password: "${BASIC_PASSWORD}"
  anon:
    auth: { type: none }
~~~

Actor-auth credentials are applied only while requests execute. They are not included in terminal, JSON, JUnit, or SARIF reports.

## Runtime login

A login actor has three parts:

1. **request** describes how to authenticate.
2. **extract** locates the credential in the response.
3. **credential** describes how to apply the extracted value to API requests.

### JSON login returning a Bearer token

~~~yaml
actors:
  alice:
    auth:
      type: login
      request: POST /api/login
      json:
        email: "${ALICE_EMAIL}"
        password: "${ALICE_PASSWORD}"
      extract:
        from: json
        path: session.access_token
      credential:
        type: bearer
~~~

Relative login paths use the contract's **base_url**.

### Separate OAuth or identity-provider URL

The login target can be an explicit HTTP(S) URL when authentication is hosted separately from the API:

~~~yaml
actors:
  service_user:
    auth:
      type: login
      request:
        method: POST
        url: https://identity.example.test/oauth/token
        data:
          grant_type: client_credentials
          client_id: "${CLIENT_ID}"
          client_secret: "${CLIENT_SECRET}"
        follow_redirects: false
      expect_status: [200]
      extract:
        from: json
        path: access_token
      credential:
        type: bearer
~~~

Login requests accept **query** (or **params**), **headers**, **json**, and form **data**. Redirects are followed by default; set **follow_redirects: false** when the identity protocol requires the original redirect response.

Use HTTPS for external identity providers. An absolute target must use HTTP or HTTPS; other URL schemes are rejected.

## Credential extraction

### JSON

Use a dotted path. Numeric components address list elements:

~~~yaml
extract: { from: json, path: results.0.access_token }
~~~

### Response header

~~~yaml
extract: { from: header, name: X-Session-Token }
credential: { type: header, name: X-API-Key }
~~~

### Response cookie

~~~yaml
extract: { from: cookie, name: session }
credential: { type: cookie, name: session }
~~~

When the source and target cookie names match, AuthzTrace relies on the actor's cookie jar. This preserves the server's domain, path, expiry, and redirect semantics instead of constructing a global Cookie header.

## Applying non-standard tokens

Standard Bearer tokens use an **Authorization: Bearer** header. A different scheme can be selected explicitly:

~~~yaml
credential: { type: bearer, scheme: Token }
~~~

For arbitrary headers, use a template containing **{value}**:

~~~yaml
credential:
  type: header
  name: Authorization
  template: "ApiKey {value}"
~~~

Header templates without **{value}** and templates containing newline characters are rejected during contract loading.

## Execution and failure behavior

- Runtime login happens once per used actor before authorization preflight.
- Each actor has an independent session, connection pool, and cookie jar.
- Login requests are explicit setup operations, so a POST login runs even when endpoint testing is in read-only mode.
- The default successful login status is any 2xx response. **expect_status** can provide an exact list.
- A rejected login, unreachable identity provider, invalid response, missing credential, or ambiguous cookie is a setup error.
- Any login setup error aborts endpoint preflight and prevents deny rows from running. The CLI exits with code 2.
- Login request bodies, extracted values, and raw transport errors are excluded from reports.

## Current boundaries

One request-and-extract step is supported per actor. Interactive browser redirects, MFA, multi-step CSRF handshakes, and automatic refresh-token rotation are not yet modeled. For those systems, provision short-lived test credentials externally and use a static actor until a dedicated flow is available.

Always run authorization probes against controlled test data in a non-production environment.
