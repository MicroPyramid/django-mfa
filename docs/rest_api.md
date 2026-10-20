# JSON API

Use the JSON API when your frontend draws its own MFA screens, for example a
single-page app or a mobile app. It drives the same factors, checks and rate
limits as the bundled HTML pages, and answers with JSON and status codes instead
of pages and redirects. If your users go through the bundled pages, you do not
need it.

## Mount it

Installing django-mfa does not expose the API. Add it to your URLconf next to
the HTML views:

```python
# urls.py
from django.urls import include, path

urlpatterns = [
    # ...
    path("mfa/", include("django_mfa.urls")),
    path("api/mfa/", include("django_mfa.api.urls")),
]
```

- The `mfa_api` namespace is built in. Do not pass `namespace=` to `include()`.
- Keep `django_mfa.urls` mounted too. `MfaMiddleware` builds its redirects from
  the `mfa:` URL names. Without them, every request from a session the
  middleware stops (one that still has to verify, or a required user with no
  factor) fails with `NoReverseMatch`, API requests included.
- Every path on this page assumes the `api/mfa/` prefix.

`MfaMiddleware` does not redirect requests to these URLs. Each endpoint checks
the session itself and answers with a [JSON error](#errors) instead. The
middleware still applies to every other URL, including your own API views, and
answers those with redirects.

## Authentication

Every endpoint except the two passkey ones needs a signed-in user. The API also
needs a Django session to keep MFA state in (whether and when the user passed a
challenge). Choose the setup that matches your client.

### Session cookie (the default)

With `MFA_API_AUTHENTICATION = None`, the caller is `request.user`. A user who
logged in through your normal Django login is already authenticated, and their
session cookie carries the MFA state.

CSRF applies to every `POST` and `DELETE` that carries a cookie. Send Django's
CSRF token in the `X-CSRFToken` header. The API does not set the `csrftoken`
cookie itself, so get it the way you would for any Django AJAX request: from a
page that renders `{% csrf_token %}`, or from a view decorated with
`ensure_csrf_cookie`.

### Your own token or JWT

Point `MFA_API_AUTHENTICATION` at a callable that takes the request and returns
a user or `None`. For example, with Django REST framework's token
authentication:

```python
# myapp/mfa_auth.py
from rest_framework.authentication import TokenAuthentication
from rest_framework.exceptions import AuthenticationFailed


def user_from_drf_token(request):
    try:
        result = TokenAuthentication().authenticate(request)
    except AuthenticationFailed:
        return None
    return result[0] if result else None
```

```python
# settings.py
MFA_API_AUTHENTICATION = "myapp.mfa_auth.user_from_drf_token"
```

A `None` result gets `401 unauthenticated`. `manage.py check` reports
`django_mfa.E006` when the path does not import or is not callable.

This setting only answers who the caller is. MFA state still lives in a Django
session. If your client keeps cookies, the session cookie carries it. If it
does not, use the token below; otherwise every request starts a new, empty
session and a completed verification is gone by the next request.

### Clients without cookies: the `X-MFA-Session` token

Once the user is signed in with your own credential, mint a token:

```http
POST /api/mfa/session/ HTTP/1.1
Authorization: Token 9944b09199c62bcf9418ad846dd0e4bbdfc6ee4b
```

```json
{"token": "0edy9qkwh0f0uwa9aja74ccau8vy7h0s", "expires_in": 1209600, "header": "X-MFA-Session"}
```

Send it in the `X-MFA-Session` header on every later request, next to your own
credential:

```http
GET /api/mfa/state/ HTTP/1.1
Authorization: Token 9944b09199c62bcf9418ad846dd0e4bbdfc6ee4b
X-MFA-Session: 0edy9qkwh0f0uwa9aja74ccau8vy7h0s
```

- The token is a Django session key. A new token starts unverified, so the user
  still has to pass a challenge with it. It lasts `expires_in` seconds
  (`SESSION_COOKIE_AGE`), and `clearsessions` removes expired ones.
- It is bound to the user it was issued to. A token that is expired, revoked,
  unknown, or sent with another user's credential gets
  `401 invalid_mfa_session`; the API never falls back to a cookie session. Mint
  a new token and verify again.
- `DELETE session/` revokes the token sent with that request and answers
  `{"revoked": true}`. Without a token it answers `{"revoked": false}` and logs
  nothing out.
- Store it like a session cookie: in the platform keychain, sent over HTTPS
  only, never logged.

CSRF is skipped only when the request carries no cookie at all. Any cookie, even
one unrelated to Django, turns CSRF checking back on, and a `POST` or `DELETE`
without a CSRF token then fails. Configure your HTTP client not to store
cookies. Token responses do not set a session cookie, unless your project sets
`SESSION_SAVE_EVERY_REQUEST = True`.

:::{warning}
With `SESSION_ENGINE = "django.contrib.sessions.backends.signed_cookies"` there
is no server-side session to hand out, and `POST session/` answers
`501 token_sessions_unsupported`. Use any other session engine, or cookie-based
clients only.
:::

Passkey login cannot use a token. See
[Passwordless login with a passkey](#passwordless-login-with-a-passkey).

## Worked flows

The examples use a cookie session: the client sends the session cookie (not
shown), and `POST` and `DELETE` requests carry `X-CSRFToken`. A token client
sends `Authorization` and `X-MFA-Session` instead, and no CSRF header.

### Log in and verify with TOTP

Log the user in with your own login view. If they hold a factor, the session
now waits for a second factor. Ask for the state:

```http
GET /api/mfa/state/ HTTP/1.1
```

```json
{
  "verified": false,
  "pending": true,
  "verified_at": null,
  "authenticators": [
    {"id": 2, "type": "recovery_codes", "name": "", "verbose_name": "Recovery codes",
     "created_at": "2026-10-20T06:57:09.681Z", "last_used_at": null},
    {"id": 1, "type": "totp", "name": "", "verbose_name": "Authenticator app",
     "created_at": "2026-10-20T06:57:08.167Z", "last_used_at": null}
  ],
  "can_verify_with": [
    {"type": "totp", "verbose_name": "Authenticator app", "supports_multiple": false},
    {"type": "recovery_codes", "verbose_name": "Recovery codes", "supports_multiple": false}
  ],
  "can_enroll": [
    {"type": "webauthn", "verbose_name": "Security key or passkey", "supports_multiple": true}
  ],
  "has_primary_factor": true,
  "recovery_codes_remaining": 10,
  "stepup_max_age": 300,
  "grace": null
}
```

Show the challenge screen when `verified` is `false` and either `pending` or
`has_primary_factor` is `true`, offering the methods in `can_verify_with`. Do
not test `pending` alone: a session that was never challenged (every new token,
or a session opened before the user enrolled) reports `"pending": false` but is
refused until it verifies.

Send the code:

```http
POST /api/mfa/verify/totp/complete/ HTTP/1.1
Content-Type: application/json
X-CSRFToken: <csrf token>

{"code": "492013"}
```

```json
{"verified": true, "verified_at": 1792479460}
```

`verified_at` is a Unix timestamp. A wrong, reused or rate-limited code gets
`400 invalid` (see [the warning below](#errors)).

TOTP needs no `begin` call. `verify/<type>/begin/` is required for `webauthn`
and `email`, where it creates the challenge or sends the code. For `totp` and
`recovery_codes` it only returns display data. See
[Request and response bodies by factor](#request-and-response-bodies-by-factor).

### Enroll an authenticator app

The enroll endpoints need a verified session whose last challenge is recent
(step-up). A user with no factor yet passes both checks.

```http
POST /api/mfa/enroll/totp/begin/ HTTP/1.1
X-CSRFToken: <csrf token>
```

```json
{"secret_key": "ZVOD3JKL6VFPYTO7HOGWFAQ6BCR6L7S3", "provisioning_uri": "otpauth://totp/ada?secret=ZVOD3JKL6VFPYTO7HOGWFAQ6BCR6L7S3"}
```

Render `provisioning_uri` as a QR code and show `secret_key` for manual entry.
The server has not stored the secret yet, so send it back with the first code:

```http
POST /api/mfa/enroll/totp/complete/ HTTP/1.1
Content-Type: application/json
X-CSRFToken: <csrf token>

{"secret_key": "ZVOD3JKL6VFPYTO7HOGWFAQ6BCR6L7S3", "code": "492013"}
```

The answer is `201 Created`:

```json
{
  "authenticator": {"id": 1, "type": "totp", "name": "", "verbose_name": "Authenticator app",
                    "created_at": "2026-10-20T06:57:08.167Z", "last_used_at": null},
  "recovery_codes_pending": true
}
```

The session is now verified. `recovery_codes_pending: true` means the user has
no recovery codes, so generate them next:

```http
POST /api/mfa/recovery-codes/ HTTP/1.1
X-CSRFToken: <csrf token>
```

```json
{"codes": ["nXKceIJrTA", "AuJwUWOn3t", "XwiHQR2wwN", "EuhmM4wivS", "vz2qWbSNZz", "oUdqQPs0Vn", "G6EIoDxgCn", "7aZVyRf7ML", "gU9Mhzrh3n", "jANDuL4Ubl"], "remaining": 10}
```

Show the codes now: they are never returned again. While a set exists, this
endpoint answers `200` with `{"codes": null, "remaining": 10}`. To issue a new
set, remove the `recovery_codes` entry listed in `authenticators` with
`DELETE factors/<id>/`, then call it again.

### Add a security key or passkey

The same gate as TOTP enrollment applies.

```http
POST /api/mfa/enroll/webauthn/begin/ HTTP/1.1
X-CSRFToken: <csrf token>
```

Shortened (the real `pubKeyCredParams` lists more algorithms):

```json
{"options": "{\"publicKey\": {\"rp\": {\"name\": \"django-mfa\", \"id\": \"example.com\"}, \"user\": {\"name\": \"ada\", \"id\": \"ZTYzNjA5YmQtYmJjNS00YjE4LTljMWItZmJlODlhMWJiYzVh\", \"displayName\": \"ada\"}, \"challenge\": \"uj_1sYg8SHaTEMClypRuC1Qty0ftzedg2SeS2Pe-VFA\", \"pubKeyCredParams\": [{\"type\": \"public-key\", \"alg\": -7}, {\"type\": \"public-key\", \"alg\": -257}], \"excludeCredentials\": [], \"authenticatorSelection\": {\"residentKey\": \"preferred\", \"userVerification\": \"preferred\", \"requireResidentKey\": false}, \"attestation\": \"none\", \"extensions\": {\"credProps\": true}}}"}
```

`options` is a JSON-encoded string, not an object: call `JSON.parse` on it. Its
`publicKey` member holds the creation options with binary fields (`challenge`,
`user.id`, each `excludeCredentials[].id`) as base64url strings. Decode those to
`ArrayBuffer`s and pass the result to `navigator.credentials.create()`.
`PublicKeyCredential.parseCreationOptionsFromJSON()` does that in browsers that
provide it, and `decodeOptions()` in the bundled
`django_mfa/static/django_mfa/webauthn.js` is a plain-JavaScript version.

Send the new credential back, again as a JSON-encoded string:

```http
POST /api/mfa/enroll/webauthn/complete/ HTTP/1.1
Content-Type: application/json
X-CSRFToken: <csrf token>

{
  "credential": "{\"id\": \"_xUzScXyEUqK60DhB2M_-m2qMCRFdQPXXH3vAdND6JQ\", \"rawId\": \"_xUzScXyEUqK60DhB2M_-m2qMCRFdQPXXH3vAdND6JQ\", \"type\": \"public-key\", \"response\": {\"clientDataJSON\": \"eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIn0\", \"attestationObject\": \"o2NmbXRkbm9uZWdhdHRTdG10oA\"}, \"clientExtensionResults\": {\"credProps\": {\"rk\": true}}}",
  "name": "Work laptop"
}
```

- `credential` is the `PublicKeyCredential` with its binary fields as base64url
  strings, passed through `JSON.stringify`. The output of `credential.toJSON()`
  (in browsers that have it) works, as does `encodeCredential()` in the bundled
  `webauthn.js`. A nested object instead of a string is rejected with
  `invalid`.
- `name` is optional (up to 100 characters) and lets the user tell keys apart.

The answer is `201 Created` with the same shape as TOTP enrollment.

Verifying with a key at login follows the same pattern.
`POST verify/webauthn/begin/` returns `{"options": "..."}` for
`navigator.credentials.get()` (decode it with
`PublicKeyCredential.parseRequestOptionsFromJSON()` or `decodeOptions()`), and
`POST verify/webauthn/complete/` takes `{"credential": "..."}` and answers like
the TOTP verify call. Call `begin` before every attempt: each challenge works
once.

### Passwordless login with a passkey

These two endpoints need no signed-in user, and they work with a cookie session
only. A token cannot be bound to a user before the ceremony has identified one,
so `X-MFA-Session` is ignored here.

```http
GET /api/mfa/passkey/begin/ HTTP/1.1
```

```json
{"options": "{\"publicKey\": {\"challenge\": \"cU97cF5L438gJ4tEj7gtgcAhCTzEnoh_GeUoOOhWb0Y\", \"rpId\": \"example.com\", \"allowCredentials\": [], \"userVerification\": \"preferred\"}}"}
```

The response sets a session cookie that holds the challenge; keep it. Decode
the options as for a security key, run `navigator.credentials.get()`, and send
the result. This request carries that cookie, so it needs `X-CSRFToken`:

```http
POST /api/mfa/passkey/complete/ HTTP/1.1
Content-Type: application/json
X-CSRFToken: <csrf token>

{"credential": "{\"id\": \"_xUzScXyEUqK60DhB2M_-m2qMCRFdQPXXH3vAdND6JQ\", \"rawId\": \"_xUzScXyEUqK60DhB2M_-m2qMCRFdQPXXH3vAdND6JQ\", \"type\": \"public-key\", \"response\": {\"clientDataJSON\": \"eyJ0eXBlIjoid2ViYXV0aG4uZ2V0In0\", \"authenticatorData\": \"SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MFAAAAAQ\", \"signature\": \"MEUCIQDx\", \"userHandle\": \"YmI0NDQ2NmE\"}}"}
```

```json
{"authenticated": true, "verified": true, "verified_at": 1792479460}
```

The user is now logged in to a new Django session. Check `verified`:

- `true`: the passkey also checked a PIN or biometric, which satisfies both
  factors.
- `false`: the authenticator only proved presence. The user is logged in, but
  the session must still pass a second factor; continue with
  [the verify flow](#log-in-and-verify-with-totp). Until it does, every gated
  request from this session is refused or redirected.

Every failure (unknown passkey, bad signature, expired or reused challenge,
malformed body) gets the same `400` with code `invalid`. Passkey login also
needs `django_mfa.backends.WebAuthnBackend` in `AUTHENTICATION_BACKENDS`; see
[System checks](settings.md#system-checks).

### Remove a factor (step-up)

Use the `id` from `authenticators` in the state response:

```http
DELETE /api/mfa/factors/3/ HTTP/1.1
X-CSRFToken: <csrf token>
```

If the session last verified more than `stepup_max_age` seconds ago, the answer
is `403`:

```json
{"error": {"code": "stepup_required", "detail": "This action needs a recent second-factor challenge."}}
```

Verify again with any method in `can_verify_with`. The verify endpoints accept a
session that is already verified, and refresh `verified_at`. Then repeat the
request:

```json
{"removed": true}
```

To ask for the code before the user clicks, compare `verified_at` plus
`stepup_max_age` with the current time. `stepup_max_age` is `null` when step-up
is switched off. The same check guards enrollment and recovery codes; see
[Step-up re-authentication](enforcement.md#step-up-re-authentication).

With `MFA_OWNED_BY_ENTERPRISE = True`, removing a WebAuthn key gets
`403 managed_by_enterprise`. An `id` that is not one of this user's factors gets
a `404`.

## Endpoint reference

| Method | Path | Purpose | Gate |
|---|---|---|---|
| `GET` | `state/` | Session and factor summary for drawing screens | Signed in |
| `POST` | `session/` | Mint an `X-MFA-Session` token | Signed in |
| `DELETE` | `session/` | Revoke the token sent with this request | Signed in |
| `POST` | `enroll/<type>/begin/` | Start adding a factor | Verified, recent |
| `POST` | `enroll/<type>/complete/` | Finish adding it (`201`) | Verified, recent |
| `POST` | `verify/<type>/begin/` | Start a challenge | Signed in |
| `POST` | `verify/<type>/complete/` | Answer the challenge | Signed in |
| `POST` | `recovery-codes/` | Generate recovery codes (`201`), once | Verified, recent |
| `DELETE` | `factors/<id>/` | Remove an enrolled factor | Verified, recent |
| `GET` | `passkey/begin/` | Start passwordless login | None, cookie only |
| `POST` | `passkey/complete/` | Finish it and log in | None, cookie only |

- **Signed in**: `401 unauthenticated` without a user. Reachable while the
  session still has to verify.
- **Verified, recent**: also refused with `403 verification_required` until
  the session passes a challenge, and with `403 stepup_required` when that was
  longer ago than `MFA_STEPUP_MAX_AGE`. A user who has not enrolled a factor
  passes both, so they can add their first one.
- **None, cookie only**: no user needed. Keep the session cookie between the
  two calls.

`<type>` is any enabled factor: `totp`, `webauthn`, `recovery_codes`, and
`email` if you added it to `MFA_FACTORS`. Request bodies are JSON objects; an
empty body counts as `{}`.

### Request and response bodies by factor

| `<type>` | `verify/.../begin/` returns | `verify/.../complete/` body | `enroll/.../begin/` returns | `enroll/.../complete/` body |
|---|---|---|---|---|
| `totp` | `{}` | `{"code"}` | `{"secret_key", "provisioning_uri"}` | `{"secret_key", "code"}` |
| `webauthn` | `{"options"}` | `{"credential"}` | `{"options"}` | `{"credential", "name"}` |
| `email` | `{"address", "code_length"}` | `{"code"}` | `{"address", "code_length"}` | `{"code"}` |
| `recovery_codes` | `{"remaining"}` | `{"code"}` | not enrollable (`404`) | not enrollable |

- `options` and `credential` are JSON-encoded strings, as shown in
  [Add a security key or passkey](#add-a-security-key-or-passkey).
- For `email`, `begin` sends the code and returns the masked address, such as
  `"a****n@example.com"`. `address` is `null` when the account has no usable
  address, and then no code is sent.
- Recovery codes come from `POST recovery-codes/`, not from `enroll/`.

### The state response

| Field | Meaning |
|---|---|
| `verified` | This session has passed a challenge. |
| `pending` | The session was asked for a challenge (at login, or by a `verify` call) and has not passed one. See [the note above](#log-in-and-verify-with-totp). |
| `verified_at` | Unix time of the last successful challenge, or `null`. |
| `authenticators` | Enrolled factors: `id`, `type`, `name` (WebAuthn only, otherwise `""`), `verbose_name`, `created_at`, `last_used_at`. Secrets and key material are never included. |
| `can_verify_with` | Factors the user can verify with now, including recovery codes. |
| `can_enroll` | Factors the user can still add. |
| `has_primary_factor` | The user holds a factor other than recovery codes. Recovery codes alone do not protect an account. |
| `recovery_codes_remaining` | Unused recovery codes. |
| `stepup_max_age` | `MFA_STEPUP_MAX_AGE` in seconds, or `null` when step-up is off. |
| `grace` | `null`, or `{"required_at": "2026-12-01T00:00:00Z", "days_remaining": 42}` while the user is in an `MFA_REQUIRED` grace period (see {doc}`enforcement`). For display only. |

`created_at`, `last_used_at` and `required_at` are ISO 8601 strings, while
`verified_at` is an integer.

## Errors

Errors have this shape, with the two exceptions listed below the tables:

```json
{"error": {"code": "verification_required", "detail": "This session must complete a second-factor challenge first."}}
```

Branch on `code`. `detail` is translated text for people, and its wording may
change in any release.

Each gate maps to one status and code:

| Gate | Status | `code` | What to do |
|---|---|---|---|
| `UNAUTHENTICATED` | 401 | `unauthenticated` | Log the user in, or check what your `MFA_API_AUTHENTICATION` callable reads. |
| `PENDING` | 403 | `verification_required` | Run the verify flow, then retry. |
| `UNENROLLED` | 403 | `enrollment_required` | Send the user to enroll. No endpoint returns this today: all of them stay open to a user with no factor, so that user can enroll. |
| `STALE` | 403 | `stepup_required` | Verify again, then retry. |

The other codes:

| Status | `code` | Meaning |
|---|---|---|
| 400 | `invalid` | The submission was rejected. See the warning below. |
| 400 | `malformed_body` | The body is not JSON, or not a JSON object. `passkey/complete/` answers `invalid` instead. |
| 401 | `invalid_mfa_session` | The `X-MFA-Session` token is expired, revoked, unknown, or belongs to another user. |
| 403 | `managed_by_enterprise` | `MFA_OWNED_BY_ENTERPRISE` stops this WebAuthn key from being removed. |
| 405 | `method_not_allowed` | Wrong HTTP method for this endpoint. |
| 501 | `token_sessions_unsupported` | The session engine cannot issue tokens. |

Two failures are not JSON, so check `Content-Type` before parsing:

- `404` is Django's normal not-found response. You get it for an unknown
  `<type>`, for `enroll/recovery_codes/...`, and for a factor `id` that does not
  belong to the user.
- A CSRF failure is Django's own `403` page.

:::{warning}
`invalid` tells you nothing about the cause, on purpose. A wrong code, a missing
field, an expired or reused challenge, a cloned security key and an attempt
refused by the rate limiter all get the identical `400` response. Any difference
would tell an attacker something, such as when the rate limiter has locked
them out.

Do not show "too many attempts" based on this API; it cannot tell you that.
Show a generic "That didn't work" and let the user try again or pick another
method. The limits are `MFA_VERIFY_RATE_LIMIT` (default 5 failures per user and
factor in 5 minutes) and `MFA_VERIFY_IP_RATE_LIMIT`; see {doc}`settings`.
:::
