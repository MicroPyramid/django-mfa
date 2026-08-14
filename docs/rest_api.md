# JSON API

Everything the bundled screens do, as JSON, for a single-page app or a mobile
client that renders its own MFA UI.

It is **opt-in**. Installing the app does not expose it; you mount it, wherever
you like:

    urlpatterns = [
        ...,
        path("mfa/", include("django_mfa.urls")),        # the HTML views
        path("api/mfa/", include("django_mfa.api.urls")),  # this
    ]

You can mount both, or only this one. The `mfa_api` namespace is baked into the
pattern list — don't pass `namespace=` to `include()`.

## Authentication

By default the caller is `request.user`: Django's session authentication, which
a same-origin SPA already has, plus CSRF on every non-safe method. Send the
`X-CSRFToken` header exactly as you would for a form post.

For a client that authenticates another way — a DRF token, a JWT, an API key —
set `MFA_API_AUTHENTICATION` to a callable taking a request and returning a user
or `None`:

    # myapp/api.py
    def user_from_token(request):
        token = request.headers.get("Authorization", "").removeprefix("Bearer ")
        return lookup_user(token)          # or None

    # settings.py
    MFA_API_AUTHENTICATION = "myapp.api.user_from_token"

`manage.py check` refuses a path that doesn't import or doesn't resolve to a
callable (`django_mfa.E006`), so a typo fails the deploy rather than the first
request.

:::{warning}
**MFA state lives in the session, and that is not negotiable by this setting.**
`MFA_API_AUTHENTICATION` answers *who you are*; whether this session has passed
a challenge, and how recently, is read from and written to `request.session`
exactly as it is for a browser.

So a client must persist the session cookie across requests. One that discards
cookies can call every endpoint here and will still never get anywhere: each
request arrives as a brand-new session, so a verification completed in one
request is gone by the next, and step-up-gated endpoints reject it forever.

If your clients genuinely cannot hold a cookie, this API is not yet the right
shape for them — say so in an issue rather than working around it, because the
workarounds all end in a bearer token that means "MFA passed" with none of the
session's revocation.
:::

## Endpoints

All paths are relative to wherever you mounted it. Every response is a JSON
object.

| Method | Path | Does |
|---|---|---|
| `GET` | `state/` | Everything needed to render the right screen |
| `POST` | `enroll/<type>/begin/` | Start enrolling a factor |
| `POST` | `enroll/<type>/complete/` | Finish enrolling it |
| `POST` | `verify/<type>/begin/` | Issue a challenge |
| `POST` | `verify/<type>/complete/` | Answer a challenge |
| `POST` | `recovery-codes/` | Generate recovery codes, once |
| `DELETE` | `factors/<id>/` | Remove an enrolled factor |
| `GET` | `passkey/begin/` | Start passwordless sign-in |
| `POST` | `passkey/complete/` | Finish it, and log in |

**`begin` is `POST`, not `GET`.** Beginning has real side effects — the email
factor *sends mail*, WebAuthn writes ceremony state to the session — and `POST`
is also what brings CSRF protection. The HTML views use `GET` there only because
rendering a page has to.

### `GET state/`

Reachable while a session is still pending, deliberately: a client that couldn't
ask what the user can verify with until *after* verifying would have nothing to
draw the challenge screen from.

    {
      "verified": false,
      "pending": true,
      "verified_at": null,
      "authenticators": [
        {"id": 7, "type": "webauthn", "name": "Work laptop",
         "verbose_name": "Security key or passkey",
         "created_at": "2026-08-14T09:12:03.114Z", "last_used_at": null}
      ],
      "can_verify_with": [{"type": "webauthn", "verbose_name": "...",
                           "supports_multiple": true}],
      "can_enroll": [{"type": "totp", "verbose_name": "...",
                      "supports_multiple": false}],
      "has_primary_factor": true,
      "recovery_codes_remaining": 10,
      "stepup_max_age": 300
    }

`can_verify_with` and `can_enroll` answer different questions and you need both:
the first includes recovery codes (a valid way to prove identity), the second is
what may still be added. `has_primary_factor` is the "is this account actually
protected" answer, which recovery codes alone do not satisfy.

`Authenticator.data` — the TOTP secret, the recovery-code hashes, the WebAuthn
credential — is never in any response, from any endpoint.

### Enrolling

    POST enroll/totp/begin/
    → {"secret_key": "...", "provisioning_uri": "otpauth://..."}

    POST enroll/totp/complete/   {"secret_key": "...", "code": "492013"}
    → 201 {"authenticator": {...}, "recovery_codes_pending": true}

The `begin` body is whatever the adapter produced, passed through unchanged. For
WebAuthn that means **`options` is a JSON-encoded string**, not a nested object —
the identical blob the bundled JavaScript parses. Call `JSON.parse` on it. It is
passed through rather than re-encoded so there is only one shape of it in the
project for anyone to keep in sync.

`recovery_codes_pending` replaces the redirect the HTML flow performs: the user
has no recovery codes yet and should be sent to generate some.

### Verifying

    POST verify/totp/begin/      → {}          (TOTP has nothing to send)
    POST verify/email/begin/     → {"address": "a•••@example.com", "code_length": 6}

    POST verify/totp/complete/   {"code": "492013"}
    → {"verified": true, "verified_at": 1755149523}

### Removing a factor

    DELETE factors/7/            → {"removed": true}

## Errors

Failures are always:

    {"error": {"code": "verification_required", "detail": "..."}}

Branch on `code`. `detail` is translated prose meant for a human, and may be
reworded in any release.

| Code | Status | Means |
|---|---|---|
| `unauthenticated` | 401 | No user, or `MFA_API_AUTHENTICATION` returned `None` |
| `verification_required` | 403 | The session is pending — challenge first |
| `enrollment_required` | 403 | No primary factor enrolled |
| `stepup_required` | 403 | Needs a challenge within `MFA_STEPUP_MAX_AGE` |
| `managed_by_enterprise` | 403 | `MFA_OWNED_BY_ENTERPRISE` protects this key |
| `invalid` | 400 | The submission was rejected |
| `malformed_body` | 400 | The body wasn't a JSON object |
| `method_not_allowed` | 405 | Wrong HTTP method |

:::{warning}
**`invalid` is deliberately uninformative, and stays that way.** A wrong code, a
malformed payload, a replayed ceremony, a clone-detected authenticator and an
attempt the rate limiter refused all return the identical 400. That is the same
property the HTML views have, for the same reason: any difference between them
is an oracle, and the rate-limit case is the worst one to leak — it tells an
attacker exactly when to back off.

In particular, **do not show the user "too many attempts"** based on this API.
It cannot tell you that, on purpose.
:::

## Enforcement and the middleware

`MfaMiddleware` answers a pending session with a *redirect*, which is wrong for
an API client. When these URLs are mounted, the middleware adds them to its
exempt sets automatically — so the endpoints answer with a status code instead,
and no configuration is needed.

They go into the *same two separate sets* the HTML views do, and the split is
load-bearing: `state` and the `verify` pair are reachable while pending, the
`enroll` endpoints are not. Enrolling marks a session verified, so a pending user
allowed to enroll could satisfy their own challenge with a factor of their
choosing instead of the one they hold. Each endpoint enforces this itself as
well, rather than trusting the middleware to have done it.

## Passwordless sign-in

    GET  passkey/begin/     → {"options": "<json string>"}
    POST passkey/complete/  {"credential": "<json string>"}
    → {"authenticated": true, "verified": true, "verified_at": 1755149523}

Both are anonymous — that is the point. `verified` distinguishes the two kinds of
success: a passkey used with a PIN or biometric (User Verification) satisfies
both factors at once, while a presence-only assertion logs the user in with a
session **still pending a second factor**. A client that treats them alike will
strand people on a screen they can't leave.

Every failure returns one identical 400 — unknown handle, unknown credential, bad
signature, expired ceremony, tampered payload. Distinguishing them would let an
attacker enumerate which opaque user handles belong to real accounts.

:::{note}
`django_mfa.urls` already exposes `mfa:passkey_begin` and `mfa:passkey_complete`.
Those keep their existing shapes — including a `302` on success and a flat
`{"error": "..."}` body — because host projects already parse them. The endpoints
here are the JSON-native equivalents; the ceremony itself is the same code.
:::
