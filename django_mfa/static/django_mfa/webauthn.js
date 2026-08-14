// django_mfa/static/django_mfa/webauthn.js
//
// Browser-side glue for the WebAuthn enroll/verify ceremonies. No
// framework, no build step -- this file is served and executed exactly as
// written, so it is deliberately plain ES5-compatible syntax throughout
// (var, function expressions, Promise#then/#catch): no let/const, arrow
// functions, async/await, spread/rest, destructuring, template literals,
// classes, or Array#includes/String#repeat (none of those are ES5).
//
// It reads the registration/authentication options the server embedded via
// {% webauthn_options_script %} into
// <script id="webauthn-options" type="application/json">, converts the
// base64url-encoded fields WebAuthn's JSON serialization uses (challenge,
// user.id, and every credential id inside excludeCredentials/
// allowCredentials) into the ArrayBuffers navigator.credentials.create()/
// .get() require, runs the ceremony, re-encodes whatever ArrayBuffers come
// back the same way, and POSTs the result through a hidden form field.
//
// The base64url<->ArrayBuffer convention here (URL-safe alphabet, padding
// stripped) must match the server's exactly, or every ceremony fails: see
// django_mfa/adapters/webauthn.py, which is built on fido2.utils
// .websafe_encode()/websafe_decode() (also URL-safe, unpadded base64).
(function () {
  "use strict";

  // Restore the "=" padding atob() requires. base64url strings never carry
  // padding (it's stripped -- see fido2.utils.websafe_encode -- because "="
  // is not URL-safe), so it has to be reconstructed from the string length
  // before the alphabet can be translated back and handed to atob().
  function padBase64(value) {
    var remainder = value.length % 4;
    var padLength = remainder === 0 ? 0 : 4 - remainder;
    var padded = value;
    for (var i = 0; i < padLength; i++) {
      padded += "=";
    }
    return padded;
  }

  // base64url string -> ArrayBuffer.
  function b64urlToBuf(value) {
    var base64 = padBase64(value).replace(/-/g, "+").replace(/_/g, "/");
    var raw = atob(base64);
    var bytes = new Uint8Array(raw.length);
    for (var i = 0; i < raw.length; i++) {
      bytes[i] = raw.charCodeAt(i);
    }
    return bytes.buffer;
  }

  // ArrayBuffer -> base64url string (no padding). Exact inverse of
  // b64urlToBuf(): standard base64 out of btoa(), then swap "+"/"/" for the
  // URL-safe "-"/"_" and drop the padding.
  function bufToB64url(buf) {
    var bytes = new Uint8Array(buf);
    var binary = "";
    for (var i = 0; i < bytes.length; i++) {
      binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  }

  // Decode every base64url field the server sent into the ArrayBuffers
  // navigator.credentials.create()/get() require, in place.
  //
  // excludeCredentials (create) and allowCredentials (get) are ARRAYS of
  // {id: <base64url string>, type: ..., transports: [...]} objects, not a
  // single field -- easy to decode challenge/user.id and forget these. They
  // matter: excludeCredentials is what stops a compliant authenticator from
  // creating a second resident credential for a device that already has
  // one, and allowCredentials is what tells it which credential(s) it's
  // being asked to assert with.
  function decodeOptions(options) {
    var pk = options.publicKey;
    pk.challenge = b64urlToBuf(pk.challenge);
    if (pk.user) {
      pk.user.id = b64urlToBuf(pk.user.id);
    }
    var credentialListKeys = ["excludeCredentials", "allowCredentials"];
    for (var k = 0; k < credentialListKeys.length; k++) {
      var key = credentialListKeys[k];
      if (!pk[key]) {
        continue;
      }
      var decoded = [];
      for (var j = 0; j < pk[key].length; j++) {
        var entry = pk[key][j];
        decoded.push({
          type: entry.type,
          id: b64urlToBuf(entry.id),
          transports: entry.transports
        });
      }
      pk[key] = decoded;
    }
    return options;
  }

  // Encode a PublicKeyCredential the browser returned back into the plain,
  // base64url JSON object django_mfa.adapters.webauthn expects as the
  // POSTed `credential` value (see complete_enroll()/complete_verify()).
  function encodeCredential(credential) {
    var response = credential.response;
    var out = {
      id: credential.id,
      type: credential.type,
      rawId: bufToB64url(credential.rawId),
      response: {clientDataJSON: bufToB64url(response.clientDataJSON)}
    };
    if (response.attestationObject) {
      // Registration response (navigator.credentials.create()).
      out.response.attestationObject = bufToB64url(response.attestationObject);
      // complete_enroll() reads clientExtensionResults.credProps.rk to know
      // whether the credential it just stored is discoverable/resident.
      // getClientExtensionResults() is the real PublicKeyCredential API --
      // reading the extension results as a plain property instead (they
      // are not exposed that way) would always be undefined, and
      // resident-key detection would silently never work in a real
      // browser.
      if (typeof credential.getClientExtensionResults === "function") {
        out.clientExtensionResults = credential.getClientExtensionResults();
      }
    } else {
      // Authentication response (navigator.credentials.get()).
      out.response.authenticatorData = bufToB64url(response.authenticatorData);
      out.response.signature = bufToB64url(response.signature);
      out.response.userHandle = response.userHandle
        ? bufToB64url(response.userHandle)
        : null;
    }
    return out;
  }

  // Run the create()/get() ceremony and POST the result. Returns the
  // promise chain so callers can attach their own .catch().
  function runCeremony(form, mode) {
    var optionsEl = document.getElementById("webauthn-options");
    var options = decodeOptions(JSON.parse(optionsEl.textContent));
    var ceremony =
      mode === "create"
        ? navigator.credentials.create(options)
        : navigator.credentials.get(options);
    return ceremony.then(function (credential) {
      form.querySelector("[name=credential]").value =
        JSON.stringify(encodeCredential(credential));
      form.submit();
    });
  }

  // Passwordless (passkey) login. Unlike runCeremony() above, there is no
  // page-embedded {% webauthn_options_script %} to read: the login page
  // belongs to the host project, not django_mfa, and no per-request user is
  // known yet to have rendered options for in the first place. Options are
  // instead fetched from mfa:passkey_begin, an ordinary GET the host page
  // wires up via the form's data-begin-url attribute (see this function's
  // caller below). The rest -- decodeOptions/navigator.credentials.get/
  // encodeCredential/form.submit -- is identical in shape to runCeremony(),
  // deliberately reusing the exact same helpers rather than a second set,
  // so the base64url<->ArrayBuffer conversion stays defined in exactly one
  // place.
  function runPasskeyLogin(form) {
    var beginUrl = form.getAttribute("data-begin-url");
    return fetch(beginUrl, {credentials: "same-origin"})
      .then(function (response) {
        if (!response.ok) {
          throw new Error("Unable to start passkey sign-in.");
        }
        return response.json();
      })
      .then(function (body) {
        var options = decodeOptions(JSON.parse(body.options));
        return navigator.credentials.get(options);
      })
      .then(function (credential) {
        form.querySelector("[name=credential]").value =
          JSON.stringify(encodeCredential(credential));
        form.submit();
      });
  }

  // Conditional-mediation ("passkey autofill") variant of runPasskeyLogin.
  //
  // Same fetch/decode/get/encode/submit shape, with two additions that are
  // what make it autofill rather than a modal prompt:
  //
  //   mediation: "conditional" -- do not show a modal. The promise stays
  //     pending, quietly, until the user chooses one of their passkeys from
  //     the browser's own autofill dropdown on an input marked
  //     autocomplete="username webauthn". If they never do, it never
  //     settles, which is the intended behaviour and not a leak.
  //   signal -- an AbortSignal, because the platform allows only ONE
  //     outstanding navigator.credentials.get() at a time. Without it, the
  //     "Sign in with a passkey" button silently does nothing for the rest
  //     of the page's life: its own get() is rejected on arrival because
  //     this one still holds the slot. See the button handler below, which
  //     aborts this before starting its own.
  //
  // Note both `mediation` and `signal` are siblings of `publicKey` in
  // CredentialRequestOptions, NOT fields inside it -- nesting them under
  // publicKey is silently ignored, and the ceremony then shows a modal
  // exactly as if this function did not exist.
  function runConditionalPasskeyLogin(form, controller) {
    var beginUrl = form.getAttribute("data-begin-url");
    return fetch(beginUrl, {credentials: "same-origin"})
      .then(function (response) {
        if (!response.ok) {
          throw new Error("Unable to start passkey sign-in.");
        }
        return response.json();
      })
      .then(function (body) {
        var options = decodeOptions(JSON.parse(body.options));
        options.mediation = "conditional";
        options.signal = controller.signal;
        return navigator.credentials.get(options);
      })
      .then(function (credential) {
        form.querySelector("[name=credential]").value =
          JSON.stringify(encodeCredential(credential));
        form.submit();
      });
  }

  document.addEventListener("DOMContentLoaded", function () {
    var form = document.getElementById("webauthn-form");
    if (form) {
      var mode = form.getAttribute("data-mode");
      var button = document.getElementById("webauthn-start");
      var unsupported = document.getElementById("webauthn-unsupported");
      var errorEl = document.getElementById("webauthn-error");

      // A browser without WebAuthn support at all must show a clear message
      // instead of throwing when the button is clicked (or, worse, silently
      // doing nothing). window.PublicKeyCredential is the standard feature
      // check every browser exposes once WebAuthn is implemented.
      if (!window.PublicKeyCredential) {
        if (unsupported) {
          unsupported.hidden = false;
        }
        if (button) {
          button.disabled = true;
        }
      } else if (button) {
        button.addEventListener("click", function () {
          if (errorEl) {
            errorEl.textContent = "";
          }
          runCeremony(form, mode).catch(function (err) {
            if (errorEl) {
              errorEl.textContent = err && err.message ? err.message : String(err);
            }
          });
        });
      }
    }

    // Passwordless login form, e.g. on a host project's own login page:
    //   <form id="webauthn-passkey-form" method="post" action="..."
    //         data-begin-url="{% url 'mfa:passkey_begin' %}"
    //         data-conditional="true">
    //     {% csrf_token %}
    //     <input type="hidden" name="next" value="...">
    //     <input type="hidden" name="credential" value="">
    //     <button type="button" id="webauthn-passkey-start">Sign in with a passkey</button>
    //   </form>
    //
    // data-conditional="true" additionally offers the user's passkeys from
    // the browser's own autofill dropdown, with no click on the button
    // above. It needs a cooperating input ELSEWHERE on the page (typically
    // the host's existing username field, which is not django-mfa's to
    // render):
    //   <input name="username" autocomplete="username webauthn">
    // Without that autocomplete token the ceremony starts and simply never
    // surfaces anywhere -- see docs/recipes.md.
    // Deliberately independent of the #webauthn-form block above (separate
    // element ids throughout) so a page is free to have neither, either, or
    // -- for a factor management page that also wants a "sign in as someone
    // else" link -- conceivably both.
    var passkeyForm = document.getElementById("webauthn-passkey-form");
    if (passkeyForm) {
      var passkeyButton = document.getElementById("webauthn-passkey-start");
      var passkeyUnsupported = document.getElementById("webauthn-passkey-unsupported");
      var passkeyError = document.getElementById("webauthn-passkey-error");
      // Opt-in, per form: data-conditional="true". Off by default because
      // it is not free -- see startConditional() below.
      var wantsConditional =
        passkeyForm.getAttribute("data-conditional") === "true";
      // The in-flight conditional ceremony's controller, or null. Module
      // state rather than a closure variable inside the handler, because
      // the button handler and the restart path both need to reach it.
      var conditionalAbort = null;

      // Begin (or re-begin) an autofill ceremony. Kept restartable: the
      // button aborts whatever is running here to claim the single
      // get() slot, and hands it back if its own ceremony fails, so a user
      // who opens the modal and presses Escape still has working autofill
      // afterwards instead of a dropdown that has quietly gone dead.
      function startConditional() {
        conditionalAbort = new AbortController();
        runConditionalPasskeyLogin(passkeyForm, conditionalAbort)
          .catch(function (err) {
            // AbortError is the normal, expected outcome every time the
            // button takes over -- reporting it would put "signal is
            // aborted without reason" in front of a user who did nothing
            // wrong. Anything else is a real failure, but this ceremony
            // was never explicitly requested by the user, so it is logged
            // rather than rendered into the page: the visible passkey
            // button is still there and still works.
            if (!err || err.name !== "AbortError") {
              if (window.console && window.console.debug) {
                window.console.debug("[django-mfa] passkey autofill:", err);
              }
            }
          });
      }

      if (!window.PublicKeyCredential) {
        if (passkeyUnsupported) {
          passkeyUnsupported.hidden = false;
        }
        if (passkeyButton) {
          passkeyButton.disabled = true;
        }
      } else {
        // isConditionalMediationAvailable() is itself newer than WebAuthn,
        // so its absence means "no autofill here" rather than an error --
        // a browser without it still gets the button, unchanged.
        if (wantsConditional
            && typeof PublicKeyCredential.isConditionalMediationAvailable
               === "function") {
          PublicKeyCredential.isConditionalMediationAvailable()
            .then(function (available) {
              if (available) {
                startConditional();
              }
            })
            .catch(function () {
              // Availability could not be determined; the button remains.
            });
        }

        if (passkeyButton) {
          passkeyButton.addEventListener("click", function () {
            if (passkeyError) {
              passkeyError.textContent = "";
            }
            // Claim the single outstanding-get() slot before asking for
            // one, or this click resolves to nothing at all.
            var wasConditional = conditionalAbort !== null;
            if (conditionalAbort) {
              conditionalAbort.abort();
              conditionalAbort = null;
            }
            runPasskeyLogin(passkeyForm).catch(function (err) {
              if (passkeyError) {
                passkeyError.textContent =
                  err && err.message ? err.message : String(err);
              }
              if (wasConditional) {
                startConditional();
              }
            });
          });
        }
      }
    }
  });
})();
