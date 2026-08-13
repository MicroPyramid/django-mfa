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
    //         data-begin-url="{% url 'mfa:passkey_begin' %}">
    //     {% csrf_token %}
    //     <input type="hidden" name="next" value="...">
    //     <input type="hidden" name="credential" value="">
    //     <button type="button" id="webauthn-passkey-start">Sign in with a passkey</button>
    //   </form>
    // Deliberately independent of the #webauthn-form block above (separate
    // element ids throughout) so a page is free to have neither, either, or
    // -- for a factor management page that also wants a "sign in as someone
    // else" link -- conceivably both.
    var passkeyForm = document.getElementById("webauthn-passkey-form");
    if (passkeyForm) {
      var passkeyButton = document.getElementById("webauthn-passkey-start");
      var passkeyUnsupported = document.getElementById("webauthn-passkey-unsupported");
      var passkeyError = document.getElementById("webauthn-passkey-error");

      if (!window.PublicKeyCredential) {
        if (passkeyUnsupported) {
          passkeyUnsupported.hidden = false;
        }
        if (passkeyButton) {
          passkeyButton.disabled = true;
        }
      } else if (passkeyButton) {
        passkeyButton.addEventListener("click", function () {
          if (passkeyError) {
            passkeyError.textContent = "";
          }
          runPasskeyLogin(passkeyForm).catch(function (err) {
            if (passkeyError) {
              passkeyError.textContent = err && err.message ? err.message : String(err);
            }
          });
        });
      }
    }
  });
})();
