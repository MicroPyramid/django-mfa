import base64
import re
import xml.etree.ElementTree as ET

from django.test import TestCase

from django_mfa.templatetags.otp_tags import qrcode

SVG_NS = "{http://www.w3.org/2000/svg}"
DATA_URI_RE = re.compile(r'src="data:image/svg\+xml;base64,([^"]+)"')


def _decode_svg(html):
    match = DATA_URI_RE.search(html)
    assert match is not None, "no base64 SVG data URI found in output"
    return base64.b64decode(match.group(1))


class QrcodeTagTests(TestCase):
    def test_renders_inline_data_uri(self):
        html = qrcode("otpauth://totp/a@example.com?secret=JBSWY3DPEHPK3PXP")
        self.assertIn('src="data:image/svg+xml;base64,', html)

    def test_data_uri_decodes_to_real_svg_xml(self):
        html = qrcode("otpauth://totp/a@example.com?secret=JBSWY3DPEHPK3PXP")
        payload = _decode_svg(html)

        # A corrupt/garbage payload raises here rather than merely lacking
        # the substring "<svg" -- proves it's parseable XML, not noise.
        root = ET.fromstring(payload)
        self.assertEqual(root.tag, f"{SVG_NS}svg")

    def test_svg_actually_encodes_the_value(self):
        # A stub encoder could return a constant SVG regardless of input.
        # Guard against that: the path data must actually be present, and a
        # QR for a much longer URI must need meaningfully more path data
        # (more modules) than one for a short string.
        short_html = qrcode("otpauth://totp/x")
        long_html = qrcode(
            "otpauth://totp/a@example.com?secret="
            "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP"
            "&issuer=SomeReallyLongIssuerNameForTestingPurposes"
        )

        short_root = ET.fromstring(_decode_svg(short_html))
        long_root = ET.fromstring(_decode_svg(long_html))

        short_path = short_root.find(f"{SVG_NS}path")
        long_path = long_root.find(f"{SVG_NS}path")
        self.assertIsNotNone(short_path)
        self.assertIsNotNone(long_path)
        self.assertTrue(short_path.get("d"))
        self.assertTrue(long_path.get("d"))
        self.assertGreater(len(long_path.get("d")), len(short_path.get("d")))

    def test_the_secret_never_leaves_this_server(self):
        """The provisioning URI CONTAINS the TOTP shared secret.

        Rendering it through any third-party QR service therefore hands that
        secret to a third party, in a URL, in plaintext -- which is what the
        original `chart.apis.google.com` implementation did, and what an
        upstream commit later re-did by swapping in `qrcode.tec-it.com`
        (merged here as dd5f7a1 and deliberately not taken).

        That second swap is why this asserts a property rather than naming a
        host: a guard that denylists one domain reads as protection and stops
        the next domain not at all. The only safe output is a self-contained
        data: URI with no network reference of any kind.
        """
        html = qrcode("otpauth://totp/x?secret=SUPERSECRET")
        self.assertIn("src=\"data:image/svg+xml;base64,", html)
        for network_marker in ("http://", "https://", "//", "src=\"/"):
            with self.subTest(marker=network_marker):
                self.assertNotIn(network_marker, html.replace(
                    "data:image/svg+xml;base64,", ""))
        self.assertNotIn("SUPERSECRET", html)

    def test_alt_text_is_escaped(self):
        html = qrcode("otpauth://totp/x", alt='"><script>alert(1)</script>')
        self.assertNotIn("<script>", html)

    def test_alt_defaults_to_scan_this_code(self):
        html = qrcode("otpauth://totp/x")
        self.assertIn('alt="Scan this code"', html)
