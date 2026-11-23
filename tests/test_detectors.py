"""Unit tests for Secret Sniper's detector layer.

These tests import :mod:`secret_sniper` directly and exercise the pattern
catalogue, the structural validators and ``SecretScanner.scan_text`` at
function level, so a regression names the exact detector that broke instead
of surfacing as one undifferentiated smoke-test failure. The CLI-level
functional coverage stays in ``smoke_test.py``.

Run from the repository root:

    python -m unittest discover -s tests -v

Fixtures are assembled from fragments at runtime (see ``_frag``) so that no
complete credential literal is ever committed to the repository -- the same
discipline ``smoke_test.py`` follows for GitHub push protection.
"""

import base64
import json
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import secret_sniper as ss


def _frag(*parts):
    """Assemble a synthetic fixture from fragments at runtime."""
    return "".join(parts)


# Synthetic fixture values (fragment-assembled; never real credentials).
GH_TOKEN = _frag("ghp_a1B2c3D4e5F6", "g7H8i9J0k1L2", "m3N4o5P6q7R8")
AWS_KEY_ID = _frag("AKIAIOSF", "ODNN7EXAMPLE")
STRIPE_KEY = _frag("sk_live_51H8", "xYzabcdefghij", "klmnop")
SLACK_TOKEN = _frag("xoxb-123456", "789012-123456789", "0123-abcdefghij",
                    "klmnopqrstuvwx")


def _b64u(obj):
    raw = json.dumps(obj).encode("utf-8")
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


JWT = (
    _b64u({"alg": "HS256", "typ": "JWT"})
    + "."
    + _b64u({"sub": "1234567890", "name": "Test User"})
    + "."
    + _frag("SflKxwRJSMeKKF2QT4fwpMeJf36POk", "6yJV_adQssw5c")
)

# The header/footer lines are fragment-assembled too: a complete PEM header
# literal in this file would trip the repository's own secret-scan CI job.
PEM_HEADER = _frag("-----BEGIN RSA ", "PRIVATE KEY-----")
PEM_FOOTER = _frag("-----END RSA ", "PRIVATE KEY-----")
PEM_BLOCK = (
    PEM_HEADER + "\n"
    + _frag("MIIEowIBAAKCAQEAvb7", "EXAMPLEKEYM", "ATERIAL",
            "doNotUseInPro", "duction", "000000")
    + "\n" + PEM_FOOTER + "\n"
)


def _scanner(**kwargs):
    kwargs.setdefault("entropy", False)
    return ss.SecretScanner(**kwargs)


def _by_pattern(findings, name):
    return [f for f in findings if f["pattern"] == name]


class TestPatternCatalogue(unittest.TestCase):
    """The compiled catalogue must stay complete and well-formed."""

    def test_catalogue_size_matches_readme_claim(self):
        # README advertises "120+ rules"; guard against silent shrinkage.
        self.assertGreaterEqual(len(ss.COMPILED), 120)

    def test_every_spec_compiled(self):
        self.assertEqual(len(ss.COMPILED), len(ss.PATTERNS))

    def test_pattern_names_unique(self):
        names = [p["name"] for p in ss.COMPILED]
        self.assertEqual(len(names), len(set(names)))

    def test_entries_carry_required_fields(self):
        for spec in ss.COMPILED:
            with self.subTest(pattern=spec["name"]):
                self.assertIn(spec["severity"], ss.SEV_ORDER)
                self.assertIn(spec["confidence"], ("HIGH", "MEDIUM", "LOW"))
                self.assertTrue(spec["category"])
                self.assertTrue(hasattr(spec["compiled"], "finditer"))

    def test_validators_wired(self):
        self.assertEqual(len(ss.VALIDATORS), 13)
        for spec in ss.COMPILED:
            validator = spec.get("validator")
            self.assertTrue(validator is None or callable(validator),
                            spec["name"])
        wired = [p for p in ss.COMPILED if p.get("validator") is not None]
        self.assertGreaterEqual(len(wired), 13)


class TestValidators(unittest.TestCase):
    """Each structural validator accepts its real shape and rejects others."""

    def test_aws_key_id(self):
        self.assertEqual(ss._validate_aws_key(AWS_KEY_ID),
                         (True, "valid AWS key-id shape"))
        self.assertFalse(ss._validate_aws_key("AKIA123")[0])
        self.assertFalse(ss._validate_aws_key("akiaiosfodnn7example")[0])
        # Right prefix and length, but a single repeated character.
        self.assertEqual(ss._validate_aws_key("AKIAAAAAAAAAAAAAAAAA"),
                         (False, "insufficient character variety"))
        # 20 uppercase alphanumerics with an unassigned prefix.
        self.assertFalse(ss._validate_aws_key("ZZIAIOSFODNN7EXAMPLE")[0])

    def test_github_pat(self):
        self.assertTrue(ss._validate_github_pat(GH_TOKEN)[0])
        self.assertTrue(ss._validate_github_pat("github_pat_" + "a" * 82)[0])
        self.assertFalse(ss._validate_github_pat("ghp_short")[0])
        self.assertFalse(ss._validate_github_pat("ghp_" + "a" * 35)[0])

    def test_stripe(self):
        self.assertEqual(ss._validate_stripe(STRIPE_KEY),
                         (True, "Stripe live key"))
        test_key = _frag("sk_test_51H8", "xYzabcdefghij", "klmnop")
        self.assertEqual(ss._validate_stripe(test_key),
                         (True, "Stripe test key"))
        self.assertFalse(ss._validate_stripe("sk_live_short")[0])
        self.assertFalse(ss._validate_stripe("pk_live_51H8xYzabcdefghij")[0])

    def test_slack(self):
        self.assertTrue(ss._validate_slack(SLACK_TOKEN)[0])
        self.assertFalse(ss._validate_slack("xoxz-123456789012")[0])
        self.assertFalse(ss._validate_slack("xoxb-short")[0])

    def test_anthropic(self):
        self.assertTrue(ss._validate_anthropic("sk-ant-api03-xyz")[0])
        self.assertEqual(ss._validate_anthropic("sk-xyz"),
                         (False, "missing sk-ant- prefix"))

    def test_openai(self):
        self.assertEqual(ss._validate_openai("sk-proj-abc"),
                         (True, "project-scoped OpenAI key"))
        self.assertEqual(ss._validate_openai("sk-" + "a" * 48),
                         (True, "legacy OpenAI key"))
        self.assertFalse(ss._validate_openai("sk-short")[0])

    def test_google(self):
        self.assertTrue(ss._validate_google("AIza" + "a" * 35)[0])
        self.assertFalse(ss._validate_google("AIza123")[0])

    def test_private_key(self):
        self.assertEqual(
            ss._validate_private_key(PEM_HEADER),
            (True, "PEM private key block"))
        self.assertFalse(ss._validate_private_key("BEGIN RSA PRIVATE KEY")[0])
        self.assertFalse(
            ss._validate_private_key("-----BEGIN CERTIFICATE-----")[0])

    def test_sendgrid(self):
        key = "SG." + "a" * 22 + "." + "b" * 43
        self.assertTrue(ss._validate_sendgrid(key)[0])
        self.assertFalse(ss._validate_sendgrid("SG.short")[0])

    def test_npm(self):
        self.assertTrue(ss._validate_npm("npm_" + "a" * 36)[0])
        self.assertFalse(ss._validate_npm("npm_short")[0])

    def test_telegram(self):
        self.assertTrue(ss._validate_telegram("123456789:" + "a" * 35)[0])
        self.assertFalse(ss._validate_telegram("123:abc")[0])

    def test_supabase(self):
        self.assertTrue(ss._validate_supabase("sbp_" + "a" * 40)[0])
        # Right length, wrong alphabet (hex only).
        self.assertFalse(ss._validate_supabase("sbp_" + "g" * 40)[0])

    def test_jwt(self):
        self.assertEqual(ss._validate_jwt(JWT), (True, "valid JWT (alg=HS256)"))
        self.assertEqual(ss._validate_jwt("abc.def"),
                         (False, "not three JWT segments"))
        no_alg = _b64u({"typ": "JWT"}) + "." + _b64u({"a": 1}) + ".sig"
        self.assertEqual(ss._validate_jwt(no_alg),
                         (False, "header missing alg"))
        bad_payload = _b64u({"alg": "HS256"}) + ".not-json!!.sig"
        self.assertFalse(ss._validate_jwt(bad_payload)[0])


class TestScannerDetection(unittest.TestCase):
    """End-to-end detection through SecretScanner.scan_text."""

    def test_aws_key_id_detected_with_metadata(self):
        findings = _scanner().scan_text(
            f"AWS_ACCESS_KEY_ID={AWS_KEY_ID}\n", source="<test>")
        hits = _by_pattern(findings, "AWS Access Key ID")
        self.assertEqual(len(hits), 1)
        hit = hits[0]
        self.assertEqual(hit["severity"], "CRITICAL")
        self.assertEqual(hit["category"], "aws")
        self.assertEqual(hit["validation"], "valid AWS key-id shape")
        self.assertEqual(hit["file"], "<test>")
        self.assertEqual(hit["line"], 1)
        self.assertEqual(hit["raw_length"], len(AWS_KEY_ID))
        self.assertEqual(hit["_raw"], AWS_KEY_ID)

    def test_aws_key_id_redacted_by_default(self):
        findings = _scanner().scan_text(
            f"AWS_ACCESS_KEY_ID={AWS_KEY_ID}\n", source="<test>")
        hit = _by_pattern(findings, "AWS Access Key ID")[0]
        self.assertNotEqual(hit["match"], AWS_KEY_ID)
        self.assertTrue(hit["match"].startswith("AKIA"))
        self.assertIn("*", hit["match"])

    def test_redaction_can_be_disabled(self):
        findings = _scanner(redact_mode=False).scan_text(
            f"AWS_ACCESS_KEY_ID={AWS_KEY_ID}\n", source="<test>")
        hit = _by_pattern(findings, "AWS Access Key ID")[0]
        self.assertEqual(hit["match"], AWS_KEY_ID)

    def test_validator_rejects_impossible_aws_prefix(self):
        findings = _scanner().scan_text(
            "KEY=ZZIAIOSFODNN7EXAMPLE\n", source="<test>")
        self.assertEqual(_by_pattern(findings, "AWS Access Key ID"), [])

    def test_github_pat_detected(self):
        findings = _scanner().scan_text(
            f'GITHUB_TOKEN="{GH_TOKEN}"\n', source="<test>")
        hits = _by_pattern(findings, "GitHub PAT (classic)")
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0]["severity"], "CRITICAL")
        self.assertEqual(hits[0]["validation"], "valid GitHub token shape")

    def test_stripe_live_key_detected(self):
        findings = _scanner().scan_text(
            f'key = "{STRIPE_KEY}"\n', source="<test>")
        hits = _by_pattern(findings, "Stripe Live Secret Key")
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0]["validation"], "Stripe live key")

    def test_jwt_detected(self):
        findings = _scanner().scan_text(
            f"Authorization: Bearer {JWT}\n", source="<test>")
        hits = _by_pattern(findings, "JSON Web Token")
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0]["severity"], "HIGH")

    def test_pem_block_detected(self):
        findings = _scanner().scan_text(PEM_BLOCK, source="<test>")
        hits = _by_pattern(findings, "Private Key (PEM)")
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0]["severity"], "CRITICAL")
        self.assertEqual(hits[0]["category"], "private-key")
        self.assertEqual(hits[0]["line"], 1)

    def test_clean_text_has_no_findings(self):
        findings = _scanner().scan_text(
            "hello world\nnothing sensitive in here\n", source="<test>")
        self.assertEqual(findings, [])

    def test_line_numbers_track_position(self):
        text = f"first line\nsecond line\nAWS_ACCESS_KEY_ID={AWS_KEY_ID}\n"
        findings = _scanner().scan_text(text, source="<test>")
        hit = _by_pattern(findings, "AWS Access Key ID")[0]
        self.assertEqual(hit["line"], 3)

    def test_only_cats_restricts_categories(self):
        text = f"AWS_ACCESS_KEY_ID={AWS_KEY_ID}\nGITHUB_TOKEN=\"{GH_TOKEN}\"\n"
        findings = _scanner(only_cats={"aws"}).scan_text(text, source="<test>")
        self.assertTrue(findings)
        self.assertEqual({f["category"] for f in findings}, {"aws"})

    def test_min_severity_filters_lower_findings(self):
        findings = _scanner(min_severity="CRITICAL").scan_text(
            f"Authorization: Bearer {JWT}\n", source="<test>")
        self.assertEqual(_by_pattern(findings, "JSON Web Token"), [])
        findings = _scanner(min_severity="CRITICAL").scan_text(
            f"AWS_ACCESS_KEY_ID={AWS_KEY_ID}\n", source="<test>")
        self.assertEqual(
            len(_by_pattern(findings, "AWS Access Key ID")), 1)

    def test_allowlist_suppresses_by_hash(self):
        scanner = _scanner(allowlist={ss.hash_secret(AWS_KEY_ID)})
        findings = scanner.scan_text(
            f"AWS_ACCESS_KEY_ID={AWS_KEY_ID}\n", source="<test>")
        self.assertEqual(findings, [])

    def test_allowlist_suppresses_by_pattern_name(self):
        scanner = _scanner(allowlist={"AWS Access Key ID"})
        findings = scanner.scan_text(
            f"AWS_ACCESS_KEY_ID={AWS_KEY_ID}\n", source="<test>")
        self.assertEqual(_by_pattern(findings, "AWS Access Key ID"), [])


if __name__ == "__main__":
    unittest.main()
