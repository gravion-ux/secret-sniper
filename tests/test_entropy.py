"""Unit tests for Secret Sniper's entropy analysis and string heuristics.

Covers the import-level helpers the pattern layer leans on -- Shannon
entropy, the keyword-adjacent entropy sweep, encoded-payload decoders,
placeholder / identifier / hash shape checks and redaction -- so a broken
heuristic fails here with its own name instead of hiding inside the
monolithic CLI smoke test.

Run from the repository root:

    python -m unittest discover -s tests -v
"""

import base64
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import secret_sniper as ss


def _frag(*parts):
    """Assemble a synthetic fixture from fragments at runtime."""
    return "".join(parts)


# High-entropy synthetic value (fragment-assembled, not a real credential).
HIGH_ENTROPY = _frag("Xq7bZ2mK9pL", "4wR8tY1nC6dF3gH5", "jS0vA")
MD5_HEX = "d41d8cd98f00b204e9800998ecf8427e"
SHA1_HEX = "da39a3ee5e6b4b0d3255bfef95601890afd80709"


class TestShannonEntropy(unittest.TestCase):
    def test_empty_string(self):
        self.assertEqual(ss.shannon_entropy(""), 0.0)

    def test_single_repeated_character(self):
        self.assertEqual(ss.shannon_entropy("aaaa"), 0.0)

    def test_two_equiprobable_symbols(self):
        self.assertEqual(ss.shannon_entropy("ab"), 1.0)

    def test_four_equiprobable_symbols(self):
        self.assertEqual(ss.shannon_entropy("abcd"), 2.0)
        self.assertEqual(ss.shannon_entropy("aabbccdd"), 2.0)

    def test_high_entropy_fixture(self):
        self.assertAlmostEqual(ss.shannon_entropy(HIGH_ENTROPY), 5.0, places=4)


class TestEntropyScan(unittest.TestCase):
    """The sweep only fires for high-entropy values next to a keyword."""

    def test_keyword_adjacent_secret_found(self):
        results = ss.entropy_scan(f'password = "{HIGH_ENTROPY}"')
        self.assertEqual(len(results), 1)
        candidate, entropy = results[0]
        self.assertEqual(candidate, HIGH_ENTROPY)
        self.assertGreaterEqual(entropy, 4.2)

    def test_plain_prose_ignored(self):
        self.assertEqual(
            ss.entropy_scan("the quick brown fox jumps over the lazy dog"), [])

    def test_short_placeholder_ignored(self):
        self.assertEqual(ss.entropy_scan('password = "changeme"'), [])

    def test_hash_next_to_keyword_ignored(self):
        # A bare digest is a hash, not a leaked secret.
        self.assertEqual(ss.entropy_scan(f'token = "{MD5_HEX}"'), [])

    def test_threshold_is_respected(self):
        self.assertEqual(
            ss.entropy_scan(f'password = "{HIGH_ENTROPY}"', min_entropy=7.0),
            [])

    def test_scanner_reports_entropy_finding(self):
        scanner = ss.SecretScanner(redact_mode=True, entropy=True)
        findings = scanner.scan_text(
            f'password = "{HIGH_ENTROPY}"\n', source="<test>")
        hits = [f for f in findings if f["pattern"] == "High Entropy String"]
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0]["category"], "entropy")
        self.assertEqual(hits[0]["severity"], "MEDIUM")
        self.assertTrue(hits[0]["validation"].startswith("entropy="))

    def test_scanner_entropy_can_be_disabled(self):
        scanner = ss.SecretScanner(redact_mode=True, entropy=False)
        findings = scanner.scan_text(
            f'password = "{HIGH_ENTROPY}"\n', source="<test>")
        hits = [f for f in findings if f["pattern"] == "High Entropy String"]
        self.assertEqual(hits, [])


class TestShapeHelpers(unittest.TestCase):
    def test_looks_like_hash(self):
        self.assertTrue(ss.looks_like_hash(MD5_HEX))
        self.assertTrue(ss.looks_like_hash(SHA1_HEX))
        self.assertTrue(ss.looks_like_hash("a" * 64))
        # Hex, but not a digest length.
        self.assertFalse(ss.looks_like_hash("a" * 20))
        # Digest length, but not hex.
        self.assertFalse(ss.looks_like_hash("z" * 32))

    def test_looks_like_url(self):
        self.assertTrue(ss.looks_like_url("https://example.com/x"))
        self.assertTrue(ss.looks_like_url("ftp://host/path"))
        self.assertFalse(ss.looks_like_url("example.com/x"))

    def test_looks_like_path(self):
        self.assertTrue(ss.looks_like_path("a/b/c"))
        self.assertFalse(ss.looks_like_path("https://x/y"))
        self.assertFalse(ss.looks_like_path("plain"))

    def test_is_placeholder(self):
        self.assertTrue(ss.is_placeholder("changeme"))
        self.assertTrue(ss.is_placeholder("your_api_key_here"))
        self.assertTrue(ss.is_placeholder("example-token-value"))
        self.assertFalse(ss.is_placeholder(HIGH_ENTROPY))


class TestRedactionAndFingerprint(unittest.TestCase):
    def test_redact_keeps_edges(self):
        value = _frag("AKIAIOSF", "ODNN7EXAMPLE")
        self.assertEqual(ss.redact(value), "AKIA************MPLE")

    def test_redact_short_value_fully_masked(self):
        self.assertEqual(ss.redact("short"), "*****")
        self.assertEqual(ss.redact(""), "")

    def test_redact_custom_keep(self):
        self.assertEqual(ss.redact("abcdefghij", keep=2), "ab******ij")

    def test_should_redact(self):
        # A PEM header line carries no secret material and is shown in full.
        # (Fragment-assembled: a complete header literal in this file would
        # trip the repository's own secret-scan CI job.)
        pem_header = _frag("-----BEGIN RSA ", "PRIVATE KEY-----")
        self.assertFalse(ss.should_redact(pem_header))
        self.assertTrue(ss.should_redact("some-secret-value"))

    def test_hash_secret_shape_and_stability(self):
        digest = ss.hash_secret("probe")
        self.assertEqual(len(digest), 16)
        self.assertEqual(digest, ss.hash_secret("probe"))
        self.assertNotEqual(digest, ss.hash_secret("other"))


class TestEncodedDecoders(unittest.TestCase):
    PLAIN = "hello secret world, this is a probe"

    def test_b64_candidates_decoded(self):
        blob = base64.b64encode(self.PLAIN.encode("utf-8")).decode("ascii")
        self.assertEqual(ss.decode_b64_candidates(f"data: {blob} end"),
                         [self.PLAIN])

    def test_b64_short_blob_ignored(self):
        self.assertEqual(ss.decode_b64_candidates("aGVsbG8="), [])

    def test_hex_candidates_decoded(self):
        blob = self.PLAIN.encode("utf-8").hex()
        self.assertEqual(ss.decode_hex_candidates(f"blob {blob} end"),
                         [self.PLAIN])

    def test_hex_short_blob_ignored(self):
        self.assertEqual(ss.decode_hex_candidates("abcd1234"), [])


class TestIdentifierHeuristics(unittest.TestCase):
    """The false-positive filters for generic low-confidence rules."""

    def test_looks_like_identifier(self):
        self.assertTrue(
            ss.looks_like_identifier("OpenapiGetV1AccountApiKeysInput"))
        self.assertTrue(ss.looks_like_identifier("specified_by_request"))
        self.assertFalse(ss.looks_like_identifier(HIGH_ENTROPY))
        self.assertFalse(ss.looks_like_identifier(""))

    def test_looks_like_public_object_id(self):
        self.assertTrue(ss.looks_like_public_object_id("cus_1234567890abcd"))
        stripe = _frag("sk_live_51H8", "xYzabcdefghij", "klmnop")
        self.assertFalse(ss.looks_like_public_object_id(stripe))
        self.assertFalse(ss.looks_like_public_object_id("cus_short"))

    def test_looks_like_code_fragment(self):
        self.assertTrue(ss.looks_like_code_fragment('",l.username="'))
        self.assertTrue(ss.looks_like_code_fragment("has space"))
        self.assertTrue(ss.looks_like_code_fragment(""))
        self.assertFalse(ss.looks_like_code_fragment(HIGH_ENTROPY))


class TestHumanSize(unittest.TestCase):
    def test_units(self):
        self.assertEqual(ss.human_size(512), "512B")
        self.assertEqual(ss.human_size(2048), "2KB")
        self.assertEqual(ss.human_size(5 * 1024 * 1024), "5MB")


if __name__ == "__main__":
    unittest.main()
