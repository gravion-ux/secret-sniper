# Contributing to Secret Sniper

Thanks for helping! Secret Sniper finds leaked API keys, tokens,
passwords and private keys across files, directories, archives, encoded
payloads, git history and live websites — and can optionally verify,
against the issuing provider, whether a found credential is still live.

It is a **defensive, authorised-testing tool**. The most valuable
contributions are new detection patterns, structural validators that
kill false positives, and smoke-test coverage.

## Ground rules

- **No runtime dependencies — hard rule.** The scanner runs on the
  Python standard library alone. `requests` is optional and may only
  be used behind the live-verification path (`scan --verify` /
  `verify`), exactly as `requirements.txt` declares it.
- **Never commit a real credential — not even in a test.** Fixtures
  are assembled from fragments at runtime (see `_frag()` in
  `smoke_test.py`) so no credential-shaped string ever lands in the
  repository. Follow that pattern; GitHub push protection will block
  anything else anyway.
- **Verify only credentials you are authorised to test.** Live
  verification contacts the credential's own provider. Only run it
  against your own systems or within a written authorisation.

## Development setup

Requires Python 3.9 or newer. There is nothing to install:

```bash
git clone https://github.com/gravion-ux/secret-sniper.git
cd secret-sniper
python secret_sniper.py selftest   # prove the engine works
python secret_sniper.py help       # every command on one screen
```

## Running the tests

```bash
python smoke_test.py
```

The smoke test is a functional end-to-end suite: it generates its
fixtures in a temporary directory, runs the real CLI against them
(local files and a local HTTP server — no external network), and exits
non-zero if any check fails. This is what CI runs, on Python 3.9–3.12.

## Adding a detection pattern

Patterns live in `secret_sniper.py`. A good pattern contribution has:

1. The pattern itself, scoped tightly enough that placeholders and
   examples do not match (structural validation beats a loose regex —
   see how the AWS/Stripe/JWT shapes are checked).
2. A smoke-test case whose fixture is assembled from fragments at
   runtime, proving the pattern fires on a realistic sample and stays
   silent on a clean one.
3. A note in the PR about where the credential format comes from
   (provider documentation, a real leaked-config shape, …).

## Code style

- Single-file tool by design: keep the scanner in `secret_sniper.py`
  unless there is a strong reason to split it.
- Standard library only; type hints where they clarify; comments
  explain *why* a threshold or shape check exists.

## Pull request workflow

1. Fork and branch from `main`: `feat/<short-name>`,
   `fix/<short-name>`, `pattern/<provider>` for new detections,
   `docs/<short-name>` otherwise.
2. Run `python smoke_test.py` and `python secret_sniper.py selftest`
   locally — both must pass.
3. Open the PR against `main` with: what changed, why, and how you
   tested it.
4. CI must be green. One logical change per PR.
