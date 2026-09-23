# Preview release checks

A passing check is evidence for a bounded claim, not a guarantee of safety.

- Run the full local fixture suite, type checks and corpus validation in a clean
  checkout. Record optional Docker/scanner tests that were skipped.
- Build wheel/source archives and run both offline demos from a fresh Python 3.12+
  environment outside the checkout. Verify LICENSE and NOTICE are included.
- Run `scripts/check_release.py` with checksum-verified Gitleaks 8.30.1 and a full
  local history. Run scanner positive controls, including a canary removed from
  current files but retained in test history. Review the actual report.
- Scan built archives too. Never bundle provider credentials, signing keys,
  runtime evidence, caches or personal/private documents. The scanner reports
  locations/rules without secret values; pattern coverage is not exhaustive.
- If a maintainer key needs an exact comparison, perform it locally in memory.
  Never supply real keys to CI or record their values/hashes in reports.
- Review public source, documentation, dependencies and licensing. No result here
  certifies unrelated IP, trademarks, model accuracy or deployment isolation.
- Keep CI read-only, without provider credentials, hosted model calls, raw-log
  uploads or automatic publishing. Treat workflow changes as executable code.
- Confirm the private security reporting channel works. Do not request public
  vulnerability details or real credentials in issues.
- An opt-in BYOK smoke may verify connectivity with synthetic inputs; it executes
  no tools and does not measure held-out accuracy. Each tester pays their provider.
- Publish only the reviewed commit and verify the public CI result afterward.
  Failed CI or missing coverage must be disclosed rather than described as passed.

This public preview begins with selected source and clean history. Private
development logs, credentials and internal planning are not part of this release.
