# Archived synthetic fixture runs

These files are **historical fake-backend diagnostics**, not results for the current
public preview. They contain inert synthetic data, not production agent logs.
The corpus README describes both revisions and preserves their failures.

| Files | Corpus at the time | Scorer | Meaning |
|---|---|---|---|
| `corpus-lint.txt`, `fake-eval.txt`, `fake-summary.json` | revision 2: 48 cases, 24 attack / 24 benign | v0.1.5 | Historical weak fixture baseline |
| `revision-3-corpus-lint.txt`, `revision-3-fake-eval.txt`, `revision-3-fake-summary.json` | revision 3: 51 cases, 25 attack / 26 benign | v0.1.6 | Historical added multi-agent fixture slice |

The current corpus has **51 cases**. Older outputs remain unchanged so failed
attempts are not hidden. A 48-case report is not a claim about the current corpus.

Embedded scorer commit identifiers refer to pre-public development snapshots;
those commits are intentionally absent from this repository's clean history.
The identifiers are historical provenance only, not runnable public revisions.
For reproducibility, record a new public commit, configuration and provider/model
with any new run. Do not describe these archived files as a fresh preview result.

Fake scoring tests wiring only. The recorded misses and false positives do not
measure Jev/Claude quality, establish protection, or replace held-out evaluation.
