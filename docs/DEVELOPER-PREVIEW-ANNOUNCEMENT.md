# IPNS Sentinel developer-preview invitation

Copy and adapt the note below for your chosen developer community. This file is
invitation text, not a record that an announcement has been sent or posted.

---

We're opening the IPNS Sentinel experimental developer preview to wider feedback.
Sentinel adds policy-aware monitoring and tool-call controls to existing Python
agents, with cross-agent signal correlation and audit records.

We'd like developers to try the quickstart and tell us about setup friction,
integration gaps, false alerts, missed violations, or slow assessments.

- Start with the **offline demo: no API keys or model account required**.
- Optionally try the **12-case synthetic evaluation pack** (5 attacks, 7 benign
  controls), using your own approved self-hosted scorer. It evaluates recorded
  proposals without executing their tools. Hosted assessment integrations also
  require each tester's own credentials; no maintainer keys are provided.
- Use Python 3.12+ on Linux/macOS, or WSL on Windows.

This is an experimental open-source preview, **not a production-security guarantee**.
The wrapper is not a sandbox. False positives, coverage gaps and self-hosted
latency remain active areas for feedback. You do not need collaborator access,
a paid model, or a complete evaluation run to contribute something useful.

Start here: [repository and quickstart](https://github.com/IPNS-OPAD/ipns-sentinel#try-it-without-keys)

Try the evals: [pilot guide](https://github.com/IPNS-OPAD/ipns-sentinel/blob/main/evals/pilot/README.md)

Share sanitized feedback: [GitHub Issues](https://github.com/IPNS-OPAD/ipns-sentinel/issues)

Please use synthetic examples and never post credentials, production conversations
or private logs. Report vulnerabilities through the
[private security channel](https://github.com/IPNS-OPAD/ipns-sentinel/security/advisories/new).
