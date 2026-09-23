# Security reporting

Sentinel is experimental. No version currently carries a production-security
support guarantee. The generic wrapper runs in your process; an agent with the
same OS authority can bypass it. The broker also trusts its host and control plane.

Never post credentials, exploitable customer traces or vulnerability details in a
public issue. Private vulnerability reporting is enabled for this repository.
Use [Report a vulnerability](https://github.com/IPNS-OPAD/ipns-sentinel/security/advisories/new).
If that channel is unavailable, open an issue asking for a private security contact,
with no vulnerability details attached.

If a real key has been exposed, revoke/rotate it with its provider. Removing the
latest file does not remove Git history, forks, caches or downloaded copies. Do not
send the credential to the maintainer to reproduce a report.

See [BYOK](docs/BYOK.md) for provider data flows and the
[release checklist](docs/RELEASE-CHECKLIST.md) for publication safeguards. Secret
scanning is defense in depth, not a guarantee of absence or a substitute for review.
