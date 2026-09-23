# Bring your own keys and data handling

No maintainer account, shared trial credential or bundled key is supplied.
The key-free `sentinel demo` always uses fixture scoring and a temporary audit key;
it ignores ambient provider keys and Sentinel configuration. Its signed demo logs
are temporary and discarded, not a durable evidence service.

For a real monitor, install the selected extra (`.[jev]` or `.[claude]`). You need
only that provider's key. OpenAI is currently an optional **agent driver** in the
repository's comparison harness, not a Sentinel monitor backend.

## Explicit opt-in smoke check

Create a private file **outside the checkout**, owned by you, with mode `600`.
Use an editor or secret manager, not a command containing the real key in shell
history. Its content is a literal export, for example:

```sh
export TYPESAFE_API_KEY=replace-with-your-own-key
```

For Claude use `ANTHROPIC_API_KEY` instead. Do not source this file: the smoke
loader parses literal exports, rejects symlinks/nonprivate files, and does no shell
expansion. Never paste keys into chat, issues, command arguments or examples.

```sh
sentinel smoke --live --backend jev \
  --credentials /absolute/path/outside-checkout/monitor.env \
  --output-dir .sentinel/my-new-smoke
```

The output directory must not already exist. The explicit file is required even
when credentials exist in your shell. Only the selected provider key is passed to
the monitor worker; there is no maintainer-file discovery, account/model fallback
or automatic retry. Use `--backend claude` and optionally `--model` for an explicit
model selection. Missing SDKs, invalid configuration, refusals and incomplete
assessments fail the check rather than switching accounts or calling the tool.

The smoke worker starts with only the selected API key in its environment and an
explicit official provider endpoint. It does not inherit proxy settings, custom
authorization headers, provider profiles, alternate tokens or endpoint/model
overrides. Corporate-proxy/custom-gateway setups need a separately configured
integration; this deliberately narrow smoke command does not support them.

This makes **one benign hosted assessment**, using one question, then submits an
inert deterministic denial canary. It executes no tools. Timeout or outage may
produce fewer calls. A pass proves limited connectivity/gating, not detection
accuracy, fleet correlation, absence of false positives or production readiness.
Hosted requests may incur charges on **your** account; provider billing applies.

## Where information goes

Real monitor backends send assessment state to the selected provider. Depending on
the integration, this includes policy, proposed arguments, exposed reasoning,
recent actions/results and peer context. Do not supply secrets or sensitive data
without approving that provider's handling and your own deployment controls.
Digest-only audit inputs do **not** mean model-bound inputs are redacted.

The opt-in smoke uses synthetic data, no remote alert sinks, and local private
evidence only. Existing SDK integrations can use operator-configured endpoints,
proxies, environment settings and alert sinks; those are trusted configuration, not
an isolated secret store. A gateway URL does not itself establish on-prem inference.

There is no maintainer collection/upload step in the demo, smoke or release checks.
Do not share the runtime output directory: it includes an audit signing key and
may include sensitive evidence in other harnesses. Keep provider files, `.sentinel/`,
audit logs and signing keys out of version control. A same-user process can still
read files it has OS permission to access; mode `600` is not agent isolation.
