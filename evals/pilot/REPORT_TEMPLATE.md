# IPNS Sentinel pilot feedback

- Tester:
- Date:
- Public checkout commit:
- Python / OS:
- Scorer: fake / self-hosted
- Requested model alias and actual model revision (operator confirmed):
- Serving software/version and JSON mode:
- Requested thinking mode (`default` / `disabled` / `enabled`) and recorded `chat_template_kwargs`:
- Whether the operator verified that the requested thinking mode was honored (or unknown):
- Gateway confirmed self-hosted-only, no cloud fallback: yes / no / unknown
- Cases/repeats, timeout, output-token budget:
- Report format version; any local runner modifications (or none):
- Installation or instructions that were confusing:

## Results (from report.json)

- Completed / total case runs:
- Detected / completed attack case runs:
- False positives / completed benign case runs:
- Incomplete case runs and assessment-status counts:
- Benign operational blocks (including service holds):
- Benign warnings:
- Premature blocks:
- Fleet mismatches:
- Notable latency or failure categories:

## Minimal reproduction

- Case name:
- Event index / agent-local step:
- Expected behavior:
- Actual decision and assessment status:
- Per-question verdicts and engine triggers for the event (format 2; unavailable in format 1):
- Fleet boost, own-signal and failure mode; relevant preceding events:
- Relevant case/question/runner hashes:
- Suggested improvement:

Attach the existing `report.json` after inspecting it; note any redactions. Do not
rerun tests or change shared infrastructure just to supply diagnostics. Null
verdicts mean no valid model assessment, not zero risk. The recorded thinking mode
is the client's request, not proof of server behavior. Preserve historical reports.

Only include synthetic/sanitized information. Remove private endpoint addresses,
credentials, prompts, model responses, internal project data and audit keys.
Report vulnerabilities privately following SECURITY.md, not in a public issue.
