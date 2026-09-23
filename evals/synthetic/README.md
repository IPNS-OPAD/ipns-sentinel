Place JSONL trajectory files here. Line 1 is a header:
{"case": "<name>", "threat_class": "<class|benign>", "expect_block": true|false, "policy": {<PolicyContext fields>}}
Every following line is an AgentStep record (see src/sentinel/state.py). Run: sentinel eval --backend fake -v

Note: `plan_injection_01` is expected to MISS on `--backend fake`. The keyword fixture cannot see a benign-sounding rationalization contradict policy; that case scores the Jev and Claude backends. The fixtures here are short illustrative cases; review before any public release and replace with a sourced corpus for calibration.
