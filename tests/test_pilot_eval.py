"""The pilot's public runner boundary: no real provider or tool execution."""
import importlib.util
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import threading
import time

import pytest

from sentinel.backends.base import BackendError, BackendInvalidResponse, BackendRefusal
from sentinel.backends.fake import FakeBackend
from sentinel.questions import select


spec = importlib.util.spec_from_file_location("pilot_eval", Path(__file__).resolve().parents[1] / "examples/pilot_eval.py")
pilot = importlib.util.module_from_spec(spec)
spec.loader.exec_module(pilot)


def benign_answers(questions):
    return {q.name: ({"probability_yes": 0.01} if q.kind == "noul" else
                     {"label": next(label for label in q.labels if label not in q.hit_labels), "confidence": 0.9}
                     if q.kind == "choice" else {"score": 0, "confidence": 0.9}) for q in questions}


@pytest.fixture
def endpoint():
    state = {"requests": [], "status": 200,
             "payload": {"choices": [{"finish_reason": "stop", "message": {
                 "content": json.dumps(benign_answers(select(None)))}}]}}

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_POST(self):
            body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            state["requests"].append({"path": self.path, "headers": dict(self.headers), "body": body})
            data = json.dumps(state["payload"]).encode()
            self.send_response(state["status"])
            self.send_header("Content-Length", str(len(data)))
            if state["status"] == 302:
                self.send_header("Location", "/should-not-be-followed")
            self.end_headers()
            if state.get("drip"):
                for byte in data[:20]:
                    try:
                        self.wfile.write(bytes([byte]))
                        self.wfile.flush()
                    except (BrokenPipeError, ConnectionResetError):
                        break
                    time.sleep(0.1)
            else:
                self.wfile.write(data)

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    state["url"] = f"http://127.0.0.1:{server.server_port}/v1"
    yield state
    server.shutdown()
    server.server_close()
    worker.join()


def test_pilot_cases_are_balanced_with_matched_pairs_and_fleet_controls():
    cases = pilot.load_cases(pilot.SUITE)
    assert len(cases) == 12
    assert sum(h["expect_block"] for h, _, _ in cases) == 5
    assert sum(len(steps) for _, steps, _ in cases) == 44
    fleet = [(h, steps) for h, steps, _ in cases if h.get("multi_agent")]
    assert sorted(len({s.agent_id for s in steps}) for _, steps in fleet) == [3, 4, 6]
    table = {h["case"]: (h, steps) for h, steps, _ in cases}
    for suffix in ("general_draft_vs_send", "plan_injection_credential_metadata",
                   "plan_injection_upload_destination", "plan_injection_transcript_redaction"):
        attack, asteps = table["attack_" + suffix]
        control, bsteps = table["benign_" + suffix]
        assert attack["policy"] == control["policy"]
        assert asteps[0].proposed_tool_call == bsteps[0].proposed_tool_call
        assert asteps[1].proposed_tool_call != bsteps[1].proposed_tool_call
        if suffix.startswith("plan_injection"):
            assert asteps[1].reasoning == bsteps[1].reasoning


def test_reloading_corpus_produces_identical_model_visible_event_ids():
    first = pilot.load_cases(pilot.SUITE)
    second = pilot.load_cases(pilot.SUITE)
    assert [[s.model_dump() for s in steps] for _, steps, _ in first] == [
        [s.model_dump() for s in steps] for _, steps, _ in second]


def test_fake_report_is_repeatable_and_never_claims_real_execution(tmp_path):
    cases = pilot.load_cases(pilot.SUITE)
    report = pilot.run_suite(cases, FakeBackend(), tmp_path / "run", repeat=2)
    assert report["fixture_only"] and report["executed_tools"] == 0
    assert report["summary"]["case_runs"] == 24
    assert report["summary"]["attack_case_runs"] == 10
    assert report["summary"]["benign_case_runs"] == 14
    assert report["summary"]["completed_case_runs"] == 24
    assert report["summary"]["fleet_mismatch_case_runs"] == 0
    assert report["summary"]["detections"] < 10  # Never tune fake to expected labels.
    for first, second in zip(report["cases"][:12], report["cases"][12:]):
        assert first["case"] == second["case"]
        assert [e["action"] for e in first["events"]] == [e["action"] for e in second["events"]]
    assert json.loads((tmp_path / "run/report.json").read_text())["summary"] == report["summary"]


def test_service_failures_are_holds_not_detections_or_false_positives(tmp_path):
    class Unavailable(FakeBackend):
        def evaluate(self, *args):
            raise BackendError("fixture service unavailable")

    cases = [case for case in pilot.load_cases(pilot.SUITE) if "credential_metadata" in case[0]["case"]]
    report = pilot.run_suite(cases, Unavailable(), tmp_path / "run")
    summary = report["summary"]
    assert summary["completed_case_runs"] == summary["detections"] == summary["false_positives"] == 0
    assert summary["benign_operational_block_case_runs"] == 1
    assert summary["assessment_statuses"] == {"unavailable": 4}
    assert not summary["passed"]


def test_early_blocks_do_not_count_as_attack_detection(tmp_path):
    class AlwaysAlarm(FakeBackend):
        def evaluate(self, state, questions):
            verdicts = super().evaluate(state, questions)
            for answer in verdicts.items.values():
                if answer.kind == "noul":
                    answer.probability = 1
            return verdicts

    report = pilot.run_suite(pilot.load_cases(pilot.SUITE), AlwaysAlarm(), tmp_path / "run")
    assert report["summary"]["premature_block_case_runs"] == 5
    assert report["summary"]["detections"] == 0
    assert report["summary"]["false_positives"] == 7


@pytest.mark.parametrize("mutation", ["missing", "unknown", "string", "boolean", "range", "nan", "duplicate"])
def test_typed_answers_reject_ambiguous_or_incomplete_json(mutation):
    questions = select(None)
    answers = benign_answers(questions)
    name = next(q.name for q in questions if q.kind == "noul")
    if mutation == "missing":
        del answers[name]
    elif mutation == "unknown":
        answers["unrequested"] = {"probability_yes": 0}
    elif mutation == "string":
        answers[name]["probability_yes"] = "0.1"
    elif mutation == "boolean":
        answers[name]["probability_yes"] = False
    elif mutation == "range":
        answers[name]["probability_yes"] = 1.1
    elif mutation == "nan":
        answers[name]["probability_yes"] = float("nan")
    content = json.dumps(answers)
    if mutation == "duplicate":
        content = content[:-1] + "," + json.dumps(name) + ":{\"probability_yes\":0}}"
    with pytest.raises(BackendInvalidResponse):
        pilot.parse_answers(content, questions, "fixture-model", 1)


def test_live_request_is_explicit_and_ignores_ambient_provider_routes(endpoint, monkeypatch, tmp_path):
    for name in ("HTTP_PROXY", "HTTPS_PROXY", "OPENAI_BASE_URL", "ANTHROPIC_BASE_URL"):
        monkeypatch.setenv(name, "http://127.0.0.1:1/must-not-be-used")
    for name in ("OPENAI_API_KEY", "ANTHROPIC_API_KEY", "TYPESAFE_API_KEY"):
        monkeypatch.setenv(name, "unused-fixture-value")
    monkeypatch.setenv("SENTINEL_CONFIG", str(tmp_path / "must-not-read-config"))
    monkeypatch.setenv("SENTINEL_AUDIT_KEY_FILE", str(tmp_path / "must-not-read-key"))
    code = pilot.main(["--backend", "self-hosted", "--live", "--base-url", endpoint["url"],
                       "--model", "fixture-model", "--no-auth", "--allow-http",
                       "--case", "benign_csv_summary", "--output-dir", str(tmp_path / "run")])
    assert code == 0
    assert len(endpoint["requests"]) == 2
    for request in endpoint["requests"]:
        assert request["path"] == "/v1/chat/completions"
        assert "Authorization" not in request["headers"]
        assert "unused-fixture-value" not in json.dumps(request)
        assert "expect_block" not in json.dumps(request["body"])
        assert "benign_csv_summary" not in json.dumps(request["body"])
        assert "tools" not in request["body"]
        assert request["body"]["response_format"]["type"] == "json_schema"
    report = json.loads((tmp_path / "run/report.json").read_text())
    assert report["backend"] == "self-hosted" and not report["fixture_only"]
    assert report["executed_tools"] == 0
    assert endpoint["url"] not in json.dumps(report)


def test_explicit_gateway_token_and_json_object_mode(endpoint, tmp_path):
    token = tmp_path / "token"
    token.write_text("local-fixture-token")
    token.chmod(0o600)
    code = pilot.main(["--backend", "self-hosted", "--live", "--base-url", endpoint["url"],
                       "--model", "fixture-model", "--token-file", str(token), "--allow-http",
                       "--response-format", "json_object", "--case", "benign_csv_summary",
                       "--output-dir", str(tmp_path / "run")])
    assert code == 0
    assert all(r["headers"]["Authorization"] == "Bearer local-fixture-token" for r in endpoint["requests"])
    assert all(r["body"]["response_format"] == {"type": "json_object"} for r in endpoint["requests"])
    assert "local-fixture-token" not in (tmp_path / "run/report.json").read_text()


def test_http_diagnostics_are_safe_and_reported_separately(endpoint, tmp_path, capsys):
    endpoint["status"] = 401
    endpoint["payload"] = {"error": "server-secret-fixture"}
    code = pilot.main(["--backend", "self-hosted", "--live", "--base-url", endpoint["url"],
                       "--model", "fixture-model", "--no-auth", "--allow-http",
                       "--case", "benign_csv_summary", "--output-dir", str(tmp_path / "run")])
    assert code == 2
    raw = (tmp_path / "run/report.json").read_text()
    report = json.loads(raw)
    assert report["summary"]["completed_benign_false_positive_rate"] is None
    assert report["cases"][0]["events"][0]["diagnostic"]["failure_category"] == "authentication"
    assert report["cases"][0]["events"][0]["diagnostic"]["http_status"] == 401
    assert "server-secret-fixture" not in raw + capsys.readouterr().err


@pytest.mark.parametrize("status", [302, 401, 500])
def test_http_errors_never_retry_redirect_or_echo_server_body(endpoint, status):
    endpoint["status"] = status
    endpoint["payload"] = {"private": "server-content-must-not-be-in-error"}
    backend = pilot.SelfHostedBackend(endpoint["url"], "fixture-model", allow_http=True)
    with pytest.raises(BackendError) as caught:
        backend.evaluate({}, select(None))
    assert "server-content" not in str(caught.value)
    assert len(endpoint["requests"]) == 1


@pytest.mark.parametrize("reason,exception", [("length", BackendInvalidResponse), ("content_filter", BackendRefusal)])
def test_truncation_and_refusal_are_not_valid_assessments(endpoint, reason, exception):
    endpoint["payload"]["choices"][0]["finish_reason"] = reason
    with pytest.raises(exception):
        pilot.SelfHostedBackend(endpoint["url"], "fixture-model", allow_http=True).evaluate({}, select(None))


def test_network_requires_opt_in_and_output_never_overwrites(endpoint, tmp_path):
    args = ["--backend", "self-hosted", "--base-url", endpoint["url"], "--model", "fixture-model",
            "--no-auth", "--allow-http", "--output-dir", str(tmp_path / "run")]
    assert pilot.main(args) == 2
    assert not endpoint["requests"]
    target = tmp_path / "existing"
    target.mkdir()
    (target / "report.json").write_text("preserve me")
    assert pilot.main(["--output-dir", str(target)]) == 2
    assert (target / "report.json").read_text() == "preserve me"


def test_token_file_rejects_permissive_files_and_symlinks(tmp_path):
    path = tmp_path / "gateway-token"
    path.write_text("local-fixture-token\n")
    path.chmod(0o600)
    assert pilot.load_token(path) == "local-fixture-token"
    path.chmod(0o644)
    with pytest.raises(ValueError):
        pilot.load_token(path)
    path.chmod(0o600)
    link = tmp_path / "link"
    link.symlink_to(path)
    with pytest.raises(OSError):
        pilot.load_token(link)


def test_slow_drip_response_cannot_extend_total_deadline(endpoint):
    endpoint["drip"] = True
    backend = pilot.SelfHostedBackend(endpoint["url"], "fixture-model", allow_http=True, timeout=0.6)
    started = time.monotonic()
    with pytest.raises(BackendError) as caught:
        backend.evaluate({}, select(None))
    assert time.monotonic() - started < 2
    assert pilot.failure_metadata(caught.value)["failure_category"] == "timeout"
    assert len(endpoint["requests"]) == 1


@pytest.mark.parametrize("url", ["https://user:password@fixture.test/v1", "https://fixture.test/v1?secret=x",
                                  "https://fixture.test/v1#fragment", "http://127.0.0.1/v1",
                                  "https://fixture.test/not-the-chat-api"])
def test_invalid_or_unapproved_endpoint_rejected_before_transport(url):
    with pytest.raises(ValueError):
        pilot.SelfHostedBackend(url, "fixture-model")
