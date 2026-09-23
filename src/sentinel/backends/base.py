"""Backend protocol: evaluate typed questions over a state, return verdicts."""

from __future__ import annotations

import math
import re
from typing import Any, Protocol

from pydantic import BaseModel, Field

from sentinel.questions import QuestionSpec


class Verdict(BaseModel):
    name: str
    kind: str
    probability: float = 0.0          # noul: P(yes). choice/score: confidence.
    label: str | None = None          # choice: selected label
    score: float | None = None        # score: expected value
    distribution: dict[str, float] = Field(default_factory=dict)


class Verdicts(BaseModel):
    backend: str
    model: str = ""
    latency_ms: float = 0.0
    input_tokens: int = 0
    items: dict[str, Verdict] = Field(default_factory=dict)

    def get(self, name: str) -> Verdict | None:
        return self.items.get(name)


class BackendError(RuntimeError):
    """Raised when the backend cannot produce verdicts. The engine decides fail-open vs fail-closed."""


class BackendRefusal(BackendError):
    """The scoring model declined to evaluate the state. This is not an outage: a safety
    classifier refusing to look at a trajectory is itself evidence about that trajectory,
    so the observer treats it under `on_backend_refusal`, not `on_backend_error`."""


class BackendInvalidResponse(BackendError):
    """The provider did not return a complete assessment of the requested questions."""

    def __init__(self, message: str, *, issue: str = "unknown") -> None:
        super().__init__(message)
        self.issue = issue if issue in {"question_coverage", "answer_identity", "probability", "choice_label",
            "score_range", "distribution", "duplicate_unknown_or_wrong_kind", "provider_kind_coverage", "schema"} else "unknown"


def failure_metadata(error: Exception) -> dict[str, Any]:
    """Allowlisted diagnostics only: never stringify errors, headers or bodies.

    Provider adapters preserve an explicit cause. Inspect a bounded chain to
    distinguish transport failures without retaining sensitive server content.
    These categories are diagnostics, never permission to execute a tool.
    """
    current: BaseException = error
    seen: set[int] = set()
    for _ in range(8):
        kind = type(current).__name__
        code = getattr(current, "status_code", getattr(current, "status", None))
        if (isinstance(current, (BackendRefusal, BackendInvalidResponse, TimeoutError, ConnectionError))
                or type(code) is int and 100 <= code <= 599
                or "ValidationError" in kind
                or kind in {"APITimeoutError", "ReadTimeout", "ConnectTimeout", "PoolTimeout", "WriteTimeout",
                            "APIConnectionError", "ConnectError", "ReadError", "RemoteProtocolError"}):
            break
        if current.__cause__ is None or id(current.__cause__) in seen:
            break
        seen.add(id(current))
        current = current.__cause__
    name = type(current).__name__
    status = getattr(current, "status_code", getattr(current, "status", None))
    if type(status) is not int or not 100 <= status <= 599:
        status = None
    if isinstance(error, BackendRefusal):
        category = "refusal"
    elif isinstance(error, BackendInvalidResponse) or "ValidationError" in name:
        category = "invalid_response"
    elif isinstance(current, TimeoutError) or name in {"APITimeoutError", "ReadTimeout", "ConnectTimeout", "PoolTimeout", "WriteTimeout"}:
        category = "timeout"
    elif status in (401, 403):
        category = "authentication"
    elif status == 429:
        category = "rate_limit"
    elif status is not None and status >= 500:
        category = "server_error"
    elif status is not None and status >= 400:
        category = "client_error"
    elif isinstance(current, ConnectionError) or name in {"APIConnectionError", "ConnectError", "ReadError", "RemoteProtocolError"}:
        category = "connection"
    else:
        category = "unknown"
    result: dict[str, Any] = {"failure_category": category,
        "provider_error_type": name if re.fullmatch(r"[A-Za-z_][A-Za-z_0-9]{0,79}", name) else "unknown"}
    if status is not None:
        result["http_status"] = status
    if isinstance(error, BackendInvalidResponse):
        result["validation_issue"] = error.issue
    return result


def validate_verdicts(verdicts: Verdicts, questions: list[QuestionSpec]) -> Verdicts:
    expected = {q.name for q in questions}
    if len(expected) != len(questions) or set(verdicts.items) != expected:
        raise BackendInvalidResponse("assessment question coverage does not match request", issue="question_coverage")
    for question in questions:
        answer = verdicts.items[question.name]
        if answer.name != question.name or answer.kind != question.kind:
            raise BackendInvalidResponse("assessment name or kind does not match request", issue="answer_identity")
        if not math.isfinite(answer.probability) or not 0 <= answer.probability <= 1:
            raise BackendInvalidResponse("assessment probability must be finite and in [0, 1]", issue="probability")
        if question.kind == "choice" and answer.label not in question.labels:
            raise BackendInvalidResponse("assessment label is not an offered choice", issue="choice_label")
        if question.kind == "score" and (answer.score is None or not math.isfinite(answer.score)
                                         or not 0 <= answer.score <= len(question.levels) - 1):
            raise BackendInvalidResponse("assessment score is outside the requested rubric", issue="score_range")
        labels = set(question.labels) if question.kind == "choice" else {str(i) for i in range(len(question.levels))}
        for label, probability in answer.distribution.items():
            if label not in labels or not math.isfinite(probability) or not 0 <= probability <= 1:
                raise BackendInvalidResponse("assessment distribution contains invalid values", issue="distribution")
    return verdicts


class Backend(Protocol):
    name: str

    def evaluate(self, state: dict[str, Any], questions: list[QuestionSpec]) -> Verdicts: ...

    async def aevaluate(self, state: dict[str, Any], questions: list[QuestionSpec]) -> Verdicts: ...
