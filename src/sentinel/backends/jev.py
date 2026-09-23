"""Jev (TypeSafe System One) backend.

One `system_one` call evaluates every question in parallel over the same
state. Env: TYPESAFE_API_KEY (required), TYPESAFE_BASE_URL, TYPESAFE_DEFAULT_MODEL.
"""

from __future__ import annotations

import time
from typing import Any

from sentinel.backends.base import BackendError, BackendInvalidResponse, Verdict, Verdicts, validate_verdicts
from sentinel.questions import QuestionSpec


class JevBackend:
    name = "jev"

    def __init__(self, model: str | None = None, timeout: float = 5.0, max_retries: int = 0, base_url: str | None = None, **_: Any) -> None:
        try:
            from typesafe_sdk import AsyncTypeSafeClient, RetryPolicy, TypeSafeAPIResponseValidationError, TypeSafeClient
        except ImportError as e:  # pragma: no cover
            raise BackendError("typesafe-sdk not installed: pip install 'ipns-sentinel[jev]'") from e
        self._retry = RetryPolicy(max_retries=max_retries, timeout=timeout)
        self._invalid_response = TypeSafeAPIResponseValidationError
        self._base_url = base_url
        self._client = TypeSafeClient(model=model, timeout=timeout, retry=self._retry, base_url=base_url)
        self._aclient_cls = AsyncTypeSafeClient
        self._model = model
        self._timeout = timeout

    @staticmethod
    def _questions(questions: list[QuestionSpec]) -> dict[str, Any]:
        return {q.name: q.to_jev() for q in questions}

    @staticmethod
    def _parse(resp: Any, questions: list[QuestionSpec], t0: float) -> Verdicts:
        items: dict[str, Verdict] = {}
        nouls, choices, scores = resp.nouls, resp.choices, resp.scores
        for kind, answers in (("noul", nouls), ("choice", choices), ("score", scores)):
            if set(answers) != {q.name for q in questions if q.kind == kind}:
                raise BackendInvalidResponse("provider answer coverage does not match requested kinds", issue="provider_kind_coverage")
        for q in questions:
            if q.kind == "noul" and q.name in nouls:
                items[q.name] = Verdict(name=q.name, kind="noul", probability=float(nouls[q.name].noul))
            elif q.kind == "choice" and q.name in choices:
                a = choices[q.name]
                items[q.name] = Verdict(
                    name=q.name, kind="choice", label=a.choice, probability=float(a.confidence),
                    distribution={str(k): float(v) for k, v in dict(a.probabilities).items()},
                )
            elif q.kind == "score" and q.name in scores:
                a = scores[q.name]
                items[q.name] = Verdict(
                    name=q.name, kind="score", score=float(a.score), probability=float(a.confidence),
                    distribution={str(k): float(v) for k, v in dict(a.probabilities).items()},
                )
        usage = getattr(resp, "usage", None)
        return validate_verdicts(Verdicts(
            backend="jev", model=getattr(resp, "model", ""), latency_ms=(time.perf_counter() - t0) * 1000,
            input_tokens=int(getattr(usage, "input_tokens", 0) or 0), items=items,
        ), questions)

    def evaluate(self, state: dict[str, Any], questions: list[QuestionSpec]) -> Verdicts:
        t0 = time.perf_counter()
        try:
            resp = self._client.system_one(state, self._questions(questions))
        except self._invalid_response as e:
            raise BackendInvalidResponse("jev response failed schema validation", issue="schema") from e
        except Exception as e:  # TypeSafeError, missing key, validation, transport
            raise BackendError(f"jev: {type(e).__name__}: {e}") from e
        return self._parse(resp, questions, t0)

    async def aevaluate(self, state: dict[str, Any], questions: list[QuestionSpec]) -> Verdicts:
        t0 = time.perf_counter()
        kw: dict[str, Any] = {"timeout": self._timeout, "retry": self._retry, "base_url": self._base_url}
        if self._model:
            kw["model"] = self._model
        try:
            async with self._aclient_cls(**kw) as client:
                resp = await client.system_one(state, self._questions(questions))
        except self._invalid_response as e:
            raise BackendInvalidResponse("jev response failed schema validation", issue="schema") from e
        except Exception as e:  # TypeSafeError, missing key, validation, transport
            raise BackendError(f"jev: {type(e).__name__}: {e}") from e
        return self._parse(resp, questions, t0)
