"""Minimal agent-facing JSONL protocol; no operator commands or policy input."""
from __future__ import annotations

import json
from typing import Literal, TextIO

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from sentinel.execution.broker import ExecutionBroker, ExecutionRequest, PermitRejected


class Message(BaseModel):
    model_config = ConfigDict(extra="forbid")
    op: Literal["authorize", "execute"]
    request: ExecutionRequest
    permit: str | None = Field(default=None, min_length=43, max_length=43)


def serve(broker: ExecutionBroker, source: TextIO, destination: TextIO) -> None:
    while line := source.readline(65537):
        if len(line.encode()) > 65536 or not line.endswith("\n"):
            destination.write('{"error":"invalid_frame"}\n')
            destination.flush()
            return
        try:
            message = Message.model_validate_json(line)
            if message.op == "authorize" and message.permit is None:
                reply = broker.authorize(message.request).model_dump(mode="json")
            elif message.op == "execute" and message.permit is not None:
                reply = broker.execute(message.request, message.permit).model_dump(mode="json")
            else:
                raise ValueError("permit required only for execute")
        except PermitRejected:
            reply = {"error": "authorization_rejected"}
        except (ValidationError, ValueError):
            reply = {"error": "invalid_request"}
        except Exception:
            # Unknown infrastructure/audit faults stop this connection. Never turn
            # an ambiguous outcome into an automatic retry of the same invocation.
            destination.write('{"error":"broker_unavailable"}\n')
            destination.flush()
            return
        destination.write(json.dumps(reply, allow_nan=False) + "\n")
        destination.flush()
