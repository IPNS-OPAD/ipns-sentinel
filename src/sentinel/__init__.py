"""Sentinel: an in-workflow observer for AI agent fleets.

Reads each agent step (reasoning, proposed tool call, recent actions, tool
results, declared policy), scores it with typed decision primitives, and can
allow / warn / pause / kill before the tool call executes.
"""

from sentinel.state import AgentStep, ToolCall, Trajectory
from sentinel.engine import Decision, Action
from sentinel.observer import SentinelObserver

__version__ = "0.1.7"
__all__ = ["AgentStep", "ToolCall", "Trajectory", "Decision", "Action", "SentinelObserver", "__version__"]
