"""
Distributed tracing for Inferno.

This module provides tracing capabilities for debugging
and performance analysis of agent operations.
"""

from __future__ import annotations

import time
import uuid
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Generator

import structlog

logger = structlog.get_logger(__name__)


@dataclass
class Span:
    """A single span in a trace."""

    trace_id: str
    span_id: str
    name: str
    parent_span_id: str | None = None
    started_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    ended_at: datetime | None = None
    duration_ms: float = 0.0
    status: str = "ok"
    attributes: dict[str, Any] = field(default_factory=dict)
    events: list[dict[str, Any]] = field(default_factory=list)

    def add_attribute(self, key: str, value: Any) -> None:
        """Add an attribute to the span."""
        self.attributes[key] = value

    def add_event(self, name: str, attributes: dict[str, Any] | None = None) -> None:
        """Add an event to the span."""
        self.events.append({
            "name": name,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "attributes": attributes or {},
        })

    def set_status(self, status: str, message: str | None = None) -> None:
        """Set the span status."""
        self.status = status
        if message:
            self.attributes["status_message"] = message

    def end(self) -> None:
        """End the span."""
        self.ended_at = datetime.now(timezone.utc)
        self.duration_ms = (self.ended_at - self.started_at).total_seconds() * 1000

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "trace_id": self.trace_id,
            "span_id": self.span_id,
            "parent_span_id": self.parent_span_id,
            "name": self.name,
            "started_at": self.started_at.isoformat(),
            "ended_at": self.ended_at.isoformat() if self.ended_at else None,
            "duration_ms": self.duration_ms,
            "status": self.status,
            "attributes": self.attributes,
            "events": self.events,
        }


class Tracer:
    """
    Distributed tracer for Inferno operations.

    Provides hierarchical tracing of agent operations
    for debugging and performance analysis.
    """

    def __init__(self, operation_id: str) -> None:
        """
        Initialize the tracer.

        Args:
            operation_id: Operation identifier (used as trace ID).
        """
        self._trace_id = operation_id
        self._spans: list[Span] = []
        self._active_span: Span | None = None
        self._span_stack: list[Span] = []

        logger.debug("tracer_initialized", trace_id=self._trace_id)

    @property
    def trace_id(self) -> str:
        """Get the trace ID."""
        return self._trace_id

    @property
    def active_span(self) -> Span | None:
        """Get the currently active span."""
        return self._active_span

    @property
    def spans(self) -> list[Span]:
        """Get all recorded spans."""
        return self._spans.copy()

    def _generate_span_id(self) -> str:
        """Generate a unique span ID."""
        return uuid.uuid4().hex[:16]

    def start_span(
        self,
        name: str,
        attributes: dict[str, Any] | None = None,
    ) -> Span:
        """
        Start a new span.

        Args:
            name: Span name.
            attributes: Initial attributes.

        Returns:
            The new span.
        """
        parent_span_id = self._active_span.span_id if self._active_span else None

        span = Span(
            trace_id=self._trace_id,
            span_id=self._generate_span_id(),
            name=name,
            parent_span_id=parent_span_id,
        )

        if attributes:
            span.attributes.update(attributes)

        self._spans.append(span)

        # Push current span to stack and set new active
        if self._active_span:
            self._span_stack.append(self._active_span)
        self._active_span = span

        logger.debug(
            "span_started",
            trace_id=self._trace_id,
            span_id=span.span_id,
            name=name,
        )

        return span

    def end_span(self, span: Span | None = None) -> None:
        """
        End a span.

        Args:
            span: Span to end (defaults to active span).
        """
        span_to_end = span or self._active_span

        if span_to_end:
            span_to_end.end()

            logger.debug(
                "span_ended",
                trace_id=self._trace_id,
                span_id=span_to_end.span_id,
                name=span_to_end.name,
                duration_ms=span_to_end.duration_ms,
            )

            # Pop from stack if this was active span
            if span_to_end == self._active_span:
                self._active_span = self._span_stack.pop() if self._span_stack else None

    @contextmanager
    def span(
        self,
        name: str,
        attributes: dict[str, Any] | None = None,
    ) -> Generator[Span, None, None]:
        """
        Context manager for creating a span.

        Args:
            name: Span name.
            attributes: Initial attributes.

        Yields:
            The created span.
        """
        span = self.start_span(name, attributes)
        try:
            yield span
        except Exception as e:
            span.set_status("error", str(e))
            raise
        finally:
            self.end_span(span)

    def add_event(
        self,
        name: str,
        attributes: dict[str, Any] | None = None,
    ) -> None:
        """Add an event to the active span."""
        if self._active_span:
            self._active_span.add_event(name, attributes)

    def set_attribute(self, key: str, value: Any) -> None:
        """Set an attribute on the active span."""
        if self._active_span:
            self._active_span.add_attribute(key, value)

    def get_trace(self) -> dict[str, Any]:
        """
        Get the complete trace.

        Returns:
            Dictionary containing all spans.
        """
        return {
            "trace_id": self._trace_id,
            "spans": [s.to_dict() for s in self._spans],
            "span_count": len(self._spans),
        }


# Span decorators for common operations
def trace_tool_call(tracer: Tracer, tool_name: str):
    """Decorator for tracing tool calls."""
    def decorator(func):
        async def wrapper(*args, **kwargs):
            with tracer.span(f"tool.{tool_name}", {"tool.name": tool_name}):
                tracer.set_attribute("tool.input", str(kwargs)[:200])
                result = await func(*args, **kwargs)
                tracer.set_attribute("tool.success", result.success if hasattr(result, 'success') else True)
                return result
        return wrapper
    return decorator


def trace_api_call(tracer: Tracer):
    """Decorator for tracing API calls."""
    def decorator(func):
        async def wrapper(*args, **kwargs):
            with tracer.span("api.call", {"api.type": "anthropic"}):
                result = await func(*args, **kwargs)
                if hasattr(result, 'usage'):
                    tracer.set_attribute("api.input_tokens", result.usage.input_tokens)
                    tracer.set_attribute("api.output_tokens", result.usage.output_tokens)
                return result
        return wrapper
    return decorator


# Global tracer
_tracer: Tracer | None = None


def get_tracer() -> Tracer | None:
    """Get the global tracer."""
    return _tracer


def init_tracer(operation_id: str) -> Tracer:
    """Initialize the global tracer."""
    global _tracer
    _tracer = Tracer(operation_id)
    return _tracer
