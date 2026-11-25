"""GateEngine V3 - OpenTelemetry Integration.

Outputs risk decisions as OTel spans/events for integration with
Datadog, Grafana, Honeycomb, ELK, and SIEM systems.

Configuration:
- GATE_ENGINE_OTEL_ENABLED: Enable OTel export (default: false)
- GATE_ENGINE_OTEL_ENDPOINT: OTel collector endpoint
- GATE_ENGINE_OTEL_SERVICE_NAME: Service name (default: GateEngine-v3)
"""

from __future__ import annotations

import os
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class OTelSpan:
    """Represents an OpenTelemetry span for a governance decision."""
    trace_id: str
    span_id: str
    name: str
    start_time: float
    end_time: float = 0.0
    attributes: Dict[str, Any] = field(default_factory=dict)
    events: List[Dict[str, Any]] = field(default_factory=list)
    status: str = "OK"
    resource: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "trace_id": self.trace_id,
            "span_id": self.span_id,
            "name": self.name,
            "start_time": self.start_time,
            "end_time": self.end_time,
            "attributes": self.attributes,
            "events": self.events,
            "status": self.status,
            "resource": self.resource,
        }


class OTelExporter:
    """Exports GateEngine governance decisions as OTel-compatible data.

    Can output to:
    - OTLP collector (when opentelemetry-sdk is installed)
    - JSON log file
    - stdout (for development)
    """

    SERVICE_NAME = os.environ.get("GATE_ENGINE_OTEL_SERVICE_NAME", "GateEngine-v3")
    ENABLED = os.environ.get("GATE_ENGINE_OTEL_ENABLED", "false").lower() == "true"
    ENDPOINT = os.environ.get("GATE_ENGINE_OTEL_ENDPOINT", "")

    def __init__(self):
        self._spans: List[OTelSpan] = []
        self._tracer = None

        if self.ENABLED:
            self._init_tracer()

    def _init_tracer(self):
        """Initialize OTel tracer if SDK is available."""
        try:
            from opentelemetry import trace
            from opentelemetry.sdk.resources import Resource
            from opentelemetry.sdk.trace import TracerProvider
            from opentelemetry.sdk.trace.export import BatchSpanProcessor

            resource = Resource.create({"service.name": self.SERVICE_NAME})
            provider = TracerProvider(resource=resource)

            if self.ENDPOINT:
                try:
                    from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import (
                        OTLPSpanExporter,
                    )
                    exporter = OTLPSpanExporter(endpoint=self.ENDPOINT)
                    provider.add_span_processor(BatchSpanProcessor(exporter))
                except ImportError:
                    pass

            trace.set_tracer_provider(provider)
            self._tracer = trace.get_tracer(self.SERVICE_NAME)
        except ImportError:
            pass

    def emit_decision_span(
        self,
        session_id: str,
        decision: str,
        risk_score: float,
        risk_level: str,
        tool_name: str,
        agent_id: str,
        policy_id: str = "",
        graph_path_hash: str = "",
        tenant_id: str = "default",
        graph_risk_state: Optional[Dict[str, Any]] = None,
    ) -> OTelSpan:
        """Emit an OTel span for a governance decision.

        This is the main integration point for observability.
        """
        now = time.time()
        span = OTelSpan(
            trace_id=uuid.uuid4().hex[:32],
            span_id=uuid.uuid4().hex[:16],
            name=f"GateEngine.decision.{decision}",
            start_time=now,
            end_time=now,
            attributes={
                "GateEngine.session_id": session_id,
                "GateEngine.decision": decision,
                "GateEngine.risk_score": risk_score,
                "GateEngine.risk_level": risk_level,
                "GateEngine.tool_name": tool_name,
                "GateEngine.agent_id": agent_id,
                "GateEngine.policy_id": policy_id,
                "GateEngine.graph_path": graph_path_hash,
                "GateEngine.tenant_id": tenant_id,
            },
            resource={"service.name": self.SERVICE_NAME},
        )

        # Add graph risk state as nested attributes
        if graph_risk_state:
            for key, value in graph_risk_state.items():
                if isinstance(value, (str, int, float, bool)):
                    span.attributes[f"GateEngine.graph.{key}"] = value

        # Set status based on decision
        if decision == "block":
            span.status = "ERROR"
        elif decision == "review":
            span.status = "UNSET"
        else:
            span.status = "OK"

        self._spans.append(span)

        # Export to OTel SDK if available
        if self._tracer:
            self._export_to_otel_sdk(span)

        return span

    def emit_risk_signal_event(
        self,
        session_id: str,
        signal_type: str,
        signal_score: float,
        evidence: List[str],
    ) -> Dict[str, Any]:
        """Emit an OTel event for a risk signal detection."""
        event = {
            "name": f"GateEngine.risk_signal.{signal_type}",
            "timestamp": time.time(),
            "attributes": {
                "GateEngine.session_id": session_id,
                "GateEngine.signal_type": signal_type,
                "GateEngine.signal_score": signal_score,
                "GateEngine.evidence_count": len(evidence),
            },
        }
        return event

    def get_recent_spans(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Get recent spans for debugging/export."""
        return [s.to_dict() for s in self._spans[-limit:]]

    def _export_to_otel_sdk(self, span: OTelSpan) -> None:
        """Export span to OTel SDK tracer."""
        if not self._tracer:
            return
        try:
            with self._tracer.start_as_current_span(span.name) as otel_span:
                for key, value in span.attributes.items():
                    otel_span.set_attribute(key, value)
                if span.status == "ERROR":
                    # StatusCode comes from the same optional SDK as the tracer;
                    # importing it lazily avoids a NameError when tracing is on
                    # but the symbol was never brought into scope.
                    from opentelemetry.trace import StatusCode

                    otel_span.set_status(StatusCode.ERROR)
        except Exception:
            pass


# Global exporter instance
_exporter: Optional[OTelExporter] = None


def get_otel_exporter() -> OTelExporter:
    """Get or create the global OTel exporter."""
    global _exporter
    if _exporter is None:
        _exporter = OTelExporter()
    return _exporter
