"""gRPC server entrypoint for VertGuard ML.

Synchronous threadpool server (max_workers=10) — async overhead is
unjustified at the stub-model latency floor and complicates the
eventual ONNX/Torch backend integration.
"""

from __future__ import annotations

import logging
import os
import signal
import sys
from concurrent import futures

import grpc
import structlog
from grpc_health.v1 import health, health_pb2, health_pb2_grpc
from grpc_reflection.v1alpha import reflection

from vertguard_ml.service import InferenceService, add_to_server

DEFAULT_PORT = 50051
SHUTDOWN_GRACE_SECONDS = 5.0


def _configure_logging() -> None:
    """structlog → JSON to stdout. WHY: Loki / Vector parse this directly."""
    logging.basicConfig(
        format="%(message)s",
        stream=sys.stdout,
        level=os.environ.get("VERTGUARD_ML_LOG_LEVEL", "INFO").upper(),
    )
    structlog.configure(
        processors=[
            structlog.contextvars.merge_contextvars,
            structlog.processors.add_log_level,
            structlog.processors.TimeStamper(fmt="iso", utc=True, key="ts"),
            structlog.processors.EventRenamer("event"),
            structlog.processors.JSONRenderer(),
        ],
        wrapper_class=structlog.make_filtering_bound_logger(logging.INFO),
        cache_logger_on_first_use=True,
    )


def _register_reflection(server: grpc.Server) -> None:
    """grpcurl-friendly reflection — invaluable in ops."""
    try:
        from vertguard_ml.proto.ml.v1 import inference_pb2

        service_names = (
            inference_pb2.DESCRIPTOR.services_by_name["InferenceService"].full_name,
            reflection.SERVICE_NAME,
            health.SERVICE_NAME,
        )
        reflection.enable_server_reflection(service_names, server)
    except Exception:  # noqa: BLE001  # pragma: no cover
        # Reflection is debug-only; never block server start on it.
        structlog.get_logger().warning("reflection_unavailable", exc_info=True)


def serve(port: int | None = None) -> grpc.Server:
    """Build and start a server. Returns the running server (caller waits)."""
    port = port if port is not None else int(os.environ.get("VERTGUARD_ML_PORT", DEFAULT_PORT))

    server = grpc.server(futures.ThreadPoolExecutor(max_workers=10))

    servicer = InferenceService()
    add_to_server(servicer, server)

    # Health: serving as soon as the model is loaded.
    health_servicer = health.HealthServicer()
    health_pb2_grpc.add_HealthServicer_to_server(health_servicer, server)
    health_servicer.set("", health_pb2.HealthCheckResponse.SERVING)
    health_servicer.set("vertguard.ml.v1.InferenceService", health_pb2.HealthCheckResponse.SERVING)

    _register_reflection(server)

    server.add_insecure_port(f"[::]:{port}")
    server.start()
    structlog.get_logger().info("server_started", port=port, backend=servicer.model.backend)
    return server


def main() -> None:
    _configure_logging()
    server = serve()

    def _shutdown(signum: int, _frame: object) -> None:
        structlog.get_logger().info("server_stopping", signal=signum)
        server.stop(SHUTDOWN_GRACE_SECONDS).wait()

    signal.signal(signal.SIGTERM, _shutdown)
    # WHY: SIGINT (Ctrl-C) handled too so local dev shuts down cleanly.
    signal.signal(signal.SIGINT, _shutdown)

    server.wait_for_termination()


if __name__ == "__main__":
    main()
