"""Where is this agent running? Best-effort sandbox identity for joining to infra logs."""

from __future__ import annotations

import os
import re
import socket
from pathlib import Path

_CONTAINER_ID = re.compile(r"(?:docker|containers|crio|containerd|libpod)[-/:]([0-9a-f]{64})")
_K8S_NAMESPACE = Path("/var/run/secrets/kubernetes.io/serviceaccount/namespace")


def detect_sandbox_id() -> str:
    """Identify the sandbox, most specific first.

    1. ``MNESTIQ_SANDBOX_ID``, if set (VM id, task ARN, ...).
    2. Kubernetes pod: ``k8s:<namespace>/<pod>``.
    3. Container id from cgroups / mountinfo: ``container:<12-char id>``.
    4. ``host:<hostname>``.
    """
    explicit = os.environ.get("MNESTIQ_SANDBOX_ID")
    if explicit:
        return explicit
    hostname = socket.gethostname()
    if os.environ.get("KUBERNETES_SERVICE_HOST"):
        namespace = _read(_K8S_NAMESPACE) or "default"
        return f"k8s:{namespace}/{hostname}"
    container = _container_id()
    if container:
        return f"container:{container[:12]}"
    return f"host:{hostname}"


def _container_id() -> str | None:
    for path in ("/proc/self/cgroup", "/proc/self/mountinfo"):
        match = _CONTAINER_ID.search(_read(Path(path)) or "")
        if match:
            return match.group(1)
    return None


def _read(path: Path) -> str | None:
    try:
        return path.read_text(encoding="utf-8", errors="replace").strip()
    except OSError:
        return None
