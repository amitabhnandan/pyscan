"""Network egress self-test.

The scan must run with no internet access. This module verifies that the only
reachable TCP endpoint is the local model server, and that a handful of common
external hosts are NOT reachable. It is meant to run at the start of every
sandboxed scan and to fail the run loudly if the sandbox is not actually
isolated -- a scan that can phone home is a scan that can exfiltrate source.

It uses raw sockets only (stdlib), never DNS-over-HTTPS or any library that
might be routed through a proxy.
"""
from __future__ import annotations

import socket
from dataclasses import dataclass
from urllib.parse import urlparse


@dataclass
class EgressReport:
    local_model_reachable: bool
    external_blocked: bool
    external_probes: dict[str, bool]  # host -> reachable
    detail: str

    @property
    def ok(self) -> bool:
        return self.local_model_reachable and self.external_blocked


# Hosts that must NOT be reachable from inside the sandbox.
_EXTERNAL_PROBES = [
    ("pypi.org", 443),
    ("github.com", 443),
    ("8.8.8.8", 53),
    ("huggingface.co", 443),
    ("registry.npmjs.org", 443),
]


def _can_connect(host: str, port: int, timeout: float = 3.0) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def check_egress(model_base_url: str, *, strict: bool = True) -> EgressReport:
    parsed = urlparse(model_base_url)
    model_host = parsed.hostname or "127.0.0.1"
    model_port = parsed.port or (443 if parsed.scheme == "https" else 80)

    local_ok = _can_connect(model_host, model_port)

    probes: dict[str, bool] = {}
    for host, port in _EXTERNAL_PROBES:
        probes[f"{host}:{port}"] = _can_connect(host, port)
    external_blocked = not any(probes.values())

    lines = [
        f"local model {model_host}:{model_port} reachable: {local_ok}",
        f"external egress blocked: {external_blocked}",
    ]
    for hp, reachable in probes.items():
        lines.append(f"  {hp}: {'REACHABLE (bad)' if reachable else 'blocked'}")
    report = EgressReport(
        local_model_reachable=local_ok,
        external_blocked=external_blocked,
        external_probes=probes,
        detail="\n".join(lines),
    )
    if strict and not report.ok:
        raise SystemExit(
            "SANDBOX EGRESS CHECK FAILED -- refusing to run a security scan that "
            "is not network-isolated.\n" + report.detail +
            "\nFix the sandbox network (see sandbox/README.md) before scanning."
        )
    return report
