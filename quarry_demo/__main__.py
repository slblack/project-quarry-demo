"""Entry point: ``python -m quarry_demo``.

Environment variables:
  QUARRY_DEMO_HOST           bind address (default 127.0.0.1)
  QUARRY_DEMO_PORT           port (default 5075; if unset and 5075 is busy, 5076 is tried)
  QUARRY_DEMO_DATA_DIR       where settings.json is stored (default ./data)
  QUARRY_DEMO_ALLOWED_HOSTS  extra Host header names, comma separated (default none)
  QUARRY_DEMO_EXTRA_CA_DIR   folder of extra PEM CA certificates (default none; /certs in Docker)
"""

from __future__ import annotations

import errno
import logging
import os
import socket
import sys

DEFAULT_PORT = 5075
ALTERNATIVE_PORT = 5076


def _port_free(host: str, port: int) -> bool:
    family = socket.AF_INET6 if ":" in host else socket.AF_INET
    with socket.socket(family, socket.SOCK_STREAM) as s:
        try:
            s.bind((host, port))
        except OSError as exc:
            if exc.errno in (errno.EADDRINUSE, getattr(errno, "WSAEADDRINUSE", -1), errno.EACCES):
                return False
            raise
    return True


def main() -> int:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    log = logging.getLogger("quarry_demo")

    from .tls import configure_extra_cas

    added = configure_extra_cas(os.environ.get("QUARRY_DEMO_EXTRA_CA_DIR"))
    if added == 0:
        log.info("No extra CA certificates supplied; using the standard trust store.")
    from .tls import relax_strict_enabled

    if relax_strict_enabled():
        log.warning(
            "QUARRY_DEMO_TLS_RELAX_X509_STRICT is on: OpenAI and AI Defense connections still require a trusted chain and "
            "matching hostname, but Python's extra strict X.509 profile checks are relaxed."
        )

    from .app import create_app
    from .security import is_loopback_bind

    host = os.environ.get("QUARRY_DEMO_HOST", "127.0.0.1").strip()
    port_env = os.environ.get("QUARRY_DEMO_PORT", "").strip()
    port = int(port_env) if port_env else DEFAULT_PORT

    if not is_loopback_bind(host):
        log.warning(
            "Binding to %s (not loopback). This is intended only inside a container whose port is "
            "published to 127.0.0.1 on the host. Do not expose this demo to a network.",
            host,
        )

    if not _port_free(host, port):
        if port_env:
            log.error("Port %s is already in use. Choose another with QUARRY_DEMO_PORT; no process was stopped.", port)
            return 2
        log.warning("Port %s is already in use; trying documented alternative port %s.", port, ALTERNATIVE_PORT)
        port = ALTERNATIVE_PORT
        if not _port_free(host, port):
            log.error("Port %s is also in use. Set QUARRY_DEMO_PORT to a free port; no process was stopped.", port)
            return 2

    extra_hosts = tuple(h for h in os.environ.get("QUARRY_DEMO_ALLOWED_HOSTS", "").split(",") if h.strip())
    app = create_app(extra_hosts=extra_hosts)
    shown = "127.0.0.1" if not is_loopback_bind(host) else host
    log.info("Project Quarry demo listening on http://%s:%s (debug off, reloader off)", shown, port)
    app.run(host=host, port=port, debug=False, use_reloader=False, threaded=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
