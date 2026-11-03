"""Optional extra trusted CA certificates (for networks that inspect HTTPS).

If ``QUARRY_DEMO_EXTRA_CA_DIR`` (default ``/certs`` in the container) contains ``*.pem`` or
``*.crt`` files, they are appended to the standard trust bundle and the combined file is
used by both ``requests`` (AI Defense) and the OpenAI client. TLS verification is never
disabled; this only *adds* trust anchors you explicitly supply.
"""

from __future__ import annotations

import logging
import os
import tempfile
from pathlib import Path

log = logging.getLogger("quarry_demo.tls")

PEM_BEGIN = "-----BEGIN CERTIFICATE-----"


def _base_bundle() -> str:
    for candidate in (
        os.environ.get("SSL_CERT_FILE"),
        "/etc/ssl/certs/ca-certificates.crt",
    ):
        if candidate and Path(candidate).is_file():
            return Path(candidate).read_text(encoding="utf-8", errors="ignore")
    try:
        import certifi

        return Path(certifi.where()).read_text(encoding="utf-8", errors="ignore")
    except Exception:  # noqa: BLE001
        return ""


RELAX_ENV = "QUARRY_DEMO_TLS_RELAX_X509_STRICT"


def relax_strict_enabled() -> bool:
    return os.environ.get(RELAX_ENV, "").strip().lower() in ("1", "true", "yes")


def relaxed_strict_context():
    """Opt-in SSLContext for networks whose inspection CA fails Python 3.13's strict X.509 profile.

    Python 3.13 sets ``ssl.VERIFY_X509_STRICT`` by default, which rejects some otherwise trusted
    corporate CAs (for example a CA certificate without a keyUsage extension, or a leaf without an
    authority key identifier). When ``QUARRY_DEMO_TLS_RELAX_X509_STRICT=1`` is set, this returns a
    context that still requires a trusted chain (standard roots plus any extra CAs), valid dates and
    a matching hostname (``CERT_REQUIRED``, ``check_hostname``) — only the extra strict-profile
    checks are cleared. Returns ``None`` when the option is off.
    """
    import ssl

    if not relax_strict_enabled():
        return None
    cafile = os.environ.get("SSL_CERT_FILE") or None
    ctx = ssl.create_default_context(cafile=cafile)
    if cafile is None:
        try:
            import certifi

            ctx.load_verify_locations(cafile=certifi.where())
        except Exception:  # noqa: BLE001
            pass
    ctx.verify_flags &= ~getattr(ssl, "VERIFY_X509_STRICT", 0)
    assert ctx.verify_mode == ssl.CERT_REQUIRED and ctx.check_hostname
    return ctx


def _loads_as_ca_bundle(text: str) -> bool:
    """True if OpenSSL can load every certificate in this PEM text."""
    import ssl

    try:
        ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT).load_verify_locations(cadata=text)
    except (ssl.SSLError, ValueError):
        return False
    return True


def configure_extra_cas(directory: str | None) -> int:
    """Returns the number of extra certificate files added (0 if none)."""
    if not directory:
        return 0
    folder = Path(directory)
    if not folder.is_dir():
        return 0
    extra: list[str] = []
    for path in sorted(folder.iterdir()):
        if path.suffix.lower() not in (".pem", ".crt") or not path.is_file():
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        if PEM_BEGIN not in text:
            log.warning("Skipped %s: not a PEM certificate (convert DER .cer files to PEM).", path.name)
            continue
        if not _loads_as_ca_bundle(text):
            log.warning("Skipped %s: the certificate data could not be parsed.", path.name)
            continue
        extra.append(text.strip())
    if not extra:
        return 0
    bundle = _base_bundle().rstrip() + "\n\n" + "\n\n".join(extra) + "\n"
    fd, out = tempfile.mkstemp(prefix="quarry-demo-ca-", suffix=".pem")
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(bundle)
    os.environ["SSL_CERT_FILE"] = out
    os.environ["REQUESTS_CA_BUNDLE"] = out
    log.info("Added %d extra CA certificate file(s) to the trust bundle.", len(extra))
    return len(extra)
