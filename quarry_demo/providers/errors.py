"""Safe provider error representation shared by adapters."""

from __future__ import annotations

import re
import ssl
from dataclasses import dataclass
from typing import Optional


@dataclass(frozen=True)
class ProviderError:
    code: str
    message: str
    http_status: Optional[int] = None

    def public(self) -> dict:
        data = {"code": self.code, "message": self.message}
        if self.http_status is not None:
            data["http_status"] = self.http_status
        return data


_REASON_RE = re.compile(r"certificate verify failed: ([A-Za-z0-9 ,.'()_\-]{3,120}?)\s*(?:\(_ssl\.c|\)|$)")
_SAFE_REASON = re.compile(r"^[A-Za-z0-9 ,.'()_\-]{3,120}$")


def tls_failure_reason(exc: BaseException) -> Optional[str]:
    """The OpenSSL verification reason (e.g. 'unable to get local issuer certificate'), if present.

    These are fixed library strings, not provider- or user-supplied text, and contain no secrets.
    """
    seen: set[int] = set()
    stack: list[BaseException] = [exc]
    while stack:
        current = stack.pop()
        if current is None or id(current) in seen:
            continue
        seen.add(id(current))
        if isinstance(current, ssl.SSLCertVerificationError):
            msg = getattr(current, "verify_message", None)
            if isinstance(msg, str) and _SAFE_REASON.match(msg):
                return msg
        m = _REASON_RE.search(str(current)[:600])
        if m:
            return m.group(1).strip()
        for nxt in (current.__cause__, current.__context__, *[a for a in getattr(current, "args", ()) if isinstance(a, BaseException)]):
            if nxt is not None:
                stack.append(nxt)
    return None


STRICT_REASONS = (
    "key usage",
    "basic constraints",
    "authority key identifier",
    "subject key identifier",
    "missing authority key",
)


def tls_message(provider: str, exc: BaseException) -> str:
    reason = tls_failure_reason(exc)
    base = f"TLS certificate verification to {provider} failed"
    if reason:
        base += f" ({reason})"
    lower = (reason or "").lower()
    if any(k in lower for k in STRICT_REASONS):
        hint = (
            ". The certificate chain was found but does not meet Python 3.13's strict X.509 checks — common with "
            "corporate inspection CAs. See README section 5: set QUARRY_DEMO_TLS_RELAX_X509_STRICT=1 after "
            "confirming the CA with IT."
        )
    else:
        hint = (
            ". If your network inspects HTTPS traffic, mount your organisation's root CA into /certs "
            "(README section 5: Corporate networks and TLS inspection)."
        )
    return base + hint + " Verification was not disabled."


def find_tls_error(exc: BaseException) -> bool:
    """Walk the exception chain looking for a certificate verification failure."""
    seen: set[int] = set()
    current: Optional[BaseException] = exc
    while current is not None and id(current) not in seen:
        seen.add(id(current))
        if isinstance(current, ssl.SSLCertVerificationError):
            return True
        text = type(current).__name__ + " " + str(current)[:500]
        if "CERTIFICATE_VERIFY_FAILED" in text or "certificate verify failed" in text:
            return True
        current = current.__cause__ or current.__context__
        # requests wraps urllib3 errors in .args
        if current is None and getattr(exc, "args", None):
            for arg in exc.args:
                if isinstance(arg, BaseException) and id(arg) not in seen:
                    current = arg
                    break
    return False
