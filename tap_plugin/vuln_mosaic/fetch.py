"""HTTPS downloads with an allow-list, caps and a timeout (req-vuln-mosaic-integrity-4).

Standard library only: ``urllib`` and ``ssl`` resolve to the image's OpenSSL
(req-vuln-mosaic-fips). TLS verification is the default context and is never disabled.
"""

from __future__ import annotations

import hashlib
import ssl
import urllib.error
import urllib.request
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import IO, Any, Protocol
from urllib.parse import urlsplit

DEFAULT_TIMEOUT = 60.0
USER_AGENT = "vuln-mosaic-tap (+https://github.com/unified-systems-com/vuln-mosaic-tap)"


class FetchError(RuntimeError):
    """A download failed or was refused; ``str(exc)`` is the reason."""

    def __init__(self, message: str, status: int | None = None) -> None:
        super().__init__(message)
        self.status = status


class Opener(Protocol):
    def open(self, request: urllib.request.Request, timeout: float) -> Any: ...


class _AllowListRedirects(urllib.request.HTTPRedirectHandler):
    def __init__(self, allowed_hosts: frozenset[str]) -> None:
        self._allowed = allowed_hosts

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[no-untyped-def]
        check_url(newurl, self._allowed)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def check_url(url: str, allowed_hosts: frozenset[str]) -> None:
    parts = urlsplit(url)
    if parts.scheme != "https":
        raise FetchError(f"refusing non-HTTPS URL {url!r}")
    if parts.hostname not in allowed_hosts:
        raise FetchError(f"host {parts.hostname!r} is not on the allow-list")


@dataclass(frozen=True)
class Downloaded:
    sha256: str
    size: int
    headers: Mapping[str, str]


def default_opener(allowed_hosts: frozenset[str]) -> urllib.request.OpenerDirector:
    context = ssl.create_default_context()
    return urllib.request.build_opener(
        urllib.request.HTTPSHandler(context=context), _AllowListRedirects(allowed_hosts)
    )


class Fetcher:
    """Fetches from a fixed set of hosts. ``opener`` is injectable so tests use no network."""

    def __init__(self, allowed_hosts: frozenset[str], opener: Opener | None = None) -> None:
        self._allowed = allowed_hosts
        self._opener: Opener = opener if opener is not None else default_opener(allowed_hosts)

    def _open(self, url: str, timeout: float, headers: Mapping[str, str] | None) -> Any:
        check_url(url, self._allowed)
        request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, **(headers or {})})
        try:
            response = self._opener.open(request, timeout=timeout)
        except urllib.error.HTTPError as exc:
            raise FetchError(f"{url}: HTTP {exc.code}", status=exc.code) from None
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            raise FetchError(f"{url}: {getattr(exc, 'reason', exc)}") from None
        final = getattr(response, "url", None) or getattr(response, "geturl", lambda: url)()
        check_url(final, self._allowed)
        return response

    def get_bytes(
        self, url: str, *, max_bytes: int, timeout: float = DEFAULT_TIMEOUT, headers: Mapping[str, str] | None = None
    ) -> tuple[bytes, Mapping[str, str]]:
        response = self._open(url, timeout, headers)
        try:
            body = response.read(max_bytes + 1)
            header_map = {k.lower(): v for k, v in response.headers.items()}
        finally:
            response.close()
        if len(body) > max_bytes:
            raise FetchError(f"{url}: body larger than {max_bytes} bytes")
        return body, header_map

    def download(
        self,
        url: str,
        dest: Path,
        *,
        max_bytes: int,
        timeout: float = DEFAULT_TIMEOUT,
        headers: Mapping[str, str] | None = None,
    ) -> Downloaded:
        """Stream to ``dest`` (created exclusively) with a size cap; the digest is of what was received."""
        response = self._open(url, timeout, headers)
        digest, size = hashlib.sha256(), 0
        try:
            header_map = {k.lower(): v for k, v in response.headers.items()}
            declared = header_map.get("content-length")
            if declared is not None and declared.isdigit() and int(declared) > max_bytes:
                raise FetchError(f"{url}: declared length {declared} exceeds {max_bytes}")
            with open(dest, "xb") as out:
                _copy(response, out, digest, max_bytes, url)
                size = out.tell()
        finally:
            response.close()
        if declared is not None and declared.isdigit() and int(declared) != size:
            raise FetchError(f"{url}: truncated ({size} of {declared} bytes)")
        return Downloaded(digest.hexdigest(), size, header_map)


def _copy(response: Any, out: IO[bytes], digest: Any, max_bytes: int, url: str) -> None:
    total = 0
    while chunk := response.read(1 << 20):
        total += len(chunk)
        if total > max_bytes:
            raise FetchError(f"{url}: body larger than {max_bytes} bytes")
        digest.update(chunk)
        out.write(chunk)
