"""Resolve and validate the site's browser security policy."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Any

SITE_CONFIG_NAME = ".gcs-static-site-proxy.json"
MAX_SITE_CONFIG_BYTES = 32 * 1024
MAX_CSP_BYTES = 16 * 1024
STRICT_STATIC_CSP = (
    "default-src 'self'; "
    "script-src 'self'; "
    "style-src 'self' 'unsafe-inline'; "
    "img-src 'self' data:; "
    "connect-src 'self'; "
    "object-src 'none'; "
    "base-uri 'none'; "
    "form-action 'none'; "
    "frame-ancestors 'none'"
)


class SiteConfigError(ValueError):
    """Raised when a site configuration is malformed or unsafe as a header."""


@dataclass(frozen=True)
class ContentSecurityPolicy:
    value: str | None
    source: str
    sha256: str | None = None
    generation: str | None = None


class BrowserCacheMode(StrEnum):
    """Browser caching policy for non-HTML site objects."""

    NO_STORE = "no-store"
    REVALIDATE = "revalidate"


@dataclass(frozen=True)
class BrowserCachePolicy:
    mode: BrowserCacheMode
    source: str


@dataclass(frozen=True)
class SiteConfiguration:
    csp: ContentSecurityPolicy
    browser_cache: BrowserCachePolicy


def validate_csp(value: Any) -> str:
    if not isinstance(value, str) or not value.strip():
        raise SiteConfigError("contentSecurityPolicy must be a non-empty string")
    policy = value.strip()
    encoded = policy.encode("utf-8")
    if len(encoded) > MAX_CSP_BYTES:
        raise SiteConfigError(
            f"contentSecurityPolicy exceeds {MAX_CSP_BYTES} UTF-8 bytes"
        )
    if any(ord(character) < 0x20 or ord(character) > 0x7E for character in policy):
        raise SiteConfigError("contentSecurityPolicy must contain printable ASCII only")
    return policy


def parse_site_config(
    body: bytes, *, source: str, generation: str | None = None
) -> SiteConfiguration:
    if len(body) > MAX_SITE_CONFIG_BYTES:
        raise SiteConfigError(
            f"site configuration exceeds {MAX_SITE_CONFIG_BYTES} bytes"
        )
    try:
        decoded = body.decode("utf-8")
        payload = json.loads(decoded)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise SiteConfigError("site configuration must be valid UTF-8 JSON") from error
    if not isinstance(payload, dict):
        raise SiteConfigError("site configuration must be a JSON object")
    required = {"version", "contentSecurityPolicy"}
    expected = required | {"browserCache"}
    unknown = set(payload) - expected
    missing = required - set(payload)
    if unknown:
        raise SiteConfigError(f"unknown site configuration fields: {sorted(unknown)}")
    if missing:
        raise SiteConfigError(f"missing site configuration fields: {sorted(missing)}")
    if payload["version"] != 1:
        raise SiteConfigError("site configuration version must be 1")
    policy = validate_csp(payload["contentSecurityPolicy"])
    try:
        browser_cache = BrowserCacheMode(
            payload.get("browserCache", BrowserCacheMode.NO_STORE)
        )
    except (TypeError, ValueError) as error:
        supported = ", ".join(mode.value for mode in BrowserCacheMode)
        raise SiteConfigError(f"browserCache must be one of: {supported}") from error
    return SiteConfiguration(
        csp=ContentSecurityPolicy(
            value=policy,
            source=source,
            sha256=hashlib.sha256(body).hexdigest(),
            generation=generation,
        ),
        browser_cache=BrowserCachePolicy(mode=browser_cache, source=source),
    )


def load_csp_file(path: Path) -> ContentSecurityPolicy:
    try:
        body = path.read_bytes()
    except OSError as error:
        raise SiteConfigError(f"unable to read CSP file {path}: {error}") from error
    if len(body) > MAX_CSP_BYTES:
        raise SiteConfigError(f"CSP file exceeds {MAX_CSP_BYTES} bytes")
    try:
        value = validate_csp(body.decode("utf-8"))
    except UnicodeDecodeError as error:
        raise SiteConfigError("CSP file must be UTF-8") from error
    return ContentSecurityPolicy(
        value=value,
        source=str(path),
        sha256=hashlib.sha256(body).hexdigest(),
    )


def default_csp() -> ContentSecurityPolicy:
    return ContentSecurityPolicy(value=STRICT_STATIC_CSP, source="built-in default")


def default_browser_cache() -> BrowserCachePolicy:
    return BrowserCachePolicy(
        mode=BrowserCacheMode.NO_STORE,
        source="built-in default",
    )
