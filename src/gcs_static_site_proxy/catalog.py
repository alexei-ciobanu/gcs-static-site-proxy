"""Validate an explicit catalog of static-site prefix mounts."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any

CATALOG_CONFIG_NAME = ".gcs-static-site-proxy-sites.json"
MAX_CATALOG_CONFIG_BYTES = 128 * 1024
MAX_CATALOG_SITES = 100
MAX_SITE_TITLE_CHARACTERS = 120
SLUG_PATTERN = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?")


class CatalogError(ValueError):
    """Raised when a site catalog is malformed or unsafe."""


@dataclass(frozen=True)
class CatalogSite:
    slug: str
    title: str
    prefix: str


@dataclass(frozen=True)
class SiteCatalog:
    sites: tuple[CatalogSite, ...]
    source: str
    sha256: str
    generation: str | None = None


def validate_object_prefix(value: Any) -> str:
    if not isinstance(value, str):
        raise CatalogError("site prefix must be a string")
    prefix = value.strip("/")
    if (
        not prefix
        or "\\" in prefix
        or any(ord(character) < 0x20 or ord(character) == 0x7F for character in prefix)
        or len(prefix.encode("utf-8")) > 1024
    ):
        raise CatalogError("site prefix must be a safe, non-empty object prefix")
    if any(part in {"", ".", ".."} for part in prefix.split("/")):
        raise CatalogError("site prefix must not contain empty, dot, or dot-dot parts")
    return prefix


def validate_title(value: Any) -> str:
    if not isinstance(value, str) or not value.strip():
        raise CatalogError("site title must be a non-empty string")
    title = value.strip()
    if len(title) > MAX_SITE_TITLE_CHARACTERS:
        raise CatalogError(f"site title exceeds {MAX_SITE_TITLE_CHARACTERS} characters")
    if any(ord(character) < 0x20 or ord(character) == 0x7F for character in title):
        raise CatalogError("site title must not contain control characters")
    return title


def parse_catalog(
    body: bytes, *, source: str, generation: str | None = None
) -> SiteCatalog:
    if len(body) > MAX_CATALOG_CONFIG_BYTES:
        raise CatalogError(f"site catalog exceeds {MAX_CATALOG_CONFIG_BYTES} bytes")
    try:
        payload = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise CatalogError("site catalog must be valid UTF-8 JSON") from error
    if not isinstance(payload, dict):
        raise CatalogError("site catalog must be a JSON object")
    expected = {"version", "sites"}
    unknown = set(payload) - expected
    missing = expected - set(payload)
    if unknown:
        raise CatalogError(f"unknown site catalog fields: {sorted(unknown)}")
    if missing:
        raise CatalogError(f"missing site catalog fields: {sorted(missing)}")
    if payload["version"] != 1:
        raise CatalogError("site catalog version must be 1")
    if not isinstance(payload["sites"], list):
        raise CatalogError("sites must be an array")
    if len(payload["sites"]) > MAX_CATALOG_SITES:
        raise CatalogError(f"site catalog exceeds {MAX_CATALOG_SITES} sites")

    sites: list[CatalogSite] = []
    slugs: set[str] = set()
    prefixes: set[str] = set()
    for index, item in enumerate(payload["sites"]):
        if not isinstance(item, dict):
            raise CatalogError(f"site {index} must be a JSON object")
        site_expected = {"slug", "title", "prefix"}
        site_unknown = set(item) - site_expected
        site_missing = site_expected - set(item)
        if site_unknown:
            raise CatalogError(
                f"unknown fields for site {index}: {sorted(site_unknown)}"
            )
        if site_missing:
            raise CatalogError(
                f"missing fields for site {index}: {sorted(site_missing)}"
            )
        slug = item["slug"]
        if not isinstance(slug, str) or not SLUG_PATTERN.fullmatch(slug):
            raise CatalogError(
                f"site {index} slug must be lowercase letters, numbers, or hyphens"
            )
        if slug in slugs:
            raise CatalogError(f"duplicate site slug: {slug}")
        prefix = validate_object_prefix(item["prefix"])
        if prefix in prefixes:
            raise CatalogError(f"duplicate site prefix: {prefix}")
        slugs.add(slug)
        prefixes.add(prefix)
        sites.append(
            CatalogSite(
                slug=slug,
                title=validate_title(item["title"]),
                prefix=prefix,
            )
        )

    return SiteCatalog(
        sites=tuple(sites),
        source=source,
        sha256=hashlib.sha256(body).hexdigest(),
        generation=generation,
    )
