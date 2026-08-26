from __future__ import annotations

import json

import pytest

from gcs_static_site_proxy.catalog import CatalogError, parse_catalog


def catalog_bytes(payload: object) -> bytes:
    return json.dumps(payload, separators=(",", ":")).encode()


def test_catalog_parses_explicit_mounts_and_records_provenance() -> None:
    body = catalog_bytes(
        {
            "version": 1,
            "sites": [
                {
                    "slug": "first-site",
                    "title": "First site",
                    "prefix": "/team/projects/first/publication/site/",
                },
                {
                    "slug": "second",
                    "title": "Second site",
                    "prefix": "team/projects/second/publication/site",
                },
            ],
        }
    )
    result = parse_catalog(body, source="gs://bucket/catalog", generation="42")
    assert [site.slug for site in result.sites] == ["first-site", "second"]
    assert result.sites[0].prefix == "team/projects/first/publication/site"
    assert result.source == "gs://bucket/catalog"
    assert result.generation == "42"
    assert len(result.sha256) == 64


@pytest.mark.parametrize(
    "payload",
    [
        {"version": 2, "sites": []},
        {"version": 1},
        {"version": 1, "sites": "not-an-array"},
        {"version": 1, "sites": [], "unexpected": True},
        {
            "version": 1,
            "sites": [{"slug": "Bad Slug", "title": "Title", "prefix": "site"}],
        },
        {
            "version": 1,
            "sites": [
                {"slug": "same", "title": "One", "prefix": "site/one"},
                {"slug": "same", "title": "Two", "prefix": "site/two"},
            ],
        },
        {
            "version": 1,
            "sites": [
                {"slug": "one", "title": "One", "prefix": "site/same"},
                {"slug": "two", "title": "Two", "prefix": "site/same"},
            ],
        },
        {
            "version": 1,
            "sites": [{"slug": "unsafe", "title": "Title", "prefix": "../site"}],
        },
    ],
)
def test_catalog_rejects_invalid_or_ambiguous_mounts(payload: object) -> None:
    with pytest.raises(CatalogError):
        parse_catalog(catalog_bytes(payload), source="test")


def test_catalog_rejects_invalid_encoding_and_oversize() -> None:
    with pytest.raises(CatalogError, match="UTF-8 JSON"):
        parse_catalog(b"\xff", source="test")
    with pytest.raises(CatalogError, match="exceeds"):
        parse_catalog(b" " * (128 * 1024 + 1), source="test")
