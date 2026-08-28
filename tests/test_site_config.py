from __future__ import annotations

import json

import pytest

from gcs_static_site_proxy.site_config import (
    MAX_SITE_CONFIG_BYTES,
    STRICT_STATIC_CSP,
    BrowserCacheMode,
    SiteConfigError,
    default_csp,
    parse_site_config,
    validate_csp,
)


def encoded_config(policy: object, *, version: object = 1, **extra: object) -> bytes:
    return json.dumps(
        {"version": version, "contentSecurityPolicy": policy, **extra}
    ).encode()


def test_default_policy_is_strict_and_self_contained() -> None:
    policy = default_csp()
    assert policy.value == STRICT_STATIC_CSP
    assert "'unsafe-eval'" not in (policy.value or "")
    assert "https:" not in (policy.value or "")
    assert policy.source == "built-in default"


def test_parse_site_config_records_provenance() -> None:
    body = encoded_config("default-src 'self'; script-src 'self' 'unsafe-eval'")
    configured = parse_site_config(
        body, source="gs://bucket/site/config", generation="7"
    )
    assert configured.csp.value == (
        "default-src 'self'; script-src 'self' 'unsafe-eval'"
    )
    assert configured.csp.source == "gs://bucket/site/config"
    assert configured.csp.generation == "7"
    assert len(configured.csp.sha256 or "") == 64
    assert configured.browser_cache.mode is BrowserCacheMode.NO_STORE


def test_parse_site_config_enables_opt_in_revalidation() -> None:
    configured = parse_site_config(
        encoded_config("default-src 'self'", browserCache="revalidate"),
        source="test",
    )
    assert configured.browser_cache.mode is BrowserCacheMode.REVALIDATE


@pytest.mark.parametrize(
    ("body", "message"),
    [
        (b"not json", "valid UTF-8 JSON"),
        (b"[]", "JSON object"),
        (json.dumps({"version": 1}).encode(), "missing"),
        (encoded_config("default-src 'self'", unexpected=True), "unknown"),
        (encoded_config("default-src 'self'", version=2), "version must be 1"),
        (
            encoded_config("default-src 'self'", browserCache="forever"),
            "browserCache must be one of",
        ),
        (
            encoded_config("default-src 'self'", browserCache=[]),
            "browserCache must be one of",
        ),
        (encoded_config(""), "non-empty string"),
        (encoded_config(None), "non-empty string"),
        (encoded_config("default-src 'self'\nX-Test: yes"), "printable ASCII"),
    ],
)
def test_invalid_site_config_is_rejected(body: bytes, message: str) -> None:
    with pytest.raises(SiteConfigError, match=message):
        parse_site_config(body, source="test")


def test_oversized_site_config_is_rejected() -> None:
    with pytest.raises(SiteConfigError, match="exceeds"):
        parse_site_config(b"x" * (MAX_SITE_CONFIG_BYTES + 1), source="test")


def test_csp_rejects_non_ascii_and_header_controls() -> None:
    for value in (
        "default-src \u2018self\u2019",
        "default-src 'self'\rX-Test: yes",
        "a\x00b",
    ):
        with pytest.raises(SiteConfigError, match="printable ASCII"):
            validate_csp(value)
