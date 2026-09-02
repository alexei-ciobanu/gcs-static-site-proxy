from __future__ import annotations

import argparse
import asyncio
import json
from pathlib import Path
from typing import Any, cast

import pytest

from gcs_static_site_proxy import cli
from gcs_static_site_proxy.cli import (
    allowed_host,
    bucket_name,
    object_prefix,
    parser,
    tcp_port,
)
from gcs_static_site_proxy.gcs import ConfigObject
from gcs_static_site_proxy.site_config import (
    STRICT_STATIC_CSP,
    BrowserCacheMode,
    BrowserCachePolicy,
    ContentSecurityPolicy,
    SiteConfiguration,
)


@pytest.mark.parametrize(
    "value",
    [
        "valid-bucket",
        "bucket.with.dots",
        "private-static-sites-prod-1234",
    ],
)
def test_valid_bucket_names(value: str) -> None:
    assert bucket_name(value) == value


@pytest.mark.parametrize(
    "value", ["-starts-with-dash", "ends-with-dash-", "UPPER", "ab", "bad/name"]
)
def test_invalid_bucket_names(value: str) -> None:
    with pytest.raises(argparse.ArgumentTypeError):
        bucket_name(value)


def test_object_prefix_rejects_traversal_controls_and_oversize() -> None:
    assert object_prefix("/team/site/") == "team/site"
    for value in ("", "../site", "team//site", "team\\site", "team\nsite"):
        with pytest.raises(argparse.ArgumentTypeError):
            object_prefix(value)
    with pytest.raises(argparse.ArgumentTypeError):
        object_prefix("x" * 1025)


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("site.example", "site.example"),
        ("SITE.EXAMPLE.", "site.example"),
        ("192.168.1.20", "192.168.1.20"),
        ("[2001:db8::1]", "2001:db8::1"),
    ],
)
def test_allowed_host(value: str, expected: str) -> None:
    assert allowed_host(value) == expected


@pytest.mark.parametrize("value", ["site:8080", "bad/name", "-bad", "bad..name"])
def test_allowed_host_rejects_ports_and_malformed_names(value: str) -> None:
    with pytest.raises(argparse.ArgumentTypeError):
        allowed_host(value)


def test_csp_cli_modes_are_mutually_exclusive() -> None:
    with pytest.raises(SystemExit):
        parser().parse_args(
            [
                "--bucket",
                "valid-bucket",
                "--prefix",
                "site",
                "--csp-override-file",
                "policy.csp",
                "--no-csp",
            ]
        )


def test_prefix_and_catalog_prefix_are_mutually_exclusive() -> None:
    with pytest.raises(SystemExit):
        parser().parse_args(
            [
                "--bucket",
                "valid-bucket",
                "--prefix",
                "site",
                "--catalog-prefix",
                "catalog",
            ]
        )
    catalog_arguments = parser().parse_args(
        ["--bucket", "valid-bucket", "--catalog-prefix", "catalog"]
    )
    assert catalog_arguments.prefix is None
    assert catalog_arguments.catalog_prefix == "catalog"


def test_tcp_port_is_bounded() -> None:
    assert tcp_port("8080") == 8080
    for value in ("0", "65536", "not-a-number"):
        with pytest.raises((argparse.ArgumentTypeError, ValueError)):
            tcp_port(value)


def test_browser_cache_override_is_bounded_to_supported_modes() -> None:
    parsed = arguments("--browser-cache", "revalidate")
    policy = cli.explicit_browser_cache(parsed)
    assert policy is not None
    assert policy.mode is BrowserCacheMode.REVALIDATE
    assert cli.explicit_browser_cache(arguments()) is None
    with pytest.raises(SystemExit):
        arguments("--browser-cache", "immutable")


def arguments(*extra: str) -> argparse.Namespace:
    return parser().parse_args(["--bucket", "valid-bucket", "--prefix", "site", *extra])


def catalog_arguments(*extra: str) -> argparse.Namespace:
    return parser().parse_args(
        ["--bucket", "valid-bucket", "--catalog-prefix", "catalog", *extra]
    )


def test_no_csp_takes_explicit_precedence() -> None:
    policy = cli.explicit_csp(arguments("--no-csp"))
    assert policy is not None
    assert policy.value is None
    assert policy.source == "disabled by --no-csp"


def test_local_csp_file_takes_precedence(tmp_path: Path) -> None:
    path = tmp_path / "site.csp"
    path.write_text("default-src 'self'; script-src 'self' 'unsafe-eval'\n")
    policy = cli.explicit_csp(arguments("--csp-override-file", str(path)))
    assert policy is not None
    assert policy.value == "default-src 'self'; script-src 'self' 'unsafe-eval'"
    assert policy.source == str(path)


def test_strict_csp_uses_default_for_every_route() -> None:
    policy = cli.explicit_csp(arguments("--strict-csp"))
    assert policy is not None
    assert policy.value == STRICT_STATIC_CSP
    assert policy.source == "built-in strict CSP selected by --strict-csp"


@pytest.mark.parametrize("removed_option", ["--csp-file", "--ignore-site-config"])
def test_removed_csp_options_are_rejected(removed_option: str) -> None:
    with pytest.raises(SystemExit):
        arguments(removed_option)


def test_gcs_site_config_precedes_default(monkeypatch: pytest.MonkeyPatch) -> None:
    expected = SiteConfiguration(
        csp=ContentSecurityPolicy(
            value="default-src 'self'",
            source="gs://bucket/site/config",
            generation="2",
        ),
        browser_cache=BrowserCachePolicy(
            BrowserCacheMode.REVALIDATE,
            source="gs://bucket/site/config",
        ),
    )

    async def fake_gcs_site_configuration(**_kwargs: object) -> SiteConfiguration:
        return expected

    monkeypatch.setattr(cli, "gcs_site_configuration", fake_gcs_site_configuration)
    source = cli.resolve_source(arguments())
    assert source.csp == expected.csp
    assert source.browser_cache == expected.browser_cache


def test_absent_gcs_site_config_uses_default(monkeypatch: pytest.MonkeyPatch) -> None:
    async def fake_gcs_site_configuration(**_kwargs: object) -> None:
        return None

    monkeypatch.setattr(cli, "gcs_site_configuration", fake_gcs_site_configuration)
    source = cli.resolve_source(arguments())
    assert source.csp.value == STRICT_STATIC_CSP
    assert source.browser_cache.mode is BrowserCacheMode.NO_STORE


def test_complete_cli_overrides_skip_site_configuration(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def unexpected_configuration(**_kwargs: object) -> SiteConfiguration:
        raise AssertionError("site configuration should not be read")

    monkeypatch.setattr(cli, "gcs_site_configuration", unexpected_configuration)
    source = cli.resolve_source(arguments("--no-csp", "--browser-cache", "revalidate"))
    assert source.csp.value is None
    assert source.browser_cache.mode is BrowserCacheMode.REVALIDATE


def test_catalog_resolves_cache_policy_for_each_mount(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    objects = {
        "catalog/.gcs-static-site-proxy-sites.json": {
            "version": 1,
            "sites": [{"slug": "demo", "title": "Demo", "prefix": "team/demo"}],
        },
        "catalog/.gcs-static-site-proxy.json": {
            "version": 1,
            "contentSecurityPolicy": "default-src 'self'",
        },
        "team/demo/.gcs-static-site-proxy.json": {
            "version": 1,
            "contentSecurityPolicy": "default-src 'none'",
            "browserCache": "revalidate",
        },
    }

    class FakeGcsClient:
        def __init__(self, *_args: Any, **_kwargs: Any) -> None:
            pass

        async def __aenter__(self) -> FakeGcsClient:
            return self

        async def __aexit__(self, *_exc: Any) -> None:
            pass

        async def read_config_object(
            self, object_name: str, *, maximum_bytes: int
        ) -> ConfigObject | None:
            del maximum_bytes
            payload = objects.get(object_name)
            if payload is None:
                return None
            return ConfigObject(json.dumps(payload).encode(), generation="7")

    monkeypatch.setattr(cli, "GcsClient", FakeGcsClient)
    source = asyncio.run(cli.gcs_catalog_source(catalog_arguments()))
    assert source.browser_cache.mode is BrowserCacheMode.NO_STORE
    assert len(source.mounts) == 1
    assert source.mounts[0].browser_cache.mode is BrowserCacheMode.REVALIDATE
    assert source.mounts[0].csp.value == "default-src 'none'"


def test_complete_catalog_overrides_skip_per_site_configuration(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    catalog_object = "catalog/.gcs-static-site-proxy-sites.json"
    catalog = {
        "version": 1,
        "sites": [{"slug": "demo", "title": "Demo", "prefix": "team/demo"}],
    }

    class CatalogOnlyGcsClient:
        def __init__(self, *_args: Any, **_kwargs: Any) -> None:
            pass

        async def __aenter__(self) -> CatalogOnlyGcsClient:
            return self

        async def __aexit__(self, *_exc: Any) -> None:
            pass

        async def read_config_object(
            self, object_name: str, *, maximum_bytes: int
        ) -> ConfigObject | None:
            del maximum_bytes
            if object_name != catalog_object:
                raise AssertionError("per-site configuration should not be read")
            return ConfigObject(json.dumps(catalog).encode(), generation="8")

    monkeypatch.setattr(cli, "GcsClient", CatalogOnlyGcsClient)
    source = asyncio.run(
        cli.gcs_catalog_source(
            catalog_arguments("--no-csp", "--browser-cache", "revalidate")
        )
    )
    assert source.csp.value is None
    assert source.browser_cache.mode is BrowserCacheMode.REVALIDATE
    assert source.mounts[0].csp.value is None
    assert source.mounts[0].browser_cache.mode is BrowserCacheMode.REVALIDATE


def test_tls_certificate_and_key_must_be_paired() -> None:
    with pytest.raises(ValueError, match="supplied together"):
        cli.tls_context(arguments("--tls-cert", "cert.pem"))


def test_run_binds_server_before_resolving_authenticated_source(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    run_calls: list[object] = []
    resolution_calls: list[object] = []

    def fake_run_app(application: object, **_kwargs: object) -> None:
        run_calls.append(application)

    async def deferred_resolution(_tokens: object) -> cli.ProxyConfig:
        resolution_calls.append(object())
        raise AssertionError("resolution should not run before the first request")

    def resolver_factory(
        _arguments: argparse.Namespace, _config: cli.ProxyConfig
    ) -> Any:
        return deferred_resolution

    monkeypatch.setattr(cli.web, "run_app", fake_run_app)
    monkeypatch.setattr(cli, "deferred_configuration_resolver", resolver_factory)
    cli.run(arguments("--no-browser"))
    assert len(run_calls) == 1
    assert resolution_calls == []


def test_deferred_resolver_uses_supplied_token_manager(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    supplied = object()
    calls: list[tuple[argparse.Namespace, object]] = []
    parsed = arguments()
    config = cli.ProxyConfig(
        bucket=parsed.bucket,
        prefix=parsed.prefix,
        csp=cli.default_csp(),
    )

    async def resolve(
        received_arguments: argparse.Namespace, tokens: object
    ) -> cli.ResolvedSource:
        calls.append((received_arguments, tokens))
        return cli.ResolvedSource(
            prefix="resolved/site",
            csp=cli.default_csp(),
            browser_cache=BrowserCachePolicy(
                BrowserCacheMode.REVALIDATE, source="test"
            ),
        )

    monkeypatch.setattr(cli, "resolve_source_async", resolve)
    resolver = cli.deferred_configuration_resolver(parsed, config)
    assert calls == []

    async def invoke() -> cli.ProxyConfig:
        return await resolver(cast(Any, supplied))

    resolved = asyncio.run(invoke())
    assert calls == [(parsed, supplied)]
    assert resolved.prefix == "resolved/site"
    assert resolved.browser_cache.mode is BrowserCacheMode.REVALIDATE
