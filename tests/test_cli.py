from __future__ import annotations

import argparse
from pathlib import Path

import pytest

from gcs_static_site_proxy import cli
from gcs_static_site_proxy.cli import (
    allowed_host,
    bucket_name,
    object_prefix,
    parser,
    tcp_port,
)
from gcs_static_site_proxy.site_config import STRICT_STATIC_CSP, ContentSecurityPolicy


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


def arguments(*extra: str) -> argparse.Namespace:
    return parser().parse_args(["--bucket", "valid-bucket", "--prefix", "site", *extra])


def test_no_csp_takes_explicit_precedence() -> None:
    policy = cli.resolve_csp(arguments("--no-csp"))
    assert policy.value is None
    assert policy.source == "disabled by --no-csp"


def test_local_csp_file_takes_precedence(tmp_path: Path) -> None:
    path = tmp_path / "site.csp"
    path.write_text("default-src 'self'; script-src 'self' 'unsafe-eval'\n")
    policy = cli.resolve_csp(arguments("--csp-override-file", str(path)))
    assert policy.value == "default-src 'self'; script-src 'self' 'unsafe-eval'"
    assert policy.source == str(path)


def test_strict_csp_uses_default_for_every_route() -> None:
    policy = cli.resolve_csp(arguments("--strict-csp"))
    assert policy.value == STRICT_STATIC_CSP
    assert policy.source == "built-in strict CSP selected by --strict-csp"


@pytest.mark.parametrize("removed_option", ["--csp-file", "--ignore-site-config"])
def test_removed_csp_options_are_rejected(removed_option: str) -> None:
    with pytest.raises(SystemExit):
        arguments(removed_option)


def test_gcs_site_config_precedes_default(monkeypatch: pytest.MonkeyPatch) -> None:
    expected = ContentSecurityPolicy(
        value="default-src 'self'", source="gs://bucket/site/config", generation="2"
    )

    async def fake_gcs_site_csp(**_kwargs: object) -> ContentSecurityPolicy:
        return expected

    monkeypatch.setattr(cli, "gcs_site_csp", fake_gcs_site_csp)
    assert cli.resolve_csp(arguments()) == expected


def test_absent_gcs_site_config_uses_default(monkeypatch: pytest.MonkeyPatch) -> None:
    async def fake_gcs_site_csp(**_kwargs: object) -> None:
        return None

    monkeypatch.setattr(cli, "gcs_site_csp", fake_gcs_site_csp)
    assert cli.resolve_csp(arguments()).value == STRICT_STATIC_CSP


def test_tls_certificate_and_key_must_be_paired() -> None:
    with pytest.raises(ValueError, match="supplied together"):
        cli.tls_context(arguments("--tls-cert", "cert.pem"))
