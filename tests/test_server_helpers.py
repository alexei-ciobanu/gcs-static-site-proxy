from __future__ import annotations

from dataclasses import dataclass
from typing import Any, cast

import pytest
from aiohttp import web

from gcs_static_site_proxy.server import (
    GcsStaticSiteProxy,
    NetworkGuard,
    ProxyConfig,
    SiteMount,
    decode_request_path,
    is_loopback_bind,
    object_candidates,
    resolve_route,
    split_host_header,
)
from gcs_static_site_proxy.site_config import ContentSecurityPolicy, default_csp


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("/", "/"),
        ("/assets/app.js?v=1", "/assets/app.js"),
        ("/space%20name.html", "/space name.html"),
        ("/%2e%2e/secret", None),
        ("/safe/%2E/secret", None),
        ("/safe%5Csecret", None),
        ("/safe%00secret", None),
        ("//double", None),
    ],
)
def test_decode_request_path(raw: str, expected: str | None) -> None:
    assert decode_request_path(raw) == expected


def test_object_candidates_are_confined_and_support_static_routes() -> None:
    prefix = "team/site"
    assert object_candidates(prefix, "/") == ["team/site/index.html"]
    assert object_candidates(prefix, "/assets/app.js") == ["team/site/assets/app.js"]
    assert object_candidates(prefix, "/about") == [
        "team/site/about",
        "team/site/about.html",
        "team/site/about/index.html",
    ]
    assert object_candidates(prefix, "/docs/") == ["team/site/docs/index.html"]
    assert object_candidates(prefix, "/.gcs-static-site-proxy.json") == []
    assert object_candidates(prefix, "/.gcs-static-site-proxy-sites.json") == []
    assert object_candidates(prefix, "/nested/.gcs-static-site-proxy.json") == []
    assert object_candidates(prefix, "/__gcs_proxy/health") == []


def test_catalog_routes_only_explicit_mounts() -> None:
    mounted_csp = ContentSecurityPolicy(value="default-src 'none'", source="mounted")
    config = ProxyConfig(
        bucket="example-bucket",
        prefix="catalog",
        csp=default_csp(),
        mounts=(
            SiteMount(
                slug="example",
                title="Example",
                prefix="projects/example/publication/site",
                csp=mounted_csp,
            ),
        ),
    )
    root = resolve_route(config, "/assets/catalog.css")
    assert root is not None
    assert root.prefix == "catalog"
    assert root.path == "/assets/catalog.css"
    assert not root.add_trailing_slash

    mounted = resolve_route(config, "/sites/example/assets/app.js")
    assert mounted is not None
    assert mounted.prefix == "projects/example/publication/site"
    assert mounted.path == "/assets/app.js"
    assert mounted.csp == mounted_csp

    redirect = resolve_route(config, "/sites/example")
    assert redirect is not None
    assert redirect.add_trailing_slash
    assert resolve_route(config, "/sites/not-allowlisted/") is None


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("localhost:8080", "localhost"),
        ("EXAMPLE.LOCAL.", "example.local"),
        ("192.168.1.20:8080", "192.168.1.20"),
        ("[::1]:8080", "::1"),
        ("::1", None),
        ("localhost:not-a-port", None),
        ("localhost:70000", None),
        ("[::1]:not-a-port", None),
        ("[broken", None),
        ("", None),
    ],
)
def test_split_host_header(value: str, expected: str | None) -> None:
    assert split_host_header(value) == expected


def test_loopback_bind_detection() -> None:
    assert is_loopback_bind("127.0.0.1")
    assert is_loopback_bind("::1")
    assert is_loopback_bind("localhost")
    assert not is_loopback_bind("0.0.0.0")
    assert not is_loopback_bind("::")


class FakeTransport:
    def __init__(self, *, sockname: tuple[str, int], peername: tuple[str, int]) -> None:
        self.values = {"sockname": sockname, "peername": peername}

    def get_extra_info(self, name: str) -> Any:
        return self.values.get(name)


@dataclass
class FakeRequest:
    host: str
    sockname: tuple[str, int]
    peername: tuple[str, int] = ("192.168.1.50", 51000)
    cookies: dict[str, str] | None = None

    @property
    def headers(self) -> dict[str, str]:
        return {"Host": self.host}

    @property
    def transport(self) -> FakeTransport:
        return FakeTransport(sockname=self.sockname, peername=self.peername)


def network_guard() -> NetworkGuard:
    return NetworkGuard(
        ProxyConfig(
            bucket="example-bucket",
            prefix="site",
            csp=default_csp(),
            bind="0.0.0.0",
            allow_hosts=("site.example",),
        )
    )


def test_network_guard_accepts_destination_ip_and_explicit_alias() -> None:
    guard = network_guard()
    matching = FakeRequest("192.168.1.20:8080", ("192.168.1.20", 8080))
    wrong = FakeRequest("192.168.1.21:8080", ("192.168.1.20", 8080))
    alias = FakeRequest("site.example:8080", ("192.168.1.20", 8080))
    assert guard.valid_host(cast(web.Request, matching))
    assert not guard.valid_host(cast(web.Request, wrong))
    assert guard.valid_host(cast(web.Request, alias))


def test_network_guard_requires_its_process_token() -> None:
    guard = network_guard()
    assert guard.network_mode
    assert guard.session_token
    missing = FakeRequest("192.168.1.20", ("192.168.1.20", 8080), cookies={})
    accepted = FakeRequest(
        "192.168.1.20",
        ("192.168.1.20", 8080),
        cookies={"gcs_static_site_proxy_session": guard.session_token},
    )
    assert not guard.authenticated(cast(web.Request, missing))
    assert guard.authenticated(cast(web.Request, accepted))
    assert guard.valid_unlock_token(guard.session_token)
    assert not guard.valid_unlock_token("wrong")


def test_only_loopback_peers_can_launch_local_operator_actions() -> None:
    local = FakeRequest(
        "localhost:8080",
        ("127.0.0.1", 8080),
        peername=("127.0.0.1", 51000),
    )
    remote = FakeRequest(
        "192.168.1.20:8080",
        ("192.168.1.20", 8080),
        peername=("192.168.1.50", 51000),
    )
    assert NetworkGuard.peer_is_loopback(cast(web.Request, local))
    assert not NetworkGuard.peer_is_loopback(cast(web.Request, remote))


def test_remote_authentication_page_does_not_disclose_reauth_command() -> None:
    config = ProxyConfig(
        bucket="example-bucket",
        prefix="site",
        csp=default_csp(),
        bind="0.0.0.0",
        reauth_command="gcloud auth login --secret-value",
    )
    proxy = GcsStaticSiteProxy(config)
    remote = FakeRequest(
        "192.168.1.20:8080",
        ("192.168.1.20", 8080),
        peername=("192.168.1.50", 51000),
    )
    response = proxy.authentication_page(cast(web.Request, remote))
    assert response.status == 503
    assert response.text is not None
    assert "Contact the person" in response.text
    assert "secret-value" not in response.text
    assert "<style>" in response.text
    assert 'class="eyebrow"' in response.text


def test_authentication_pages_have_self_contained_styles() -> None:
    config = ProxyConfig(
        bucket="example-bucket",
        prefix="site",
        csp=default_csp(),
    )
    proxy = GcsStaticSiteProxy(config)
    local = FakeRequest(
        "localhost:8080",
        ("127.0.0.1", 8080),
        peername=("127.0.0.1", 51000),
    )

    for response in (
        proxy.network_authentication_page(),
        proxy.authentication_page(cast(web.Request, local)),
    ):
        assert response.text is not None
        assert "<style>" in response.text
        assert "prefers-color-scheme: dark" in response.text
        assert 'class="eyebrow"' in response.text
        assert "https://" not in response.text
        assert (
            "style-src 'unsafe-inline'" in response.headers["Content-Security-Policy"]
        )
