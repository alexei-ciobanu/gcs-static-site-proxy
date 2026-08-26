from __future__ import annotations

import gzip
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any, cast
from urllib.parse import unquote

import pytest
from aiohttp import ClientSession, CookieJar, web
from aiohttp.test_utils import TestServer

from gcs_static_site_proxy.gcs import GcsClient
from gcs_static_site_proxy.server import GcsStaticSiteProxy, ProxyConfig, SiteMount
from gcs_static_site_proxy.site_config import ContentSecurityPolicy, default_csp


class FakeTokens:
    def __init__(self) -> None:
        self.force_reloads = 0
        self.invalidations = 0

    async def token(self, *, force_reload: bool = False, **_kwargs: Any) -> str:
        self.force_reloads += int(force_reload)
        return "test-access-token"

    async def invalidate(self) -> None:
        self.invalidations += 1


@asynccontextmanager
async def mock_gcs(
    objects: dict[str, tuple[bytes, dict[str, str]]],
) -> AsyncIterator[str]:
    async def media(request: web.Request) -> web.Response:
        assert request.headers["Authorization"] == "Bearer test-access-token"
        assert request.query["alt"] == "media"
        name = unquote(request.match_info["name"])
        if name not in objects:
            return web.Response(status=404)
        body, headers = objects[name]
        return web.Response(
            body=body,
            headers={
                "Content-Disposition": "attachment",
                "x-goog-generation": "42",
                **headers,
            },
        )

    app = web.Application()
    app.router.add_get("/storage/v1/b/{bucket}/o/{name:.*}", media)
    server = TestServer(app)
    await server.start_server()
    try:
        yield str(server.make_url("/storage/v1"))
    finally:
        await server.close()


@asynccontextmanager
async def running_proxy(
    objects: dict[str, tuple[bytes, dict[str, str]]], *, network_mode: bool = False
) -> AsyncIterator[tuple[ClientSession, str, GcsStaticSiteProxy]]:
    async with mock_gcs(objects) as api_root:
        config = ProxyConfig(
            bucket="example-bucket",
            prefix="team/site",
            csp=default_csp(),
            bind="0.0.0.0" if network_mode else "127.0.0.1",
            gcs_api_root=api_root,
        )
        proxy = GcsStaticSiteProxy(config)
        proxy.tokens = cast(Any, FakeTokens())
        server = TestServer(proxy.application())
        await server.start_server()
        session = ClientSession(
            auto_decompress=False,
            cookie_jar=CookieJar(unsafe=True),
        )
        try:
            yield session, str(server.make_url("/")), proxy
        finally:
            await session.close()
            await server.close()


def site_objects() -> dict[str, tuple[bytes, dict[str, str]]]:
    compressed = gzip.compress(b'{"rows":10000}', mtime=0)
    return {
        "team/site/index.html": (
            b"<!doctype html><title>Private site</title>",
            {
                "Content-Type": "text/html; charset=utf-8",
                "Cache-Control": "private,no-cache",
            },
        ),
        "team/site/about.html": (
            b"<h1>About</h1>",
            {"Content-Type": "text/html; charset=utf-8"},
        ),
        "team/site/docs/index.html": (
            b'<script src="assets/docs.js"></script>',
            {"Content-Type": "text/html; charset=utf-8"},
        ),
        "team/site/data/review.json.gz": (
            compressed,
            {
                "Content-Type": "application/json",
                "Content-Encoding": "gzip",
                "Cache-Control": "private,no-store",
            },
        ),
    }


@pytest.mark.asyncio
async def test_proxy_serves_exact_prefix_with_security_and_gzip() -> None:
    async with running_proxy(site_objects()) as (session, base, _proxy):
        response = await session.get(base)
        assert response.status == 200
        assert await response.text() == "<!doctype html><title>Private site</title>"
        assert response.headers["Content-Type"] == "text/html; charset=utf-8"
        assert "Content-Disposition" not in response.headers
        assert response.headers["X-Content-Type-Options"] == "nosniff"
        assert response.headers["Referrer-Policy"] == "no-referrer"
        assert response.headers["X-Frame-Options"] == "DENY"
        assert response.headers["Content-Security-Policy"] == default_csp().value

        extensionless = await session.get(f"{base}about")
        assert extensionless.status == 200
        assert await extensionless.text() == "<h1>About</h1>"

        directory = await session.get(f"{base}docs", allow_redirects=False)
        assert directory.status == 308
        assert directory.headers["Location"] == "/docs/"
        directory_index = await session.get(f"{base}docs/")
        assert directory_index.status == 200
        assert "assets/docs.js" in await directory_index.text()

        bundle = await session.get(f"{base}data/review.json.gz")
        assert bundle.status == 200
        assert bundle.headers["Content-Encoding"] == "gzip"
        raw = await bundle.read()
        assert raw.startswith(b"\x1f\x8b")
        assert gzip.decompress(raw) == b'{"rows":10000}'

        head = await session.head(base)
        assert head.status == 200
        assert await head.read() == b""


@pytest.mark.asyncio
async def test_proxy_rejects_writes_bad_hosts_and_reserved_paths() -> None:
    async with running_proxy(site_objects()) as (session, base, _proxy):
        post = await session.post(base)
        assert post.status == 405

        bad_host = await session.get(base, headers={"Host": "attacker.example"})
        assert bad_host.status == 400

        reserved = await session.get(f"{base}.gcs-static-site-proxy.json")
        assert reserved.status == 404

        traversal = await session.get(f"{base}%2e%2e/secret")
        assert traversal.status in {404, 400}


@pytest.mark.asyncio
async def test_local_authentication_actions_require_csrf_token() -> None:
    async with running_proxy(site_objects()) as (session, base, _proxy):
        missing = await session.post(f"{base}__gcs_proxy/auth/start")
        assert missing.status == 403
        invalid = await session.post(
            f"{base}__gcs_proxy/auth/start",
            headers={"X-Local-Action-Token": "wrong"},
        )
        assert invalid.status == 403


@pytest.mark.asyncio
async def test_network_mode_requires_token_then_sets_session_cookie() -> None:
    async with running_proxy(site_objects(), network_mode=True) as (
        session,
        base,
        proxy,
    ):
        denied = await session.get(base)
        assert denied.status == 401
        assert "tokenised URL" in await denied.text()

        wrong = await session.get(f"{base}__gcs_proxy/unlock/wrong")
        assert wrong.status == 403

        token = proxy.guard.session_token
        assert token
        unlock = await session.get(
            f"{base}__gcs_proxy/unlock/{token}", allow_redirects=False
        )
        assert unlock.status == 303
        assert "HttpOnly" in unlock.headers["Set-Cookie"]
        assert "SameSite=Strict" in unlock.headers["Set-Cookie"]

        accepted = await session.get(base)
        assert accepted.status == 200
        assert "Private site" in await accepted.text()


@pytest.mark.asyncio
async def test_catalog_mounts_exact_prefixes_with_per_site_csp() -> None:
    objects = {
        "catalog/index.html": (
            b'<a href="/sites/demo/">Demo</a>',
            {"Content-Type": "text/html; charset=utf-8"},
        ),
        "projects/demo/publication/site/index.html": (
            b"<h1>Mounted demo</h1>",
            {"Content-Type": "text/html; charset=utf-8"},
        ),
        "projects/demo/protected/secret.txt": (
            b"must not be reachable",
            {"Content-Type": "text/plain"},
        ),
    }
    async with mock_gcs(objects) as api_root:
        mounted_policy = "default-src 'self'; script-src 'self' 'unsafe-eval'"
        config = ProxyConfig(
            bucket="example-bucket",
            prefix="catalog",
            csp=default_csp(),
            gcs_api_root=api_root,
            mounts=(
                SiteMount(
                    slug="demo",
                    title="Demo",
                    prefix="projects/demo/publication/site",
                    csp=ContentSecurityPolicy(
                        value=mounted_policy,
                        source="test mounted policy",
                    ),
                ),
            ),
        )
        proxy = GcsStaticSiteProxy(config)
        proxy.tokens = cast(Any, FakeTokens())
        server = TestServer(proxy.application())
        await server.start_server()
        session = ClientSession()
        try:
            base = str(server.make_url("/"))
            landing = await session.get(base)
            assert landing.status == 200
            assert landing.headers["Content-Security-Policy"] == default_csp().value

            redirect = await session.get(f"{base}sites/demo", allow_redirects=False)
            assert redirect.status == 308
            assert redirect.headers["Location"] == "/sites/demo/"
            assert redirect.headers["Content-Security-Policy"] == mounted_policy

            mounted = await session.get(f"{base}sites/demo/")
            assert mounted.status == 200
            assert await mounted.text() == "<h1>Mounted demo</h1>"
            assert mounted.headers["Content-Security-Policy"] == mounted_policy

            unknown = await session.get(f"{base}sites/unknown/")
            assert unknown.status == 404
            traversal = await session.get(
                f"{base}sites/demo/../../protected/secret.txt"
            )
            assert traversal.status == 404
        finally:
            await session.close()
            await server.close()


@pytest.mark.asyncio
async def test_gcs_client_refreshes_once_after_unauthorized_response() -> None:
    requests = 0

    async def media(_request: web.Request) -> web.Response:
        nonlocal requests
        requests += 1
        if requests == 1:
            return web.Response(status=401)
        return web.Response(body=b"ok", headers={"x-goog-generation": "9"})

    app = web.Application()
    app.router.add_get("/storage/v1/b/{bucket}/o/{name:.*}", media)
    server = TestServer(app)
    await server.start_server()
    tokens = FakeTokens()
    try:
        async with GcsClient(
            "example-bucket",
            cast(Any, tokens),
            api_root=str(server.make_url("/storage/v1")),
        ) as client:
            result = await client.read_config_object(
                "site/config.json", maximum_bytes=10
            )
        assert result is not None
        assert result.body == b"ok"
        assert result.generation == "9"
        assert requests == 2
        assert tokens.invalidations == 1
        assert tokens.force_reloads == 1
    finally:
        await server.close()
