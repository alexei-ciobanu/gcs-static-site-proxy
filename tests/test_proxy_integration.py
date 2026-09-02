from __future__ import annotations

import gzip
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import replace
from typing import Any, cast
from urllib.parse import unquote

import pytest
from aiohttp import ClientPayloadError, ClientSession, CookieJar, web
from aiohttp.test_utils import TestServer

from gcs_static_site_proxy.auth import AuthenticationUnavailable
from gcs_static_site_proxy.gcs import GcsClient, GcsConnectionError
from gcs_static_site_proxy.server import (
    GcsStaticSiteProxy,
    ProxyConfig,
    SiteMount,
    SourceResolutionError,
)
from gcs_static_site_proxy.site_config import (
    BrowserCacheMode,
    BrowserCachePolicy,
    ContentSecurityPolicy,
    default_csp,
)


class FakeTokens:
    def __init__(self) -> None:
        self.force_reloads = 0
        self.invalidations = 0
        self.rejections = 0

    async def token(self, *, force_reload: bool = False, **_kwargs: Any) -> str:
        self.force_reloads += int(force_reload)
        return "test-access-token"

    async def invalidate(self) -> None:
        self.invalidations += 1

    async def reject(self, _message: str) -> None:
        self.rejections += 1


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
        if headers.get("X-Test-Status") == "401":
            return web.Response(status=401)
        etag = headers.get("ETag", '"test-etag"')
        last_modified = headers.get("Last-Modified", "Tue, 25 Aug 2026 00:00:00 GMT")
        response_headers = {
            "Content-Disposition": "attachment",
            "x-goog-generation": "42",
            "ETag": etag,
            "Last-Modified": last_modified,
            **{
                name: value
                for name, value in headers.items()
                if not name.startswith("X-Test-")
            },
        }
        if request.headers.get("If-None-Match") == etag or (
            "If-None-Match" not in request.headers
            and request.headers.get("If-Modified-Since") == last_modified
        ):
            not_modified_headers = response_headers.copy()
            if headers.get("X-Test-Omit-304-Content-Type") == "true":
                not_modified_headers.pop("Content-Type", None)
            return web.Response(status=304, headers=not_modified_headers)
        return web.Response(
            body=body,
            headers=response_headers,
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
    objects: dict[str, tuple[bytes, dict[str, str]]],
    *,
    network_mode: bool = False,
    browser_cache: BrowserCacheMode = BrowserCacheMode.NO_STORE,
) -> AsyncIterator[tuple[ClientSession, str, GcsStaticSiteProxy]]:
    async with mock_gcs(objects) as api_root:
        config = ProxyConfig(
            bucket="example-bucket",
            prefix="team/site",
            csp=default_csp(),
            browser_cache=BrowserCachePolicy(browser_cache, source="test"),
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
        "team/site/mislabelled.txt": (
            b"<h1>Still HTML</h1>",
            {
                "Content-Type": "text/html; charset=utf-8",
                "X-Test-Omit-304-Content-Type": "true",
            },
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
async def test_proxy_starts_unresolved_and_recovers_without_restart() -> None:
    ready = False
    attempts = 0
    async with mock_gcs(site_objects()) as api_root:
        config = ProxyConfig(
            bucket="example-bucket",
            prefix="team/site",
            csp=default_csp(),
            gcs_api_root=api_root,
        )

        async def resolve(_tokens: object) -> ProxyConfig:
            nonlocal attempts
            attempts += 1
            if not ready:
                raise AuthenticationUnavailable("test credentials unavailable")
            return replace(
                config,
                browser_cache=BrowserCachePolicy(
                    BrowserCacheMode.REVALIDATE,
                    source="resolved test configuration",
                ),
            )

        proxy = GcsStaticSiteProxy(config, configuration_resolver=resolve)
        proxy.tokens = cast(Any, FakeTokens())
        server = TestServer(proxy.application())
        await server.start_server()
        async with ClientSession() as session:
            base = str(server.make_url("/"))
            unavailable = await session.get(base)
            assert unavailable.status == 503
            assert "Google Cloud sign-in required" in await unavailable.text()
            health = await session.get(f"{base}__gcs_proxy/health")
            assert (await health.json())["source_ready"] is False

            ready = True
            status = await session.get(f"{base}__gcs_proxy/auth/status")
            assert (await status.json())["authenticated"] is True
            recovered = await session.get(base)
            assert recovered.status == 200
            assert "Private site" in await recovered.text()
            health = await session.get(f"{base}__gcs_proxy/health")
            assert (await health.json())["source_ready"] is True
        await server.close()
    assert attempts == 2


@pytest.mark.asyncio
async def test_deferred_catalog_configuration_activates_exact_mounts() -> None:
    objects = {
        "catalog/index.html": (
            b'<a href="/sites/demo/">Demo</a>',
            {"Content-Type": "text/html; charset=utf-8"},
        ),
        "projects/demo/publication/site/index.html": (
            b"<h1>Mounted demo</h1>",
            {"Content-Type": "text/html; charset=utf-8"},
        ),
    }
    async with mock_gcs(objects) as api_root:
        config = ProxyConfig(
            bucket="example-bucket",
            prefix="catalog",
            csp=default_csp(),
            gcs_api_root=api_root,
        )

        async def resolve(_tokens: object) -> ProxyConfig:
            return replace(
                config,
                mounts=(
                    SiteMount(
                        slug="demo",
                        title="Demo",
                        prefix="projects/demo/publication/site",
                        csp=default_csp(),
                    ),
                ),
            )

        proxy = GcsStaticSiteProxy(config, configuration_resolver=resolve)
        proxy.tokens = cast(Any, FakeTokens())
        server = TestServer(proxy.application())
        await server.start_server()
        async with ClientSession() as session:
            base = str(server.make_url("/"))
            landing = await session.get(base)
            assert landing.status == 200
            mounted = await session.get(f"{base}sites/demo/")
            assert mounted.status == 200
            assert await mounted.text() == "<h1>Mounted demo</h1>"
            unknown = await session.get(f"{base}sites/unknown/")
            assert unknown.status == 404
        await server.close()


@pytest.mark.asyncio
async def test_source_configuration_failure_is_not_reported_as_authentication() -> None:
    config = ProxyConfig(
        bucket="example-bucket",
        prefix="catalog",
        csp=default_csp(),
    )

    async def resolve(_tokens: object) -> ProxyConfig:
        raise SourceResolutionError("catalog is invalid")

    proxy = GcsStaticSiteProxy(config, configuration_resolver=resolve)
    server = TestServer(proxy.application())
    await server.start_server()
    async with ClientSession() as session:
        response = await session.get(str(server.make_url("/")))
        assert response.status == 502
        body = await response.text()
        assert body == "Unable to load GCS source configuration\n"
        assert "sign-in" not in body.lower()
    await server.close()


@pytest.mark.parametrize("prefix", ["team/site", "catalog"])
@pytest.mark.asyncio
async def test_config_unauthorized_serves_authentication_page(prefix: str) -> None:
    config_name = f"{prefix}/configuration.json"
    objects = {
        config_name: (
            b"{}",
            {"Content-Type": "application/json", "X-Test-Status": "401"},
        )
    }
    async with mock_gcs(objects) as api_root:
        config = ProxyConfig(
            bucket="example-bucket",
            prefix=prefix,
            csp=default_csp(),
            gcs_api_root=api_root,
        )

        async def resolve(tokens: object) -> ProxyConfig:
            async with GcsClient(
                "example-bucket", cast(Any, tokens), api_root=api_root
            ) as client:
                await client.read_config_object(config_name, maximum_bytes=100)
            raise AssertionError("persistent 401 should prevent source resolution")

        proxy = GcsStaticSiteProxy(config, configuration_resolver=resolve)
        proxy.tokens = cast(Any, FakeTokens())
        server = TestServer(proxy.application())
        await server.start_server()
        async with ClientSession() as session:
            response = await session.get(str(server.make_url("/")))
            assert response.status == 503
            assert "Google Cloud sign-in required" in await response.text()
            status = await session.get(str(server.make_url("/__gcs_proxy/auth/status")))
            assert (await status.json())["authenticated"] is False
        await server.close()


@pytest.mark.asyncio
async def test_unresolved_network_proxy_retains_operator_access_controls() -> None:
    config = ProxyConfig(
        bucket="example-bucket",
        prefix="team/site",
        csp=default_csp(),
        bind="0.0.0.0",
    )

    async def resolve(_tokens: object) -> ProxyConfig:
        raise AuthenticationUnavailable("test credentials unavailable")

    proxy = GcsStaticSiteProxy(config, configuration_resolver=resolve)
    server = TestServer(proxy.application())
    await server.start_server()
    async with ClientSession(cookie_jar=CookieJar(unsafe=True)) as session:
        base = str(server.make_url("/"))
        locked = await session.get(base)
        assert locked.status == 401
        assert "Access token required" in await locked.text()

        token = proxy.guard.session_token
        assert token
        unlocked = await session.get(
            f"{base}__gcs_proxy/unlock/{token}", allow_redirects=False
        )
        assert unlocked.status == 303
        unavailable = await session.get(base)
        assert unavailable.status == 503
        assert "Google Cloud sign-in required" in await unavailable.text()
    await server.close()


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
        assert response.headers["Cache-Control"] == "private,no-store"

        extensionless = await session.get(f"{base}about")
        assert extensionless.status == 200
        assert await extensionless.text() == "<h1>About</h1>"

        directory = await session.get(f"{base}docs", allow_redirects=False)
        assert directory.status == 308
        assert directory.headers["Location"] == "/docs/"
        assert directory.headers["Cache-Control"] == "no-store"
        directory_index = await session.get(f"{base}docs/")
        assert directory_index.status == 200
        assert "assets/docs.js" in await directory_index.text()

        bundle = await session.get(f"{base}data/review.json.gz")
        assert bundle.status == 200
        assert bundle.headers["Content-Encoding"] == "gzip"
        raw = await bundle.read()
        assert raw.startswith(b"\x1f\x8b")
        assert gzip.decompress(raw) == b'{"rows":10000}'
        assert bundle.headers["Cache-Control"] == "private,no-store"

        head = await session.head(base)
        assert head.status == 200
        assert await head.read() == b""


@pytest.mark.asyncio
async def test_opt_in_assets_revalidate_while_html_remains_no_store() -> None:
    async with running_proxy(
        site_objects(), browser_cache=BrowserCacheMode.REVALIDATE
    ) as (session, base, _proxy):
        html = await session.get(base)
        assert html.status == 200
        assert html.headers["Cache-Control"] == "private,no-store"

        first = await session.get(f"{base}data/review.json.gz")
        assert first.status == 200
        assert first.headers["Cache-Control"] == "private,no-cache"
        etag = first.headers["ETag"]
        await first.read()

        unchanged = await session.get(
            f"{base}data/review.json.gz",
            headers={"If-None-Match": etag},
        )
        assert unchanged.status == 304
        assert unchanged.headers["Cache-Control"] == "private,no-cache"
        assert unchanged.headers["ETag"] == etag
        assert await unchanged.read() == b""

        unchanged_since = await session.get(
            f"{base}data/review.json.gz",
            headers={"If-Modified-Since": first.headers["Last-Modified"]},
        )
        assert unchanged_since.status == 304
        assert await unchanged_since.read() == b""

        forced_html_validator = await session.get(
            base,
            headers={"If-None-Match": html.headers["ETag"]},
        )
        assert forced_html_validator.status == 200
        assert forced_html_validator.headers["Cache-Control"] == "private,no-store"

        extensionless_html = await session.get(
            f"{base}about",
            headers={"If-None-Match": '"test-etag"'},
        )
        assert extensionless_html.status == 200
        assert extensionless_html.headers["Cache-Control"] == "private,no-store"

        content_typed_html = await session.get(
            f"{base}mislabelled.txt",
            headers={"If-None-Match": '"test-etag"'},
        )
        assert content_typed_html.status == 200
        assert content_typed_html.headers["Cache-Control"] == "private,no-store"


@pytest.mark.asyncio
async def test_revalidation_does_not_hide_an_authentication_failure() -> None:
    objects = site_objects()
    objects["team/site/assets/private.js"] = (
        b"console.log('private')",
        {"Content-Type": "text/javascript", "X-Test-Status": "401"},
    )
    async with running_proxy(objects, browser_cache=BrowserCacheMode.REVALIDATE) as (
        session,
        base,
        _proxy,
    ):
        response = await session.get(
            f"{base}assets/private.js",
            headers={"If-None-Match": '"previous"'},
        )
        assert response.status == 503
        assert response.headers["Cache-Control"] == "no-store"
        assert "Google Cloud sign-in required" in await response.text()


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
        "projects/demo/publication/site/assets/app.js": (
            b"console.log('mounted')",
            {"Content-Type": "text/javascript"},
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
                    browser_cache=BrowserCachePolicy(
                        BrowserCacheMode.REVALIDATE,
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
            assert redirect.headers["Cache-Control"] == "no-store"

            mounted = await session.get(f"{base}sites/demo/")
            assert mounted.status == 200
            assert await mounted.text() == "<h1>Mounted demo</h1>"
            assert mounted.headers["Content-Security-Policy"] == mounted_policy
            assert mounted.headers["Cache-Control"] == "private,no-store"

            mounted_asset = await session.get(f"{base}sites/demo/assets/app.js")
            assert mounted_asset.status == 200
            assert mounted_asset.headers["Cache-Control"] == "private,no-cache"

            assert landing.headers["Cache-Control"] == "private,no-store"

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


@pytest.mark.asyncio
async def test_persistent_config_unauthorized_is_an_authentication_failure() -> None:
    requests = 0

    async def media(_request: web.Request) -> web.Response:
        nonlocal requests
        requests += 1
        return web.Response(status=401)

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
            with pytest.raises(AuthenticationUnavailable, match="rejected"):
                await client.read_config_object("site/config.json", maximum_bytes=10)
        assert requests == 2
        assert tokens.invalidations == 1
        assert tokens.rejections == 1
        assert tokens.force_reloads == 1
    finally:
        await server.close()


@pytest.mark.asyncio
async def test_config_payload_failure_is_a_gcs_connection_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class BrokenContent:
        async def read(self, _maximum_bytes: int) -> bytes:
            raise ClientPayloadError("truncated response")

    class BrokenResponse:
        status = 200
        content = BrokenContent()

        def __init__(self) -> None:
            self.headers: dict[str, str] = {}

        def release(self) -> None:
            pass

    client = GcsClient("example-bucket", cast(Any, FakeTokens()))

    async def request(_object_name: str) -> BrokenResponse:
        return BrokenResponse()

    monkeypatch.setattr(client, "request", request)
    with pytest.raises(GcsConnectionError, match="failed reading"):
        await client.read_config_object("site/config.json", maximum_bytes=10)
