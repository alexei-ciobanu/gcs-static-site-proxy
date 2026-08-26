"""Read-only local static-site server backed by one private GCS prefix."""

from __future__ import annotations

import hmac
import html
import ipaddress
import json
import secrets
import socket
import urllib.parse
from collections.abc import AsyncIterator, Awaitable, Callable, MutableMapping
from dataclasses import dataclass, field

from aiohttp import ClientResponse, web

from gcs_static_site_proxy.auth import (
    DEFAULT_REAUTH_COMMAND,
    AccessTokenManager,
    AuthenticationUnavailable,
    LoginController,
)
from gcs_static_site_proxy.catalog import CATALOG_CONFIG_NAME
from gcs_static_site_proxy.gcs import GcsClient, GcsConnectionError
from gcs_static_site_proxy.site_config import SITE_CONFIG_NAME, ContentSecurityPolicy

LOCAL_PREFIX = "/__gcs_proxy"
SESSION_COOKIE = "gcs_static_site_proxy_session"
FORWARDED_HEADERS = {
    "cache-control",
    "content-encoding",
    "content-language",
    "content-length",
    "content-type",
    "etag",
    "last-modified",
}
AUTH_PAGE_CSP = (
    "default-src 'none'; style-src 'unsafe-inline'; "
    "script-src 'unsafe-inline'; connect-src 'self'; frame-ancestors 'none'"
)
AUTH_PAGE_STYLE = """
:root {
  color-scheme: light dark;
  font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont,
    "Segoe UI", sans-serif;
}
* { box-sizing: border-box; }
body {
  min-height: 100vh;
  margin: 0;
  padding: 1.5rem;
  display: grid;
  place-items: center;
  background: #f3f6fa;
  color: #172033;
}
main {
  width: min(100%, 36rem);
  padding: clamp(1.5rem, 5vw, 2.5rem);
  border: 1px solid #d8e0eb;
  border-radius: 1rem;
  background: #fff;
  box-shadow: 0 1.25rem 3rem rgba(30, 50, 80, .12);
}
.eyebrow {
  margin: 0 0 .75rem;
  color: #52637a;
  font-size: .75rem;
  font-weight: 700;
  letter-spacing: .08em;
  text-transform: uppercase;
}
h1 {
  margin: 0;
  font-size: clamp(1.55rem, 5vw, 2rem);
  line-height: 1.2;
  letter-spacing: -.02em;
}
.lead {
  margin: 1rem 0 0;
  color: #52637a;
  line-height: 1.6;
}
pre {
  margin: 1.25rem 0;
  padding: .9rem 1rem;
  overflow-x: auto;
  border: 1px solid #d8e0eb;
  border-radius: .65rem;
  background: #f7f9fc;
  color: #172033;
  font-size: .875rem;
  line-height: 1.5;
  white-space: pre-wrap;
  overflow-wrap: anywhere;
}
.actions {
  display: flex;
  flex-wrap: wrap;
  gap: .75rem;
  margin-top: 1.25rem;
}
button {
  min-height: 2.75rem;
  padding: .65rem 1rem;
  border: 1px solid #1a5fc1;
  border-radius: .6rem;
  background: #1769d2;
  color: #fff;
  font: inherit;
  font-weight: 650;
  cursor: pointer;
}
button:hover:not(:disabled) { background: #0d55ad; }
button:focus-visible { outline: .2rem solid #9bc5ff; outline-offset: .15rem; }
button:disabled { cursor: wait; opacity: .65; }
button.secondary {
  border-color: #b7c2d1;
  background: transparent;
  color: #36465d;
}
button.secondary:hover:not(:disabled) { background: #edf2f8; }
[hidden] { display: none !important; }
.status {
  min-height: 1.5rem;
  margin: 1rem 0 0;
  color: #52637a;
  font-size: .9rem;
  line-height: 1.5;
}
@media (prefers-color-scheme: dark) {
  body { background: #0e1522; color: #eef4ff; }
  main {
    border-color: #34445c;
    background: #182235;
    box-shadow: 0 1.25rem 3rem rgba(0, 0, 0, .35);
  }
  .eyebrow, .lead, .status { color: #afbdd0; }
  pre { border-color: #34445c; background: #101827; color: #eef4ff; }
  button.secondary { border-color: #607089; color: #e3ebf7; }
  button.secondary:hover:not(:disabled) { background: #26344a; }
}
"""
_CONFIGURED_CSP = object()


@dataclass(frozen=True)
class SiteMount:
    slug: str
    title: str
    prefix: str
    csp: ContentSecurityPolicy


@dataclass(frozen=True)
class ProxyConfig:
    bucket: str
    prefix: str
    csp: ContentSecurityPolicy
    bind: str = "127.0.0.1"
    port: int = 8080
    allow_hosts: tuple[str, ...] = ()
    tls_enabled: bool = False
    auth_retry_seconds: int = 5
    reauth_command: str = DEFAULT_REAUTH_COMMAND
    gcs_api_root: str = "https://storage.googleapis.com/storage/v1"
    mounts: tuple[SiteMount, ...] = ()


@dataclass(frozen=True)
class ResolvedRoute:
    prefix: str
    path: str
    csp: ContentSecurityPolicy
    add_trailing_slash: bool = False


def is_loopback_bind(bind: str) -> bool:
    if bind.lower() == "localhost":
        return True
    try:
        return ipaddress.ip_address(bind).is_loopback
    except ValueError:
        try:
            addresses = {
                item[4][0]
                for item in socket.getaddrinfo(bind, None, type=socket.SOCK_STREAM)
            }
        except socket.gaierror:
            return False
        return bool(addresses) and all(
            ipaddress.ip_address(address).is_loopback for address in addresses
        )


def known_local_hostnames() -> set[str]:
    names = {"localhost"}
    for value in (socket.gethostname(), socket.getfqdn()):
        normalized = value.rstrip(".").lower()
        if not normalized:
            continue
        names.add(normalized)
        short = normalized.split(".", 1)[0]
        names.add(short)
        names.add(f"{short}.local")
    return names


def split_host_header(value: str) -> str | None:
    value = value.strip()
    if not value:
        return None
    if value.startswith("["):
        closing = value.find("]")
        if closing < 0:
            return None
        suffix = value[closing + 1 :]
        if not valid_host_port(suffix):
            return None
        return value[1:closing].lower()
    if value.count(":") > 1:
        return None
    hostname, separator, port = value.partition(":")
    if separator and not valid_host_port(f":{port}"):
        return None
    return hostname.rstrip(".").lower()


def valid_host_port(suffix: str) -> bool:
    if not suffix:
        return True
    if not suffix.startswith(":") or not suffix[1:].isdigit():
        return False
    return 1 <= int(suffix[1:]) <= 65535


def normalize_ip(value: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return None
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
        return address.ipv4_mapped
    return address


@dataclass
class NetworkGuard:
    config: ProxyConfig
    network_mode: bool = field(init=False)
    session_token: str | None = field(init=False)
    local_hostnames: set[str] = field(init=False)

    def __post_init__(self) -> None:
        self.network_mode = not is_loopback_bind(self.config.bind)
        self.session_token = secrets.token_urlsafe(32) if self.network_mode else None
        self.local_hostnames = known_local_hostnames() | {
            host.rstrip(".").lower() for host in self.config.allow_hosts
        }

    def valid_host(self, request: web.Request) -> bool:
        hostname = split_host_header(request.headers.get("Host", ""))
        if hostname is None:
            return False
        if hostname in self.local_hostnames:
            return True
        supplied_ip = normalize_ip(hostname)
        if supplied_ip is None:
            return False
        transport = request.transport
        socket_name = transport.get_extra_info("sockname") if transport else None
        if not socket_name:
            return supplied_ip.is_loopback
        destination_ip = normalize_ip(str(socket_name[0]))
        if destination_ip is None:
            return False
        return supplied_ip == destination_ip or (
            supplied_ip.is_loopback and destination_ip.is_loopback
        )

    def authenticated(self, request: web.Request) -> bool:
        if self.session_token is None:
            return True
        supplied = request.cookies.get(SESSION_COOKIE, "")
        return hmac.compare_digest(supplied, self.session_token)

    def valid_unlock_token(self, supplied: str) -> bool:
        return self.session_token is not None and hmac.compare_digest(
            supplied, self.session_token
        )

    @staticmethod
    def peer_is_loopback(request: web.Request) -> bool:
        transport = request.transport
        peer = transport.get_extra_info("peername") if transport else None
        if not peer:
            return False
        address = normalize_ip(str(peer[0]))
        return bool(address and address.is_loopback)


def decode_request_path(raw_path: str) -> str | None:
    encoded = raw_path.partition("?")[0]
    try:
        path = urllib.parse.unquote(encoded, errors="strict")
    except UnicodeDecodeError:
        return None
    if not path.startswith("/") or "\\" in path or "\x00" in path:
        return None
    parts = path.removeprefix("/").split("/")
    if any(part in {".", ".."} for part in parts):
        return None
    if any(not part for part in parts[:-1]):
        return None
    return path


def object_candidates(prefix: str, path: str) -> list[str]:
    if path == "/":
        return [f"{prefix}/index.html"]
    relative = path.removeprefix("/")
    basename = relative.rsplit("/", 1)[-1]
    if basename in {SITE_CONFIG_NAME, CATALOG_CONFIG_NAME} or relative.startswith(
        f"{LOCAL_PREFIX[1:]}/"
    ):
        return []
    if path.endswith("/"):
        return [f"{prefix}/{relative}index.html"]
    exact = f"{prefix}/{relative}"
    if "." in relative.rsplit("/", 1)[-1]:
        return [exact]
    return [exact, f"{exact}.html", f"{exact}/index.html"]


def resolve_route(config: ProxyConfig, path: str) -> ResolvedRoute | None:
    if not path.startswith("/sites/"):
        return ResolvedRoute(prefix=config.prefix, path=path, csp=config.csp)
    relative = path.removeprefix("/sites/")
    slug, separator, remainder = relative.partition("/")
    mount = next(
        (candidate for candidate in config.mounts if candidate.slug == slug), None
    )
    if mount is None:
        return None
    if not separator:
        return ResolvedRoute(
            prefix=mount.prefix,
            path="/",
            csp=mount.csp,
            add_trailing_slash=True,
        )
    return ResolvedRoute(
        prefix=mount.prefix,
        path=f"/{remainder}",
        csp=mount.csp,
    )


class GcsStaticSiteProxy:
    def __init__(self, config: ProxyConfig) -> None:
        self.config = config
        self.tokens = AccessTokenManager(retry_seconds=config.auth_retry_seconds)
        self.login = LoginController(
            config.reauth_command, self.tokens.invalidate, self.tokens.token
        )
        self.guard = NetworkGuard(config)
        self.gcs: GcsClient | None = None
        self._local_action_token = secrets.token_urlsafe(32)

    def application(self) -> web.Application:
        app = web.Application(client_max_size=1024**2, middlewares=[self._gate])
        app.cleanup_ctx.append(self._gcs_client)
        app.on_cleanup.append(self._cleanup)
        app.router.add_get(f"{LOCAL_PREFIX}/health", self.health)
        app.router.add_get(f"{LOCAL_PREFIX}/auth/status", self.authentication_status)
        app.router.add_post(f"{LOCAL_PREFIX}/auth/start", self.start_authentication)
        app.router.add_post(f"{LOCAL_PREFIX}/auth/cancel", self.cancel_authentication)
        app.router.add_get(f"{LOCAL_PREFIX}/unlock/{{token}}", self.unlock)
        app.router.add_route("*", "/{path:.*}", self.serve)
        return app

    @web.middleware
    async def _gate(
        self,
        request: web.Request,
        handler: Callable[[web.Request], Awaitable[web.StreamResponse]],
    ) -> web.StreamResponse:
        if not self.guard.valid_host(request):
            raise web.HTTPBadRequest(text="Invalid Host header\n")
        if request.path.startswith(f"{LOCAL_PREFIX}/unlock/"):
            return await handler(request)
        if not self.guard.authenticated(request):
            return self.network_authentication_page()
        return await handler(request)

    async def _gcs_client(self, _app: web.Application) -> AsyncIterator[None]:
        async with GcsClient(
            self.config.bucket,
            self.tokens,
            api_root=self.config.gcs_api_root,
        ) as client:
            self.gcs = client
            try:
                yield
            finally:
                self.gcs = None

    async def _cleanup(self, _app: web.Application) -> None:
        await self.login.close()

    async def health(self, _request: web.Request) -> web.Response:
        return self._json_response(
            {
                "status": "ok",
                "bucket": self.config.bucket,
                "prefix": self.config.prefix,
                "network_mode": self.guard.network_mode,
            }
        )

    async def unlock(self, request: web.Request) -> web.Response:
        if not self.guard.valid_unlock_token(request.match_info["token"]):
            return self._text_response(403, "Invalid access token\n")
        response = web.Response(status=303, headers={"Location": "/"})
        response.set_cookie(
            SESSION_COOKIE,
            self.guard.session_token or "",
            httponly=True,
            secure=self.config.tls_enabled,
            samesite="Strict",
            path="/",
        )
        response.headers["Cache-Control"] = "no-store"
        self._security_headers(response.headers)
        return response

    async def authentication_status(self, _request: web.Request) -> web.Response:
        status = self.login.status()
        if self.login.running:
            return self._json_response({"authenticated": False, **status})
        try:
            await self.tokens.token(report_failure=False)
        except AuthenticationUnavailable:
            if status["login_state"] not in {"failed", "cancelled"}:
                status["message"] = "Sign-in required. Select Sign in to continue."
            return self._json_response({"authenticated": False, **status})
        return self._json_response(
            {
                "authenticated": True,
                "login_running": False,
                "login_state": "succeeded",
                "message": "Authentication succeeded. Reloading…",
            }
        )

    async def start_authentication(self, request: web.Request) -> web.Response:
        self._require_local_action(request)
        await self.login.start()
        return self._json_response(self.login.status(), status=202)

    async def cancel_authentication(self, request: web.Request) -> web.Response:
        self._require_local_action(request)
        await self.login.cancel()
        return self._json_response(self.login.status())

    async def serve(self, request: web.Request) -> web.StreamResponse:
        if request.method not in {"GET", "HEAD"}:
            raise web.HTTPMethodNotAllowed(request.method, ["GET", "HEAD"])
        path = decode_request_path(request.raw_path)
        if path is None:
            return self._text_response(404, "Not found\n")
        route = resolve_route(self.config, path)
        if route is None:
            return self._text_response(404, "Not found\n")
        if route.add_trailing_slash:
            return self._redirect_response(f"{request.path}/", csp=route.csp.value)
        candidates = object_candidates(route.prefix, route.path)
        if not candidates:
            return self._text_response(404, "Not found\n", csp=route.csp.value)
        if self.gcs is None:
            raise RuntimeError("GCS client has not started")

        try:
            for object_name in candidates:
                upstream = await self.gcs.request(object_name)
                if upstream.status == 404:
                    upstream.release()
                    continue
                if upstream.status in {401, 403}:
                    upstream.release()
                    if upstream.status == 401:
                        return self.authentication_page(request)
                    return self._text_response(
                        403, "GCS denied access\n", csp=route.csp.value
                    )
                if upstream.status != 200:
                    status = upstream.status
                    upstream.release()
                    return self._text_response(
                        502, f"GCS returned HTTP {status}\n", csp=route.csp.value
                    )
                if (
                    object_name.endswith("/index.html")
                    and route.path != "/"
                    and not route.path.endswith("/")
                ):
                    upstream.release()
                    return self._redirect_response(
                        f"{request.path}/", csp=route.csp.value
                    )
                return await self._stream_object(request, upstream, csp=route.csp.value)
            return self._text_response(404, "Not found\n", csp=route.csp.value)
        except AuthenticationUnavailable:
            return self.authentication_page(request)
        except GcsConnectionError as error:
            print(f"GCS request failed: {error}")
            return self._text_response(
                502, "Unable to connect to GCS\n", csp=route.csp.value
            )

    async def _stream_object(
        self,
        request: web.Request,
        upstream: ClientResponse,
        *,
        csp: str | None,
    ) -> web.StreamResponse:
        downstream = web.StreamResponse(status=200)
        for name, value in upstream.headers.items():
            if name.lower() in FORWARDED_HEADERS:
                downstream.headers[name] = value
        downstream.headers.setdefault("Cache-Control", "private,no-store")
        self._security_headers(downstream.headers, csp=csp)
        try:
            await downstream.prepare(request)
            if request.method != "HEAD":
                async for chunk in upstream.content.iter_chunked(64 * 1024):
                    await downstream.write(chunk)
            await downstream.write_eof()
            return downstream
        except ConnectionError:
            return downstream
        finally:
            upstream.release()

    def network_authentication_page(self) -> web.Response:
        return self._html_response(
            401,
            f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Access token required</title><style>{AUTH_PAGE_STYLE}</style></head><body><main>
<p class="eyebrow">gcs-static-site-proxy</p>
<h1>Access token required</h1>
<p class="lead">Open the tokenised URL printed by the proxy operator to unlock
this browser session.</p>
</main></body></html>""",
            csp=AUTH_PAGE_CSP,
        )

    def authentication_page(self, request: web.Request) -> web.Response:
        local_operator = self.guard.peer_is_loopback(request)
        command = html.escape(self.config.reauth_command)
        if not local_operator:
            body = f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Google Cloud authentication required</title>
<style>{AUTH_PAGE_STYLE}</style></head><body><main>
<p class="eyebrow">gcs-static-site-proxy</p>
<h1>Google Cloud sign-in required</h1>
<p class="lead">The proxy operator must refresh Google Cloud authentication.
Contact the person who started this proxy.</p></main></body></html>"""
            return self._html_response(503, body, csp=AUTH_PAGE_CSP)

        action_token = json.dumps(self._local_action_token)
        body = f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Google Cloud authentication required</title>
<style>{AUTH_PAGE_STYLE}</style></head><body><main>
<p class="eyebrow">gcs-static-site-proxy</p>
<h1>Google Cloud sign-in required</h1>
<p class="lead">This proxy cannot access the private site until its Application
Default Credentials are refreshed. Select Sign in, or run:</p>
<pre><code>{command}</code></pre>
<div class="actions">
<button id="signin" type="button">Sign in</button>
<button class="secondary" id="cancel" type="button" hidden>Cancel</button>
</div>
<p class="status" id="status" role="status" aria-live="polite">
Checking authentication…</p>
</main>
<script>
const actionToken={action_token};const statusElement=document.querySelector('#status');
const signIn=document.querySelector('#signin');
const cancel=document.querySelector('#cancel');
function render(data){{if(data.authenticated){{location.reload();return;}}
statusElement.textContent=data.message||'Authentication unavailable.';
signIn.disabled=Boolean(data.login_running);cancel.hidden=!data.login_running;}}
async function call(path,method='GET'){{
const headers=method==='POST'?{{'X-Local-Action-Token':actionToken}}:{{}};
const response=await fetch(path,{{method,cache:'no-store',headers}});
render(await response.json());}}
signIn.onclick=()=>call('{LOCAL_PREFIX}/auth/start','POST');
cancel.onclick=()=>call('{LOCAL_PREFIX}/auth/cancel','POST');
call('{LOCAL_PREFIX}/auth/status');setInterval(()=>call('{LOCAL_PREFIX}/auth/status'),2000);
</script></body></html>"""
        return self._html_response(503, body, csp=AUTH_PAGE_CSP)

    def _require_local_action(self, request: web.Request) -> None:
        if not self.guard.peer_is_loopback(request):
            raise web.HTTPForbidden(text="Local operator action required\n")
        supplied = request.headers.get("X-Local-Action-Token", "")
        if not hmac.compare_digest(supplied, self._local_action_token):
            raise web.HTTPForbidden(text="Invalid local action token\n")

    def _security_headers(
        self,
        headers: MutableMapping[str, str],
        *,
        csp: str | object | None = _CONFIGURED_CSP,
    ) -> None:
        policy = self.config.csp.value if csp is _CONFIGURED_CSP else csp
        if policy:
            assert isinstance(policy, str)
            headers["Content-Security-Policy"] = policy
        headers["Referrer-Policy"] = "no-referrer"
        headers["X-Content-Type-Options"] = "nosniff"
        headers["X-Frame-Options"] = "DENY"

    def _json_response(self, payload: object, *, status: int = 200) -> web.Response:
        response = web.json_response(
            payload, status=status, headers={"Cache-Control": "no-store"}
        )
        self._security_headers(response.headers, csp=AUTH_PAGE_CSP)
        return response

    def _text_response(
        self,
        status: int,
        text: str,
        *,
        csp: str | object | None = _CONFIGURED_CSP,
    ) -> web.Response:
        response = web.Response(
            status=status,
            text=text,
            content_type="text/plain",
            headers={"Cache-Control": "no-store"},
        )
        self._security_headers(response.headers, csp=csp)
        return response

    def _redirect_response(
        self,
        location: str,
        *,
        csp: str | object | None = _CONFIGURED_CSP,
    ) -> web.Response:
        response = web.Response(
            status=308,
            headers={"Location": location, "Cache-Control": "private,no-cache"},
        )
        self._security_headers(response.headers, csp=csp)
        return response

    def _html_response(self, status: int, body: str, *, csp: str) -> web.Response:
        response = web.Response(
            status=status,
            text=body,
            content_type="text/html",
            headers={"Cache-Control": "no-store"},
        )
        self._security_headers(response.headers, csp=csp)
        return response
