"""Command-line entry point for gcs-static-site-proxy."""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import ipaddress
import os
import re
import socket
import ssl
import sys
import webbrowser
from collections.abc import AsyncIterator, Sequence
from dataclasses import dataclass
from pathlib import Path

import truststore
from aiohttp import web

from gcs_static_site_proxy import __version__
from gcs_static_site_proxy.auth import (
    DEFAULT_REAUTH_COMMAND,
    AccessTokenManager,
    AuthenticationUnavailable,
)
from gcs_static_site_proxy.catalog import (
    CATALOG_CONFIG_NAME,
    MAX_CATALOG_CONFIG_BYTES,
    CatalogError,
    SiteCatalog,
    parse_catalog,
)
from gcs_static_site_proxy.gcs import GcsClient, GcsConnectionError
from gcs_static_site_proxy.server import (
    GcsStaticSiteProxy,
    ProxyConfig,
    SiteMount,
)
from gcs_static_site_proxy.site_config import (
    MAX_SITE_CONFIG_BYTES,
    SITE_CONFIG_NAME,
    BrowserCacheMode,
    BrowserCachePolicy,
    ContentSecurityPolicy,
    SiteConfigError,
    SiteConfiguration,
    default_browser_cache,
    default_csp,
    load_csp_file,
    parse_site_config,
)

BUCKET_PATTERN = re.compile(r"[a-z0-9][a-z0-9._-]{1,220}[a-z0-9]")
HOSTNAME_PATTERN = re.compile(
    r"(?=.{1,253}$)[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
    r"(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*"
)


@dataclass(frozen=True)
class ResolvedSource:
    prefix: str
    csp: ContentSecurityPolicy
    browser_cache: BrowserCachePolicy
    mounts: tuple[SiteMount, ...] = ()
    catalog: SiteCatalog | None = None


def positive_int(value: str) -> int:
    number = int(value)
    if number < 1:
        raise argparse.ArgumentTypeError("must be a positive integer")
    return number


def tcp_port(value: str) -> int:
    number = positive_int(value)
    if number > 65535:
        raise argparse.ArgumentTypeError("must be between 1 and 65535")
    return number


def bucket_name(value: str) -> str:
    if not BUCKET_PATTERN.fullmatch(value):
        raise argparse.ArgumentTypeError("must be a lowercase GCS bucket name")
    return value


def object_prefix(value: str) -> str:
    prefix = value.strip("/")
    if (
        not prefix
        or "\\" in prefix
        or any(ord(character) < 0x20 or ord(character) == 0x7F for character in prefix)
        or len(prefix.encode("utf-8")) > 1024
    ):
        raise argparse.ArgumentTypeError("must be a safe, non-empty object prefix")
    if any(part in {"", ".", ".."} for part in prefix.split("/")):
        raise argparse.ArgumentTypeError(
            "must not contain empty, dot, or dot-dot parts"
        )
    return prefix


def allowed_host(value: str) -> str:
    host = value.strip().rstrip(".").lower()
    if host.startswith("[") and host.endswith("]"):
        host = host[1:-1]
    with contextlib.suppress(ValueError):
        return str(ipaddress.ip_address(host))
    if not HOSTNAME_PATTERN.fullmatch(host):
        raise argparse.ArgumentTypeError(
            "must be a hostname or IP address without a port"
        )
    return host


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(
        description=(
            "Serve one private GCS static-site prefix or an explicit catalog "
            "of prefixes through a renewable, read-only local proxy."
        )
    )
    result.add_argument("--bucket", required=True, type=bucket_name)
    source_group = result.add_mutually_exclusive_group(required=True)
    source_group.add_argument("--prefix", type=object_prefix)
    source_group.add_argument(
        "--catalog-prefix",
        type=object_prefix,
        help=(
            "landing-page prefix containing "
            f"{CATALOG_CONFIG_NAME} with explicit site mounts"
        ),
    )
    result.add_argument(
        "--bind",
        default="127.0.0.1",
        metavar="ADDRESS",
        help="listening address (default: 127.0.0.1)",
    )
    result.add_argument(
        "--port",
        type=tcp_port,
        default=os.environ.get("PORT", "8080"),
        help="local TCP port (default: 8080)",
    )
    result.add_argument(
        "--allow-host",
        action="append",
        default=[],
        type=allowed_host,
        metavar="HOST",
        help="additional accepted Host value; may be repeated",
    )
    result.add_argument("--tls-cert", type=Path, metavar="PATH")
    result.add_argument("--tls-key", type=Path, metavar="PATH")
    csp_group = result.add_mutually_exclusive_group()
    csp_group.add_argument(
        "--csp-override-file",
        type=Path,
        metavar="PATH",
        help="override the CSP for every served route with the exact policy in a file",
    )
    csp_group.add_argument(
        "--strict-csp",
        action="store_true",
        help="use the strict built-in CSP for every served route",
    )
    csp_group.add_argument(
        "--no-csp",
        action="store_true",
        help="do not add a CSP response header to any served route",
    )
    result.add_argument(
        "--browser-cache",
        choices=[mode.value for mode in BrowserCacheMode],
        help=(
            "override the browser cache policy for every served route; "
            "the secure default is no-store"
        ),
    )
    result.add_argument(
        "--auth-retry-seconds",
        type=positive_int,
        default=5,
        metavar="N",
        help="delay after a failed ADC refresh (default: 5)",
    )
    result.add_argument(
        "--reauth-command",
        default=DEFAULT_REAUTH_COMMAND,
        metavar="COMMAND",
        help="command offered to the local operator when ADC expires",
    )
    result.add_argument("--no-browser", action="store_true")
    result.add_argument(
        "--version", action="version", version=f"%(prog)s {__version__}"
    )
    return result


async def gcs_site_configuration(
    *, bucket: str, prefix: str, auth_retry_seconds: int
) -> SiteConfiguration | None:
    tokens = AccessTokenManager(retry_seconds=auth_retry_seconds)
    async with GcsClient(bucket, tokens) as gcs:
        return await read_site_configuration(gcs, bucket=bucket, prefix=prefix)


async def read_site_configuration(
    gcs: GcsClient, *, bucket: str, prefix: str
) -> SiteConfiguration | None:
    object_name = f"{prefix}/{SITE_CONFIG_NAME}"
    result = await gcs.read_config_object(
        object_name, maximum_bytes=MAX_SITE_CONFIG_BYTES
    )
    if result is None:
        return None
    return parse_site_config(
        result.body,
        source=f"gs://{bucket}/{object_name}",
        generation=result.generation,
    )


def explicit_csp(arguments: argparse.Namespace) -> ContentSecurityPolicy | None:
    if arguments.no_csp:
        return ContentSecurityPolicy(value=None, source="disabled by --no-csp")
    if arguments.csp_override_file:
        return load_csp_file(arguments.csp_override_file)
    if arguments.strict_csp:
        strict = default_csp()
        return ContentSecurityPolicy(
            value=strict.value,
            source="built-in strict CSP selected by --strict-csp",
        )
    return None


def explicit_browser_cache(
    arguments: argparse.Namespace,
) -> BrowserCachePolicy | None:
    if arguments.browser_cache is None:
        return None
    return BrowserCachePolicy(
        mode=BrowserCacheMode(arguments.browser_cache),
        source=f"--browser-cache {arguments.browser_cache}",
    )


async def gcs_catalog_source(arguments: argparse.Namespace) -> ResolvedSource:
    catalog_prefix = arguments.catalog_prefix
    assert isinstance(catalog_prefix, str)
    tokens = AccessTokenManager(retry_seconds=arguments.auth_retry_seconds)
    catalog_object = f"{catalog_prefix}/{CATALOG_CONFIG_NAME}"
    async with GcsClient(arguments.bucket, tokens) as gcs:
        result = await gcs.read_config_object(
            catalog_object, maximum_bytes=MAX_CATALOG_CONFIG_BYTES
        )
        if result is None:
            raise CatalogError(
                f"site catalog does not exist: gs://{arguments.bucket}/{catalog_object}"
            )
        catalog = parse_catalog(
            result.body,
            source=f"gs://{arguments.bucket}/{catalog_object}",
            generation=result.generation,
        )
        override = explicit_csp(arguments)
        cache_override = explicit_browser_cache(arguments)

        async def site_configuration(
            prefix: str,
        ) -> tuple[ContentSecurityPolicy, BrowserCachePolicy]:
            configured = (
                None
                if override is not None and cache_override is not None
                else await read_site_configuration(
                    gcs, bucket=arguments.bucket, prefix=prefix
                )
            )
            csp = override or (configured.csp if configured else default_csp())
            browser_cache = cache_override or (
                configured.browser_cache if configured else default_browser_cache()
            )
            return csp, browser_cache

        landing_csp, landing_browser_cache = await site_configuration(catalog_prefix)
        mounts_list: list[SiteMount] = []
        for site in catalog.sites:
            mounted_csp, mounted_browser_cache = await site_configuration(site.prefix)
            mounts_list.append(
                SiteMount(
                    slug=site.slug,
                    title=site.title,
                    prefix=site.prefix,
                    csp=mounted_csp,
                    browser_cache=mounted_browser_cache,
                )
            )
        mounts = tuple(mounts_list)

    return ResolvedSource(
        prefix=catalog_prefix,
        csp=landing_csp,
        browser_cache=landing_browser_cache,
        mounts=mounts,
        catalog=catalog,
    )


def resolve_source(arguments: argparse.Namespace) -> ResolvedSource:
    if arguments.catalog_prefix:
        return asyncio.run(gcs_catalog_source(arguments))
    assert isinstance(arguments.prefix, str)
    override = explicit_csp(arguments)
    cache_override = explicit_browser_cache(arguments)
    configured = (
        None
        if override is not None and cache_override is not None
        else asyncio.run(
            gcs_site_configuration(
                bucket=arguments.bucket,
                prefix=arguments.prefix,
                auth_retry_seconds=arguments.auth_retry_seconds,
            )
        )
    )
    return ResolvedSource(
        prefix=arguments.prefix,
        csp=override or (configured.csp if configured else default_csp()),
        browser_cache=(
            cache_override
            or (configured.browser_cache if configured else default_browser_cache())
        ),
    )


def tls_context(arguments: argparse.Namespace) -> ssl.SSLContext | None:
    if bool(arguments.tls_cert) != bool(arguments.tls_key):
        raise ValueError("--tls-cert and --tls-key must be supplied together")
    if not arguments.tls_cert:
        return None
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(arguments.tls_cert, arguments.tls_key)
    return context


def discover_network_addresses() -> list[str]:
    addresses: set[str] = set()
    try:
        for item in socket.getaddrinfo(socket.gethostname(), None):
            address = item[4][0]
            if isinstance(address, str):
                addresses.add(address)
    except socket.gaierror:
        pass
    for destination in (("8.8.8.8", 80), ("2001:4860:4860::8888", 80)):
        family = socket.AF_INET6 if ":" in destination[0] else socket.AF_INET
        with contextlib.suppress(OSError):
            probe = socket.socket(family, socket.SOCK_DGRAM)
            try:
                probe.connect(destination)
                addresses.add(probe.getsockname()[0])
            finally:
                probe.close()
    useful = []
    for value in addresses:
        with contextlib.suppress(ValueError):
            address = ipaddress.ip_address(value)
            if not address.is_loopback and not address.is_unspecified:
                useful.append(str(address))
    return sorted(set(useful))


def url_host(value: str) -> str:
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return value
    return f"[{address}]" if address.version == 6 else str(address)


async def open_browser(url: str) -> None:
    await asyncio.sleep(0.5)
    try:
        opened = await asyncio.to_thread(webbrowser.open, url, new=2)
    except (OSError, webbrowser.Error) as error:
        print(f"Could not open the default browser: {error}")
        return
    if not opened:
        print(f"Could not open the default browser. Open {url} manually.")


def run(arguments: argparse.Namespace) -> None:
    source = resolve_source(arguments)
    ssl_context = tls_context(arguments)
    config = ProxyConfig(
        bucket=arguments.bucket,
        prefix=source.prefix,
        csp=source.csp,
        browser_cache=source.browser_cache,
        bind=arguments.bind,
        port=arguments.port,
        allow_hosts=tuple(arguments.allow_host),
        tls_enabled=ssl_context is not None,
        auth_retry_seconds=arguments.auth_retry_seconds,
        reauth_command=arguments.reauth_command,
        mounts=source.mounts,
    )
    proxy = GcsStaticSiteProxy(config)
    application = proxy.application()
    scheme = "https" if ssl_context else "http"
    unlock = (
        f"{LOCAL_UNLOCK_PATH}/{proxy.guard.session_token}"
        if proxy.guard.network_mode
        else ""
    )
    local_url = f"{scheme}://localhost:{config.port}{unlock}"

    if not arguments.no_browser:

        async def browser_context(_app: web.Application) -> AsyncIterator[None]:
            task = asyncio.create_task(open_browser(local_url))
            try:
                yield
            finally:
                task.cancel()
                with contextlib.suppress(asyncio.CancelledError):
                    await task

        application.cleanup_ctx.append(browser_context)

    print(f"GCS source: gs://{config.bucket}/{config.prefix}/")
    print("Authentication: direct user ADC")
    if source.catalog is not None:
        print(f"Catalog source: {source.catalog.source}")
        if source.catalog.generation:
            print(f"Catalog object generation: {source.catalog.generation}")
        print(f"Catalog SHA-256: {source.catalog.sha256}")
        if arguments.no_csp or arguments.csp_override_file or arguments.strict_csp:
            print(
                "WARNING: the explicit CSP mode applies to the landing page and "
                "every mounted site.",
                file=sys.stderr,
            )
    print_policy("Landing" if source.catalog else "Site", source.csp)
    print_browser_cache("Landing" if source.catalog else "Site", source.browser_cache)
    for mount in source.mounts:
        print(
            f"Mount /sites/{mount.slug}/ -> "
            f"gs://{config.bucket}/{mount.prefix}/ ({mount.title})"
        )
        print_policy(f"Mount /sites/{mount.slug}/", mount.csp)
        print_browser_cache(f"Mount /sites/{mount.slug}/", mount.browser_cache)
    print(f"Local URL: {local_url}")
    if proxy.guard.network_mode:
        print(
            "WARNING: network mode exposes ADC-readable site content to token holders."
        )
        if ssl_context is None:
            print("WARNING: network traffic is HTTP and is not encrypted.")
        for address in discover_network_addresses():
            print(f"Network URL: {scheme}://{url_host(address)}:{config.port}{unlock}")
    print("Read-only mode: only GET and HEAD requests are accepted.")
    web.run_app(
        application,
        host=config.bind,
        port=config.port,
        ssl_context=ssl_context,
        print=None,
        access_log=None,
    )


def print_policy(label: str, csp: ContentSecurityPolicy) -> None:
    print(f"{label} CSP source: {csp.source}")
    if csp.generation:
        print(f"{label} CSP object generation: {csp.generation}")
    if csp.sha256:
        print(f"{label} CSP SHA-256: {csp.sha256}")
    if csp.value is None:
        print(f"WARNING: {label} CSP is disabled.", file=sys.stderr)
    elif "'unsafe-eval'" in csp.value:
        print(f"WARNING: {label} CSP permits 'unsafe-eval'.", file=sys.stderr)


def print_browser_cache(label: str, policy: BrowserCachePolicy) -> None:
    print(f"{label} browser cache: {policy.mode.value} ({policy.source})")


LOCAL_UNLOCK_PATH = "/__gcs_proxy/unlock"


def main(argv: Sequence[str] | None = None) -> None:
    # This is a dedicated CLI process. Use the operating system trust store for
    # both google-auth's requests transport and the aiohttp GCS transport so
    # root CAs installed through device management work consistently.
    truststore.inject_into_ssl()
    argument_parser = parser()
    arguments = argument_parser.parse_args(argv)
    try:
        run(arguments)
    except (
        AuthenticationUnavailable,
        CatalogError,
        GcsConnectionError,
        OSError,
        SiteConfigError,
        ValueError,
    ) as error:
        argument_parser.error(str(error))


if __name__ == "__main__":
    main()
