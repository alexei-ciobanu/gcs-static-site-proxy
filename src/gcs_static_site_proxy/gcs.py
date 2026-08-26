"""Authenticated streaming access to the GCS JSON media API."""

from __future__ import annotations

import ssl
import urllib.parse
from dataclasses import dataclass
from typing import Any

import truststore
from aiohttp import (
    ClientError,
    ClientResponse,
    ClientSession,
    ClientTimeout,
    TCPConnector,
)

from gcs_static_site_proxy.auth import AccessTokenManager, AuthenticationUnavailable

DEFAULT_GCS_API_ROOT = "https://storage.googleapis.com/storage/v1"


class GcsConnectionError(RuntimeError):
    """Raised when the proxy cannot reach GCS."""


@dataclass(frozen=True)
class ConfigObject:
    body: bytes
    generation: str | None


class GcsClient:
    """A renewable authenticated client for one bucket."""

    def __init__(
        self,
        bucket: str,
        tokens: AccessTokenManager,
        *,
        api_root: str = DEFAULT_GCS_API_ROOT,
    ) -> None:
        self.bucket = bucket
        self.tokens = tokens
        self.api_root = api_root.rstrip("/")
        self.session: ClientSession | None = None

    async def __aenter__(self) -> GcsClient:
        timeout = ClientTimeout(total=None, connect=20, sock_read=300)
        ssl_context = truststore.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        connector = TCPConnector(ssl=ssl_context)
        self.session = ClientSession(
            timeout=timeout,
            connector=connector,
            auto_decompress=False,
        )
        return self

    async def __aexit__(self, *_exc: Any) -> None:
        if self.session is not None:
            await self.session.close()
            self.session = None

    def media_url(self, object_name: str) -> str:
        bucket = urllib.parse.quote(self.bucket, safe="")
        name = urllib.parse.quote(object_name, safe="")
        return f"{self.api_root}/b/{bucket}/o/{name}?alt=media"

    async def request(self, object_name: str) -> ClientResponse:
        if self.session is None:
            raise RuntimeError("GCS client session has not started")
        try:
            token = await self.tokens.token()
        except AuthenticationUnavailable:
            raise

        for attempt in range(2):
            try:
                response = await self.session.get(
                    self.media_url(object_name),
                    headers={
                        "Authorization": f"Bearer {token}",
                        "Accept-Encoding": "gzip",
                    },
                    allow_redirects=False,
                )
            except (ClientError, TimeoutError) as error:
                raise GcsConnectionError(str(error)) from error
            if response.status != 401:
                return response
            if attempt == 1:
                await self.tokens.invalidate()
                return response
            response.release()
            await self.tokens.invalidate()
            token = await self.tokens.token(force_reload=True)

        raise AssertionError("unreachable")

    async def read_config_object(
        self, object_name: str, *, maximum_bytes: int
    ) -> ConfigObject | None:
        response = await self.request(object_name)
        try:
            if response.status == 404:
                return None
            if response.status != 200:
                raise GcsConnectionError(
                    f"GCS returned HTTP {response.status} for gs://"
                    f"{self.bucket}/{object_name}"
                )
            body = await response.content.read(maximum_bytes + 1)
            if len(body) > maximum_bytes:
                raise GcsConnectionError(
                    f"GCS object exceeds the {maximum_bytes}-byte limit"
                )
            return ConfigObject(
                body=body,
                generation=response.headers.get("x-goog-generation"),
            )
        finally:
            response.release()
