"""Renewable OAuth access tokens and local ADC recovery."""

from __future__ import annotations

import asyncio
import contextlib
import shlex
import shutil
import sys
import time
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime

import google.auth
from google.auth import exceptions as auth_exceptions
from google.auth.credentials import Credentials
from google.auth.transport.requests import Request as AuthRequest

DEFAULT_REAUTH_COMMAND = "gcloud auth login --update-adc --quiet"
SCOPES = ("https://www.googleapis.com/auth/cloud-platform",)
TOKEN_REFRESH_SKEW_SECONDS = 300
LOGIN_TIMEOUT_SECONDS = 15 * 60


class AuthenticationUnavailable(Exception):
    """Raised when ADC cannot provide a usable OAuth access token."""


def split_command(command: str, *, windows: bool | None = None) -> list[str]:
    """Split an operator command without corrupting Windows path separators."""
    if windows is None:
        windows = sys.platform == "win32"
    arguments = shlex.split(command, posix=not windows)
    if windows:
        arguments = [
            argument[1:-1]
            if (
                len(argument) >= 2
                and argument[0] == argument[-1]
                and argument[0] in "\"'"
            )
            else argument
            for argument in arguments
        ]
    return arguments


def executable_command(arguments: list[str], executable: str) -> list[str]:
    """Return arguments that can execute a resolved program on this platform."""
    if sys.platform == "win32" and executable.lower().endswith((".bat", ".cmd")):
        return ["cmd.exe", "/d", "/s", "/c", executable, *arguments[1:]]
    return [executable, *arguments[1:]]


class AccessTokenManager:
    """Load user ADC on demand and renew its OAuth access token."""

    def __init__(self, *, retry_seconds: int = 5) -> None:
        self.retry_seconds = retry_seconds
        self._credentials: Credentials | None = None
        self._request = AuthRequest()
        self._lock = asyncio.Lock()
        self._failed_at = 0.0
        self._last_error = ""

    @property
    def last_error(self) -> str:
        return self._last_error

    async def token(
        self, *, force_reload: bool = False, report_failure: bool = True
    ) -> str:
        async with self._lock:
            if force_reload:
                self._clear()
                self._failed_at = 0.0

            if self._credentials is not None and self._is_fresh(self._credentials):
                assert isinstance(self._credentials.token, str)
                return self._credentials.token

            retry_in = self.retry_seconds - (time.monotonic() - self._failed_at)
            if self._failed_at and retry_in > 0:
                raise AuthenticationUnavailable(self._last_error)

            try:
                token = await asyncio.to_thread(self._load_or_refresh)
            except (auth_exceptions.GoogleAuthError, OSError) as error:
                self._clear()
                self._failed_at = time.monotonic()
                self._last_error = str(error)
                if report_failure:
                    print(f"Authentication unavailable: {error}", file=sys.stderr)
                raise AuthenticationUnavailable(str(error)) from error

            self._failed_at = 0.0
            self._last_error = ""
            return token

    async def invalidate(self) -> None:
        async with self._lock:
            self._clear()
            self._failed_at = 0.0

    def _load_or_refresh(self) -> str:
        if self._credentials is None:
            self._credentials, _ = google.auth.default(scopes=SCOPES)
        self._credentials.refresh(self._request)
        token = self._credentials.token
        if not isinstance(token, str) or not token:
            raise auth_exceptions.RefreshError("ADC refresh returned no access token")
        return token

    def _clear(self) -> None:
        self._credentials = None

    @staticmethod
    def _is_fresh(credentials: Credentials) -> bool:
        if not isinstance(credentials.token, str) or not credentials.token:
            return False
        expiry = credentials.expiry
        if not isinstance(expiry, datetime):
            return False
        if expiry.tzinfo is None:
            expiry = expiry.replace(tzinfo=UTC)
        return time.time() < expiry.timestamp() - TOKEN_REFRESH_SKEW_SECONDS


class LoginController:
    """Run one local reauthentication command without invoking a shell."""

    def __init__(
        self,
        command: str,
        invalidate: Callable[[], Awaitable[None]],
        verify: Callable[..., Awaitable[str]],
    ) -> None:
        self._command = command
        self._invalidate = invalidate
        self._verify = verify
        self._task: asyncio.Task[None] | None = None
        self._process: asyncio.subprocess.Process | None = None
        self._state = "idle"
        self._message = "Authentication is unavailable."

    @property
    def running(self) -> bool:
        return self._task is not None and not self._task.done()

    def status(self) -> dict[str, str | bool]:
        return {
            "login_running": self.running,
            "login_state": self._state,
            "message": self._message,
        }

    async def start(self) -> None:
        if self.running:
            return
        self._state = "running"
        self._message = "Starting Google Cloud sign-in in your browser…"
        self._task = asyncio.create_task(self._run())

    async def cancel(self) -> None:
        if not self.running or self._task is None:
            return
        self._task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await self._task
        self._state = "cancelled"
        self._message = "Sign-in was cancelled. You can start it again."

    async def close(self) -> None:
        await self.cancel()

    async def _run(self) -> None:
        try:
            arguments = split_command(self._command)
            if not arguments:
                raise ValueError("the reauthentication command is empty")
            executable = shutil.which(arguments[0])
            if executable is None:
                raise OSError(f"executable not found on PATH: {arguments[0]}")
            arguments = executable_command(arguments, executable)
            self._process = await asyncio.create_subprocess_exec(
                *arguments,
                stdin=asyncio.subprocess.DEVNULL,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT,
            )
            self._message = (
                "Complete Google Cloud sign-in in the browser window that opened."
            )
            try:
                output, _ = await asyncio.wait_for(
                    self._process.communicate(), timeout=LOGIN_TIMEOUT_SECONDS
                )
            except TimeoutError:
                await self._stop_process()
                self._state = "failed"
                self._message = "Sign-in timed out after 15 minutes."
                return

            if self._process.returncode != 0:
                detail = self._output_detail(output)
                self._state = "failed"
                self._message = (
                    f"The sign-in command exited with status "
                    f"{self._process.returncode}.{detail}"
                )
                return

            await self._invalidate()
            try:
                await self._verify(force_reload=True, report_failure=False)
            except AuthenticationUnavailable as error:
                self._state = "failed"
                self._message = f"Sign-in finished, but ADC is not usable: {error}"
                return

            self._state = "succeeded"
            self._message = "Sign-in succeeded. Reloading the requested page…"
        except asyncio.CancelledError:
            await self._stop_process()
            raise
        except (OSError, ValueError) as error:
            self._state = "failed"
            self._message = f"Could not start the sign-in command: {error}"
        finally:
            self._process = None

    async def _stop_process(self) -> None:
        if self._process is None or self._process.returncode is not None:
            return
        self._process.terminate()
        try:
            await asyncio.wait_for(self._process.wait(), timeout=5)
        except TimeoutError:
            self._process.kill()
            await self._process.wait()

    @staticmethod
    def _output_detail(output: bytes) -> str:
        text = output.decode(errors="replace").strip()
        return f" {text[-2000:]}" if text else ""
