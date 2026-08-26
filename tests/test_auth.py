from __future__ import annotations

import asyncio
import shlex
import subprocess
import sys
from datetime import UTC, datetime, timedelta
from typing import cast

import pytest
from google.auth.credentials import Credentials

from gcs_static_site_proxy.auth import (
    AccessTokenManager,
    LoginController,
    executable_command,
    split_command,
)


class FakeCredentials:
    def __init__(self, token: str | None, expiry: datetime | None) -> None:
        self.token = token
        self.expiry = expiry


def credentials(token: str | None, expiry: datetime | None) -> Credentials:
    return cast(Credentials, FakeCredentials(token, expiry))


def test_access_token_freshness_accepts_aware_future_expiry() -> None:
    value = credentials("token", datetime.now(UTC) + timedelta(minutes=10))
    assert AccessTokenManager._is_fresh(value)


def test_access_token_freshness_treats_naive_expiry_as_utc() -> None:
    expiry = datetime.now(UTC).replace(tzinfo=None) + timedelta(minutes=10)
    value = credentials("token", expiry)
    assert AccessTokenManager._is_fresh(value)


def test_access_token_freshness_rejects_missing_and_near_expiry() -> None:
    assert not AccessTokenManager._is_fresh(credentials(None, None))
    near = credentials("token", datetime.now(UTC) + timedelta(minutes=2))
    assert not AccessTokenManager._is_fresh(near)


def test_split_command_preserves_windows_paths() -> None:
    command = r'"C:\Program Files\Google\Cloud SDK\gcloud.cmd" auth login'
    assert split_command(command, windows=True) == [
        r"C:\Program Files\Google\Cloud SDK\gcloud.cmd",
        "auth",
        "login",
    ]


def test_windows_batch_commands_are_run_through_cmd(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(sys, "platform", "win32")
    assert executable_command(
        [r"C:\tools\gcloud.cmd", "auth", "login"], r"C:\tools\gcloud.cmd"
    ) == [
        "cmd.exe",
        "/d",
        "/s",
        "/c",
        r"C:\tools\gcloud.cmd",
        "auth",
        "login",
    ]


async def wait_until_finished(controller: LoginController) -> None:
    for _ in range(200):
        if not controller.running:
            return
        await asyncio.sleep(0.01)
    raise AssertionError("login controller did not finish")


@pytest.mark.asyncio
async def test_login_controller_successfully_verifies_new_adc() -> None:
    invalidations = 0
    verifications = 0

    async def invalidate() -> None:
        nonlocal invalidations
        invalidations += 1

    async def verify(**_kwargs: object) -> str:
        nonlocal verifications
        verifications += 1
        return "token"

    command = subprocess.list2cmdline([sys.executable, "-c", "pass"])
    if sys.platform != "win32":
        command = " ".join(shlex.quote(part) for part in [sys.executable, "-c", "pass"])
    controller = LoginController(command, invalidate, verify)
    await controller.start()
    await wait_until_finished(controller)
    assert controller.status()["login_state"] == "succeeded"
    assert invalidations == 1
    assert verifications == 1


@pytest.mark.asyncio
async def test_login_controller_records_nonzero_exit() -> None:
    async def invalidate() -> None:
        raise AssertionError("must not invalidate after a failed command")

    async def verify(**_kwargs: object) -> str:
        raise AssertionError("must not verify after a failed command")

    parts = [sys.executable, "-c", "import sys; sys.exit(7)"]
    command = subprocess.list2cmdline(parts)
    if sys.platform != "win32":
        command = " ".join(shlex.quote(part) for part in parts)
    controller = LoginController(command, invalidate, verify)
    await controller.start()
    await wait_until_finished(controller)
    status = controller.status()
    assert status["login_state"] == "failed"
    assert "status 7" in str(status["message"])


@pytest.mark.asyncio
async def test_login_controller_cancels_a_running_process() -> None:
    async def invalidate() -> None:
        raise AssertionError("must not invalidate a cancelled command")

    async def verify(**_kwargs: object) -> str:
        raise AssertionError("must not verify a cancelled command")

    parts = [sys.executable, "-c", "import time; time.sleep(30)"]
    command = subprocess.list2cmdline(parts)
    if sys.platform != "win32":
        command = " ".join(shlex.quote(part) for part in parts)
    controller = LoginController(command, invalidate, verify)
    await controller.start()
    await asyncio.sleep(0.05)
    assert controller.running
    await controller.cancel()
    assert not controller.running
    assert controller.status()["login_state"] == "cancelled"
