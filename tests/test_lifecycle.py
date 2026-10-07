"""Regression tests for the OpenPhish background task lifecycle.

Guards against the pytest/TestClient teardown hang: the refresh loop must be an
owned task that shutdown() cancels and awaits, leaving no pending tasks.
"""

from __future__ import annotations

import asyncio

from backend.services.threat_intel.openphish_cache import openphish_cache


def _pending_tasks() -> set[asyncio.Task]:
    current = asyncio.current_task()
    return {t for t in asyncio.all_tasks() if t is not current and not t.done()}


def test_start_and_shutdown_leave_no_pending_tasks(monkeypatch):
    calls = {"n": 0}

    async def fake_refresh():
        calls["n"] += 1  # no network

    monkeypatch.setattr(openphish_cache, "refresh_feed", fake_refresh)

    async def scenario():
        task = openphish_cache.start()
        assert openphish_cache.start() is task  # idempotent while running
        await asyncio.sleep(0)  # let it run the first refresh, then park in sleep()
        assert calls["n"] == 1
        assert not task.done()

        await openphish_cache.shutdown()
        assert task.cancelled()
        assert _pending_tasks() == set()
        await openphish_cache.shutdown()  # idempotent

    asyncio.run(scenario())


def test_shutdown_during_inflight_fetch_is_clean(monkeypatch):
    started = None

    async def slow_refresh():
        started.set()
        await asyncio.sleep(3600)  # simulates a hung network fetch

    monkeypatch.setattr(openphish_cache, "refresh_feed", slow_refresh)

    async def scenario():
        nonlocal started
        started = asyncio.Event()
        task = openphish_cache.start()
        await asyncio.wait_for(started.wait(), timeout=2)
        await asyncio.wait_for(openphish_cache.shutdown(), timeout=2)
        assert task.cancelled()
        assert _pending_tasks() == set()

    asyncio.run(scenario())


def test_lock_rebinds_across_event_loops():
    """The cache is a module singleton reused by multiple loops (TestClient, asyncio.run)."""

    async def use_lock():
        async with openphish_cache.lock:
            pass
        await openphish_cache.shutdown()

    asyncio.run(use_lock())
    asyncio.run(use_lock())  # would raise "bound to a different event loop" if not reset


def test_app_lifespan_shuts_down_cleanly(client):
    # The session client already ran startup; the background refresh is disabled in tests.
    assert client.get("/health").status_code == 200
    assert openphish_cache._task is None
