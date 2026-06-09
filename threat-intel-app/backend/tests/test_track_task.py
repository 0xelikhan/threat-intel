"""Tests for the track_task helper in main.py.

asyncio.create_task only retains a weakref to the running coroutine;
without a strong reference somewhere the task can be GC'd before it
finishes. main.track_task() registers the task in a module-level set
and registers a done-callback to remove it once the coroutine
completes (see 447deb6)."""

from __future__ import annotations

import asyncio


def test_tracked_task_is_held_until_completion():
    from bg_utils import track_task, _BG_TASKS

    async def _scenario():
        started_marker = asyncio.Event()
        finished_marker = asyncio.Event()

        async def _work():
            started_marker.set()
            await asyncio.sleep(0.05)
            finished_marker.set()

        task = track_task(asyncio.create_task(_work()))
        await started_marker.wait()
        assert task in _BG_TASKS
        await finished_marker.wait()
        await asyncio.sleep(0)
        assert task not in _BG_TASKS

    asyncio.run(_scenario())


def test_tracked_task_returns_same_task():
    from bg_utils import track_task

    async def _scenario():
        async def _noop():
            return 42

        task = asyncio.create_task(_noop())
        returned = track_task(task)
        assert returned is task
        result = await task
        assert result == 42

    asyncio.run(_scenario())


def test_tracked_task_cleaned_up_on_exception():
    from bg_utils import track_task, _BG_TASKS

    async def _scenario():
        async def _boom():
            raise RuntimeError("intentional")

        task = track_task(asyncio.create_task(_boom()))
        try:
            await task
        except RuntimeError:
            pass
        await asyncio.sleep(0)
        assert task not in _BG_TASKS

    asyncio.run(_scenario())
