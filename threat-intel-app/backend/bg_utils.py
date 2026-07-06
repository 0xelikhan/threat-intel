"""
Two small helpers used by main.py but kept here so the test suite can
exercise them without paying the full main.py import cost.

  - BoundedDict: insertion-order dict with LRU eviction; the standard
    pattern for module-level caches that would otherwise grow forever.
    Replaces the per-investigation `_results` / `_chats` stores in
    main.py.

  - track_task: registers a fire-and-forget asyncio.Task in a strong-ref
    set + a done-callback that removes it on completion. Without this,
    asyncio's weakref policy can let a long-running background task be
    GC'd before its coroutine finishes.

Neither helper has any FastAPI / Starlette / SDK dependency, which is
why they live here instead of main.py.
"""

from __future__ import annotations

import asyncio
from collections import OrderedDict
from typing import Set


class BoundedDict(OrderedDict):
    """Insertion-order dict that evicts the oldest entry once `_cap` is
    exceeded. Re-assigning an existing key refreshes its position so
    "recently touched" entries stick around."""

    def __init__(self, cap: int):
        super().__init__()
        self._cap = cap

    def __setitem__(self, key, value):
        if key in self:
            self.move_to_end(key)
        super().__setitem__(key, value)
        while len(self) > self._cap:
            self.popitem(last=False)


# Module-level strong-ref store for background tasks. main.track_task
# (which proxies to track_task here) is the entry point external modules
# should call when they want a task to outlive the request that spawned
# it (sandbox polling, post-scan AI fan-out, periodic refresh loops).
_BG_TASKS: "Set[asyncio.Task]" = set()


def track_task(task: "asyncio.Task") -> "asyncio.Task":
    _BG_TASKS.add(task)
    task.add_done_callback(_BG_TASKS.discard)
    return task
