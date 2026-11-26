"""Bounded polling with injectable clock/sleep so callers stay testable."""
from __future__ import annotations

import time as _time


def wait_until(predicate, timeout, interval, *, clock=None, sleep=None):
    """Poll `predicate` until it is true or `timeout` seconds have elapsed.

    Callers pass their own `time` module attributes: tests replace those with a
    fake clock, and the production code keeps using the real one.
    """
    clock = clock or _time.monotonic
    sleep = sleep or _time.sleep
    deadline = clock() + timeout
    while True:
        if predicate():
            return True
        if clock() >= deadline:
            return False
        sleep(interval)
