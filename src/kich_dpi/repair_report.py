"""Accumulator and error formatter for the one-click repair command."""
from __future__ import annotations

from . import core


class RepairReport:
    def __init__(self):
        self.fixes = []
        self.blocked = []

    def fixed(self, text):
        self.fixes.append(text)

    def blocked_by(self, text):
        self.blocked.append(text)


def repair_error(cp_text, fallback):
    return core.clip(cp_text, fallback, 160)
