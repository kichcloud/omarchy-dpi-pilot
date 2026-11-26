"""Errors shared by the CLI facade and its helper modules."""
from __future__ import annotations


class Fail(Exception):
    """An error that should reach the panel as a short JSON message."""
