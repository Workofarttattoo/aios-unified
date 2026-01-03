#!/usr/bin/env python3
"""
Common helpers for ech0 CLI scripts.

Provides utility functions to render commands and paths in a way that
stays valid regardless of the user's current working directory.
"""

from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent


def _resolve_for_display(target: Path) -> str:
    """
    Return a human-friendly string for the given target path.

    If the target lives under the current working directory, return a
    relative path; otherwise fall back to the absolute path so the
    command still works when copied.
    """
    target = target.resolve()
    cwd = Path.cwd().resolve()

    try:
        return target.relative_to(cwd).as_posix()
    except ValueError:
        return str(target)


def format_python_command(script_name: str, *args: str) -> str:
    """
    Construct a python command string that invokes the given script.

    Example:
        format_python_command("ech0_daemon.py", "start")
    """
    script_path = BASE_DIR / script_name
    parts = ["python", _resolve_for_display(script_path)]
    parts.extend(arg for arg in args if arg)
    return " ".join(parts)


def format_path(filename: str) -> str:
    """
    Return a display-friendly path for files that live beside the CLI scripts.
    """
    return _resolve_for_display(BASE_DIR / filename)


__all__ = ["format_python_command", "format_path"]
