#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Logging configuration module for colored console and file output.

This module provides centralized logging setup with support for colored
console output and optional file logging. Uses colorlog for enhanced
readability in terminal environments.
"""

import logging
import os
import sys
from typing import Optional

import colorlog


# Define log formats for different output contexts
INTERACTIVE_FORMAT = "%(log_color)s%(asctime)s %(levelname)-8s %(message)s"  # Colors + timestamp
SYSTEMD_FORMAT = "%(levelname)-8s %(message)s"                               # Plain (systemd adds timestamp)
REDIRECTED_FORMAT = "%(asctime)s %(levelname)-8s %(message)s"                # Timestamp, no colors


def is_running_under_systemd() -> bool:
    """Check if the process was started via systemd."""
    # JOURNAL_STREAM: Set when systemd redirects output to journal
    # INVOCATION_ID: Unique identifier set by systemd for each service invocation
    # Both indicate we're running as a systemd service, where colored output
    # would appear as escape sequences in logs
    return bool(os.environ.get('JOURNAL_STREAM') or os.environ.get('INVOCATION_ID'))


def is_stdout_tty() -> bool:
    """Check if stdout is connected to a TTY (terminal)."""
    # TTY (TeleTYpewriter) means we're outputting directly to a terminal
    # Returns False when output is redirected to files, pipes, or other processes
    # Examples where this returns False:
    #   - python script.py > output.txt
    #   - python script.py | grep something
    #   - running in non-interactive environments
    return sys.stdout.isatty()


def setup_logging(log_file: Optional[str] = None,
                  level: int = logging.INFO,
                  no_color=False,
                  force=True,
                  **kwargs):
    """Set up the logging framework.

    Configures the Python logging system with colored output support for
    console logging and optional file output. When logging to a file,
    color formatting is automatically disabled.

    Args:
        log_file (str | None, optional): Path to log file for file-based logging.
            If None, logs to stdout. Defaults to None.
        level (int, optional): Logging level threshold. Uses standard logging
            levels (DEBUG=10, INFO=20, WARNING=30, ERROR=40, CRITICAL=50).
            Defaults to logging.INFO.
        no_color (bool, optional): Disable colored output even for console
            logging. Automatically set to True when logging to file.
            Defaults to False.
        force (bool, optional): if true, any existing handlers
              attached to the root logger are removed and closed.

    Returns:
        colorlog.StreamHandler: The configured stream handler instance.

    Note:
        When log_file is specified, the file is opened in append mode with
        UTF-8 encoding. Color formatting is automatically disabled for file
        output to prevent ANSI escape codes in log files.
    """
    # Only auto-detect color support if colors haven't been explicitly disabled
    if not no_color:
        # Auto-detect if colors should be disabled based on environment
        # Disable colors if running under systemd OR output is not a TTY
        # Result: no_color = True in any environment where colored output
        # would be garbled, unwanted, or unsupported
        no_color = is_running_under_systemd() or not is_stdout_tty()
    if log_file:
        # pylint: disable=consider-using-with
        stream = open(log_file, "a", encoding="utf8")
        no_color = True
    else:
        stream = sys.stdout
    handler = colorlog.StreamHandler(stream=stream)
    # Use colored format with timestamp for interactive terminals,
    # plain format without colors/timestamp for non-interactive
    # (systemd/redirected output)
    if is_running_under_systemd():
        # Systemd services: no colors (would show as escape sequences in journal)
        # no timestamp (systemd journal adds its own)
        format = SYSTEMD_FORMAT
    elif not is_stdout_tty():
        # Redirected output (files, pipes): include timestamp for context
        # no colors (would show as escape sequences in files)
        format = REDIRECTED_FORMAT
    else:
        # Interactive terminal: full formatting with colors and timestamp
        format = INTERACTIVE_FORMAT
    handler.setFormatter(
        colorlog.ColoredFormatter(
            fmt=format,
            datefmt="%Y-%m-%d %H:%M:%S",
            no_color=no_color
        )
    )
    basic_config_kwargs = {
        'level': level,
        'handlers': [handler],
        'force': force,
        **kwargs
    }
    logging.basicConfig(**basic_config_kwargs)
    return handler
