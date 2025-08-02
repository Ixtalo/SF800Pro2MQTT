#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Logging configuration module for colored console and file output.

This module provides centralized logging setup with support for colored
console output and optional file logging. Uses colorlog for enhanced
readability in terminal environments.
"""

import logging
import sys

import colorlog


def setup_logging(log_file: str | None = None, level: int = logging.INFO, no_color=False):
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

    Returns:
        colorlog.StreamHandler: The configured stream handler instance.

    Note:
        When log_file is specified, the file is opened in append mode with
        UTF-8 encoding. Color formatting is automatically disabled for file
        output to prevent ANSI escape codes in log files.
    """
    if log_file:
        # pylint: disable=consider-using-with
        stream = open(log_file, "a", encoding="utf8")
        no_color = True
    else:
        stream = sys.stdout
    handler = colorlog.StreamHandler(stream=stream)
    handler.setFormatter(
        colorlog.ColoredFormatter(
            "%(log_color)s%(asctime)s %(levelname)-8s %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
            no_color=no_color
        )
    )
    logging.basicConfig(level=level, handlers=[handler])
    return handler
