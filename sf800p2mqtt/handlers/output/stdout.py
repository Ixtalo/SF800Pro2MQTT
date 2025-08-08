# -*- coding: utf-8 -*-
"""STDOUT output handler for printing messages to standard output.

This module provides a simple output handler that prints formatted messages
to stdout with timestamps for logging and debugging purposes.
"""
import logging
from time import strftime

from ..base import OutputHandler


class StdoutOutputHandler(OutputHandler):
    """STDOUT output handler implementation.

    Handles outputting messages to standard output with timestamp formatting.
    Provides a simple, always-available output mechanism for debugging and
    logging purposes.
    """

    def __init__(self):
        """Initialize STDOUT output handler.

        STDOUT is always available, so no actual connection setup is required.
        """
        self.connected = False

    def connect(self) -> bool:
        """Connect to STDOUT (always successful).

        Since stdout is always available, this operation always
        succeeds and simply updates the connection state.

        Returns:
            bool: Always True, indicating successful connection.
        """
        self.connected = True
        return True

    def publish(self, topic: str, payload: str) -> bool:
        """Print message to STDOUT.

        Formats and prints a message to standard output with timestamp prefix.
        The message format is: [YYYY-MM-DD HH:MM:SS] topic: payload

        Args:
            topic (str): The topic or category for the message.
            payload (str): The message content to be printed.

        Returns:
            bool: True if message was printed successfully, False if an error occurred.
        """
        try:
            timestamp = strftime("%Y-%m-%d %H:%M:%S")
            print(f"[{timestamp}] {topic}: {payload}", flush=True)
            return True
        except Exception as e:  # pylint: disable=broad-except
            logging.error("STDOUT publish failed: %s", e)
            return False

    def disconnect(self):
        """Disconnect from STDOUT.

        No actual disconnection is required since stdout is always available.
        """
        self.connected = False
