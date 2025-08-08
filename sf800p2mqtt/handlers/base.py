#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Abstract base classes for input and output handlers.

This module provides the abstract interfaces that all input and output
handlers must implement. Input handlers are responsible for packet capture
from various sources, while output handlers manage publishing data to
different destinations.
"""

from abc import ABC, abstractmethod
from typing import Callable


class InputHandler(ABC):    # pylint: disable=too-few-public-methods
    """Abstract base class for input handlers.

    Defines the interface that all input handlers must implement for
    capturing network packets from various sources such as live network
    interfaces or PCAP files.
    """

    @abstractmethod
    def start_capture(self, packet_callback: Callable, bpf_filter: str) -> int:
        """Start packet capture.

        Begin capturing packets from the input source and process them
        through the provided callback function. Supports BPF filtering
        to capture only relevant packets.

        Args:
            packet_callback (Callable): Function to call for each captured
                packet. Should accept a single packet argument.
            bpf_filter (str): Berkeley Packet Filter expression to apply
                during capture. Empty string means no filtering.

        Returns:
            int: 0 on successful completion, -1 on error.
        """


class OutputHandler(ABC):
    """Abstract base class for output handlers.

    Defines the interface that all output handlers must implement for
    publishing messages to various destinations such as MQTT brokers,
    files, or standard output.
    """

    @abstractmethod
    def connect(self) -> bool:
        """Connect to the output destination.

        Establish connection to the output destination. This may involve
        network connections, file opens, or other setup operations required
        before publishing can begin.

        Returns:
            bool: True if connection was successful, False otherwise.
        """

    @abstractmethod
    def publish(self, topic: str, payload: str) -> bool:
        """Publish a message.

        Send a message to the configured output destination. The exact
        behavior depends on the implementation (e.g., MQTT publish,
        file write, console output).

        Args:
            topic (str): The topic or category for the message.
            payload (str): The message content to be published.

        Returns:
            bool: True if the message was published successfully,
                False otherwise.
        """

    @abstractmethod
    def disconnect(self):
        """Disconnect from the output destination.

        Clean up any resources and close connections to the output
        destination. Should be called when the handler is no longer
        needed to ensure proper cleanup.
        """
