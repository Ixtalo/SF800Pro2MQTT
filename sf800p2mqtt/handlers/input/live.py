# -*- coding: utf-8 -*-
"""Live network interface input handler for real-time packet capture.

This module provides functionality for capturing network packets from live
network interfaces using scapy with custom socket handling for improved
error resilience and BPF filtering support.
"""
import logging
from functools import partial
from typing import Callable

from scapy.all import Packet, sniff
from scapy.arch.linux import L2ListenSocket
from scapy.data import MTU
from scapy.layers.l2 import Ether

from ..base import InputHandler


# pylint: disable=broad-exception-caught
class MyL2ListenSocket(L2ListenSocket):
    """Enhanced L2 listen socket with comprehensive exception handling.

    This class extends the standard L2ListenSocket to provide robust error
    handling for packet reception, parsing, and socket operations. It includes
    protection against Unicode errors and graceful degradation when parsing fails.
    """

    def __init__(self, *args, **kwargs):
        """Initialize the enhanced L2 listen socket.

        Args:
            *args: Variable length argument list passed to parent constructor.
            **kwargs: Arbitrary keyword arguments passed to parent constructor.
        """
        logging.debug("MyL2ListenSocket initialized")
        super().__init__(*args, **kwargs)
        # Track closure state to prevent operations on closed socket
        self._closed = False

    # pylint: disable=too-many-return-statements
    def recv(self, x: int = MTU, **kwargs) -> Packet | None:
        """Receive packets with robust error handling and parsing protection.

        This method overrides the standard recv() to provide comprehensive
        error handling, including Unicode decode errors and packet parsing
        failures. It ensures the application continues running even when
        malformed packets are received.

        Args:
            x (int): Maximum number of bytes to receive. Defaults to MTU.
            **kwargs: Additional keyword arguments (currently unused).

        Returns:
            Packet | None: Parsed Ethernet packet if successful, None if failed
                          or socket is closed.

        Raises:
            Does not raise exceptions - all errors are caught and logged.
        """
        # Return immediately if socket has been marked as closed
        if self._closed:
            return None

        try:
            # Receive raw bytes directly from the underlying socket
            # This is the primary data reception point
            raw_data = self.ins.recv(x)
            if not raw_data:
                # connection closure or no data available
                return None

            try:
                # Parse raw bytes into Ethernet packet structure
                return Ether(raw_data)
            except (UnicodeDecodeError, UnicodeError) as ex:
                # Handle Unicode-related parsing errors gracefully
                # These can occur with malformed or corrupted packet data
                logging.warning("Unicode error parsing packet, skipping: %s", ex)
                return None
            except Exception as ex:
                # Catch any other parsing errors (malformed packets, etc.)
                # Use debug level as these are common in network environments
                logging.debug("Error parsing packet, skipping: %s", ex)
                return None

        except (UnicodeDecodeError, UnicodeError) as ex:
            # Handle Unicode errors at the socket level
            # This provides an additional safety layer
            logging.warning("UnicodeDecodeError in recv: %s", ex)
            return None
        except Exception as ex:
            logging.exception("recv() failed: %s", ex)
            return None

    def close(self):
        """Override close to prevent premature socket closure.

        This method marks the socket as closed internally but doesn't actually
        close the underlying socket immediately. This prevents issues with
        premature closure during active packet processing.
        """
        # Set internal flag instead of actually closing
        # This prevents operations on a closed socket while maintaining stability
        self._closed = True
        # Intentionally not calling super().close() to prevent premature closure

    def fileno(self):
        """Get the socket file descriptor with error handling.

        This method safely retrieves the socket file descriptor, which is
        used for socket operations and select() calls. Returns a safe default
        if the underlying socket is not available.

        Returns:
            int: Socket file descriptor number, or -1 if unavailable.

        Raises:
            Does not raise exceptions - errors return -1 as safe default.
        """
        try:
            # Get file descriptor from parent socket implementation
            return super().fileno()
        except Exception:
            # Return -1 as a safe default for invalid file descriptors
            # This prevents select() and other operations from failing
            return -1


# pylint: disable=too-few-public-methods
class LiveInputHandler(InputHandler):
    """Live network interface input handler.

    Handles real-time packet capture from network interfaces using scapy.
    Provides robust packet capture with BPF filtering support and graceful
    handling of interruptions and errors during live capture sessions.
    """

    def __init__(self, interface: str):
        """Initialize live input handler.

        Sets up the handler for capturing packets from a specific network
        interface. The interface must be available and accessible for
        packet capture operations.

        Args:
            interface (str): Network interface name to capture from
                (e.g., 'eth0', 'wlan0', 'enp0s3').
        """
        self.interface = interface

    def start_capture(self, packet_callback: Callable, bpf_filter: str) -> int:
        """Start live packet capture from network interface.

        Begins capturing packets from the configured network interface using
        the custom L2ListenSocket for enhanced error handling. Supports BPF
        filtering and processes packets through the provided callback function.
        Handles KeyboardInterrupt gracefully for clean shutdown.

        Args:
            packet_callback (Callable): Function to call for each captured
                packet. Should accept a single packet argument.
            bpf_filter (str): Berkeley Packet Filter expression to apply
                during capture. Empty string means no filtering.

        Returns:
            int: 0 on successful completion or graceful interruption,
                -1 on error during capture setup or execution.
        """
        logging.info("Sniffing on %s, filter: '%s' ...", self.interface, bpf_filter)
        try:
            l2socket_class = partial(MyL2ListenSocket, filter=bpf_filter)
            sniff(iface=self.interface, L2socket=l2socket_class, prn=packet_callback, store=False)
            return 0
        except KeyboardInterrupt:
            logging.info("Stopping live capture...")
            return 0
        except Exception as ex:
            logging.exception("Error during live sniffing: %s", ex)
            return -1
