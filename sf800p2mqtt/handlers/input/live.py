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

from sf800p2mqtt.handlers.base import InputHandler


class MyL2ListenSocket(L2ListenSocket):
    """Enhanced L2 listen socket with exception handling.

    Custom implementation of L2ListenSocket that provides robust error
    handling for packet reception. Catches and logs common exceptions
    like UnicodeDecodeError to prevent capture interruption.
    """

    def recv(self, x: int = MTU, **kwargs) -> Packet | None:
        """Override the recv method and catches exceptions.

        Receives packets from the network interface with enhanced error
        handling. Catches UnicodeDecodeError and other exceptions that
        might occur during packet reception, logging them appropriately
        while allowing capture to continue.

        Args:
            x (int, optional): The number of bytes to read from the socket.
                Defaults to MTU (Maximum Transmission Unit).
            **kwargs: Additional keyword arguments passed to parent recv method.

        Returns:
            Packet | None: The received packet if no error occurs, None if
                an error is encountered during reception.
        """
        try:
            return super().recv(x, **kwargs)
        except UnicodeDecodeError as ex:
            logging.warning("UnicodeDecodeError when receiving bytes: %s", ex)
        except Exception as ex:
            logging.exception("recv() failed: %s", ex)
        return None


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
