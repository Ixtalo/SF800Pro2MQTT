# -*- coding: utf-8 -*-
"""PCAP file input handler for reading packet captures from files.

This module provides functionality to read and process network packet
captures from PCAP files using scapy with support for BPF filtering.
"""
import logging
from pathlib import Path
from typing import Callable

from scapy.all import sniff

from sf800p2mqtt.handlers.base import InputHandler


class PcapInputHandler(InputHandler):
    """PCAP file input handler.

    Handles reading network packet captures from PCAP files with support
    for BPF filtering and callback-based packet processing. Provides
    validation to ensure the specified PCAP file exists before processing.
    """

    def __init__(self, pcap_file: Path):
        """Initialize PCAP input handler.

        Validates that the specified PCAP file exists and is accessible.
        Raises an exception if the file cannot be found.

        Args:
            pcap_file (Path): Path to PCAP file to read.

        Raises:
            FileNotFoundError: If the specified PCAP file does not exist.
        """
        self.pcap_file = pcap_file
        if not pcap_file.exists():
            raise FileNotFoundError(f"PCAP file not found: {pcap_file.resolve()}")

    def start_capture(self, packet_callback: Callable, bpf_filter: str) -> int:
        """Start packet capture from PCAP file.

        Reads packets from the PCAP file and processes them through the
        provided callback function. Supports BPF filtering to process
        only packets matching specific criteria.

        Args:
            packet_callback (Callable): Function to call for each packet.
                Should accept a single packet argument.
            bpf_filter (str): BPF filter expression to apply to packets.
                Empty string means no filtering.

        Returns:
            int: 0 on successful completion, -1 on error.
        """
        logging.info("Reading PCAP file '%s', filter: '%s' ...", self.pcap_file.name, bpf_filter)
        try:
            sniff(offline=str(self.pcap_file), prn=packet_callback, filter=bpf_filter)
            logging.info("Finished reading PCAP file")
            return 0
        except Exception as ex:
            logging.exception("Error reading PCAP file: %s", ex)
            return -1
