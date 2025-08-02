# -*- coding: utf-8 -*-
"""Factory module for creating input handler instances.

This module provides a factory class for creating appropriate input handler
instances based on the input type and source parameters. Supports creation
of handlers for PCAP files and live network interfaces.
"""
from pathlib import Path

from sf800p2mqtt.constants import InputType
from sf800p2mqtt.handlers.base import InputHandler
from sf800p2mqtt.handlers.input.live import LiveInputHandler
from sf800p2mqtt.handlers.input.pcap_file import PcapInputHandler


class InputHandlerFactory:
    """Factory for creating input handlers.

    Provides a centralized factory for creating input handler instances
    based on the specified input type and source. Encapsulates the logic
    for determining which handler class to instantiate and how to configure
    it based on the input parameters.
    """

    @staticmethod
    def create_handler(input_type: InputType, source: str) -> InputHandler:
        """Create an input handler based on parameters.

        Factory method that creates and returns an appropriate input handler
        instance based on the specified input type and source. The source
        parameter is interpreted differently depending on the input type:
        for PCAP files it should be a file path, for interfaces it should
        be the interface name.

        Args:
            input_type (InputType): The type of input handler to create.
                Should be one of InputType.PCAP_FILE or InputType.INTERFACE.
            source (str): The source specification for the handler.
                For PCAP_FILE: path to the PCAP file to read.
                For INTERFACE: name of the network interface to capture from.

        Returns:
            InputHandler: The created input handler instance configured
                for the specified input type and source.

        Raises:
            ValueError: If the input_type is not supported or recognized.
        """
        if input_type == InputType.PCAP_FILE:
            return PcapInputHandler(pcap_file=Path(source))
        if input_type == InputType.INTERFACE:
            return LiveInputHandler(interface=source)
        # else
        raise ValueError(f"Unsupported input type: {input_type}")
