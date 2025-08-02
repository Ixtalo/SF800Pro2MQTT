# -*- coding: utf-8 -*-
"""Factory module for creating output handler instances."""
from sf800p2mqtt.constants import OutputType
from sf800p2mqtt.handlers.base import OutputHandler
from sf800p2mqtt.handlers.output.mqtt import MqttOutputHandler
from sf800p2mqtt.handlers.output.stdout import StdoutOutputHandler


class OutputHandlerFactory:
    """Factory for creating output handlers."""

    @staticmethod
    def create_handler(output_type: OutputType, **kwargs) -> OutputHandler:
        """Create an output handler based on the specified type.

        Args:
            output_type: Type of output handler to create
            **kwargs: Additional arguments for handler initialization

        Returns:
            OutputHandler: The created output handler

        Raises:
            ValueError: If output_type is not supported
        """
        if output_type == OutputType.MQTT:
            return MqttOutputHandler(
                host=kwargs.get('mqtt_host', '127.0.0.1'),
                port=kwargs.get('mqtt_port', 1883),
                username=kwargs.get('mqtt_user'),
                password=kwargs.get('mqtt_pass')
            )
        if output_type == OutputType.STDOUT:
            return StdoutOutputHandler()
        # else
        raise ValueError(f"Unsupported output type: {output_type}")
