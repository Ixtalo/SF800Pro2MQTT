# -*- coding: utf-8 -*-
"""MQTT output handler for publishing messages to MQTT brokers.

This module provides an MQTT-based output handler that can connect to
MQTT brokers and publish messages with automatic reconnection capabilities.
"""
import logging
from time import sleep

import paho.mqtt.client as mqtt

from sf800p2mqtt.handlers.base import OutputHandler


class MqttOutputHandler(OutputHandler):
    """MQTT output handler implementation.

    Handles publishing messages to MQTT brokers with automatic connection
    management and reconnection logic. Supports authentication and provides
    robust error handling for network failures.
    """

    def __init__(self, host="127.0.0.1", port=1883, username=None, password=None):
        """Initialize MQTT output handler.

        Creates a new MQTT client instance and configures connection parameters.
        Authentication credentials are optional and will be used if both
        username and password are provided.

        Args:
            host (str, optional): MQTT broker hostname or IP address.
                Defaults to "127.0.0.1".
            port (int, optional): MQTT broker port number. Defaults to 1883.
            username (str, optional): MQTT authentication username.
                Defaults to None.
            password (str, optional): MQTT authentication password.
                Defaults to None.
        """
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2)     # type: ignore
        self._setup_callbacks()

    def _setup_callbacks(self):
        """Set up MQTT client callbacks.

        Configures the MQTT client with connection and disconnection callback
        handlers. Also sets up authentication credentials if both username
        and password are provided.
        """
        self.client.on_connect = self._on_connect
        self.client.on_disconnect = self._on_disconnect
        if self.username and self.password:
            self.client.username_pw_set(self.username, self.password)

    def _on_connect(self, client, *_):
        """Handle callback for MQTT connection established.

        Called when the MQTT client successfully connects to the broker.
        Logs the successful connection event.

        Args:
            client: The MQTT client instance that connected.
            *_: Additional callback arguments (unused).
        """
        logging.info("MQTT connected (%s)", client)

    def _on_disconnect(self, client, _userdata, _flags, rc, _properties):
        """Handle callback for MQTT disconnection.

        Called when the MQTT client disconnects from the broker. Implements
        automatic reconnection logic with simple retry mechanism. Will
        continuously attempt to reconnect with 5-second delays between
        attempts.

        Args:
            client: The MQTT client instance that disconnected.
            _userdata: User data (unused).
            _flags: Disconnect flags (unused).
            rc: Disconnect reason code.
            _properties: MQTT v5 properties (unused).
        """
        logging.warning("MQTT disconnected (rc=%s) – retrying ...", rc)
        # Simple retry loop; exponential back-off would be nicer
        while True:
            try:
                client.reconnect()
                return
            except Exception as e:  # pylint: disable=broad-except
                logging.error("Reconnect failed: %s", e)
                sleep(5)

    def connect(self) -> bool:
        """Connect to MQTT broker.

        Establishes connection to the configured MQTT broker and starts
        the client loop for handling network traffic. Connection uses
        a 60-second keepalive interval.

        Returns:
            bool: True if connection was successful, False otherwise.
        """
        try:
            self.client.connect(self.host, self.port, keepalive=60)
            self.client.loop_start()
            return True
        except Exception as e:  # pylint: disable=broad-except
            logging.error("Failed to connect to MQTT broker: %s", e)
            return False

    def publish(self, topic: str, payload: str) -> bool:
        """Publish message to MQTT broker.

        Sends a message to the specified MQTT topic. Messages are published
        with QoS level 0 (at most once delivery) and retain flag set to False.

        Args:
            topic (str): MQTT topic to publish to.
            payload (str): Message payload to publish.

        Returns:
            bool: True if publish was successful, False otherwise.
        """
        try:
            self.client.publish(topic, payload, qos=0, retain=False)
            return True
        except Exception as e:  # pylint: disable=broad-except
            logging.error("MQTT publish failed: %s", e)
            return False

    def disconnect(self):
        """Disconnect from MQTT broker.

        Cleanly shuts down the MQTT client by stopping the network loop
        and disconnecting from the broker. Handles any exceptions that
        may occur during the disconnection process.
        """
        try:
            self.client.loop_stop()
            self.client.disconnect()
        except Exception as e:  # pylint: disable=broad-except
            logging.error("MQTT disconnect failed: %s", e)
