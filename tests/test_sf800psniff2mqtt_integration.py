# -*- coding: utf-8 -*-
"""
Pytest unit tests to verify the behavior of the InputHandler and OutputHandler
in the run() function while also using mocked packet processing.

These tests simulate a single packet that is received and processed through the
packet callback (pkt_cb), then verify that a publish call is made via the
dummy output handler.
"""
import json

import pytest

import sf800p2mqtt.sf800psniff2mqtt as sm
from sf800p2mqtt.config import Config
from sf800p2mqtt.handlers.input.factory import InputHandlerFactory
from sf800p2mqtt.handlers.input.live import LiveInputHandler
from sf800p2mqtt.handlers.input.pcap_file import PcapInputHandler
from sf800p2mqtt.handlers.output.factory import OutputHandlerFactory
from sf800p2mqtt.handlers.output.mqtt import MqttOutputHandler
from sf800p2mqtt.handlers.output.stdout import StdoutOutputHandler


# pylint: disable=too-few-public-methods,missing-function-docstring,redefined-outer-name


@pytest.fixture
def test_config():
    """Provide a minimal Config object for testing."""
    return Config(
        filter_ip="192.168.3.100",
        mqtt_host="127.0.0.1",
        mqtt_port=1883,
        mqtt_user=None,
        mqtt_pass=None,
        mqtt_topic_prefix="",
        publish_period_seconds=30,
        topics_blacklist=set()
    )


class DummyPayload:
    """
    Dummy payload class to simulate an MQTT packet payload.
    The attribute 'value' should hold a JSON string.
    """
    value = '{"properties": {"packNum": 2, "data": "value"}}'


class DummyMqttLayer:
    """
    Dummy MQTT layer to simulate a valid MQTT PUBLISH packet.
    Attributes:
      - type: Indicates the MQTT packet type (3 for PUBLISH).
      - topic: The MQTT topic in bytes.
      - payload: An object with a 'value' attribute containing JSON.
    """
    type = 3
    topic = b"/test/topic"
    payload = DummyPayload()


class DummyPacket:
    """
    Dummy packet that simulates a Scapy packet.
    It provides the method getlayer() so that when called with the MQTT layer,
    it returns our dummy MQTT layer.
    """

    def __init__(self, mqtt_layer):
        self._mqtt_layer = mqtt_layer

    def getlayer(self, _layer):
        # If the requested layer is MQTT, return our dummy MQTT layer.
        return self._mqtt_layer

    def summary(self):
        return "DummyPacket summary for testing"


class DummyOutputHandler(sm.OutputHandler):
    """Dummy output handler that records publish calls."""

    def __init__(self):
        self.calls = []  # List to record (topic, payload) tuples
        self.connected = False

    def connect(self) -> bool:
        """Simulate successful connection."""
        self.connected = True
        return True

    def publish(self, topic: str, payload: str) -> bool:
        """Record publish calls."""
        self.calls.append((topic, payload))
        return True

    def disconnect(self):
        """Simulate disconnection."""
        self.connected = False


class DummyInputHandler(sm.InputHandler):
    """Dummy input handler that simulates packet capture."""

    def __init__(self, packets_to_send=None):
        self.packets_to_send = packets_to_send or []

    def start_capture(self, packet_callback, bpf_filter: str) -> int:
        """Simulate packet capture by calling callback with dummy packets."""
        # Process each packet through the callback
        for packet in self.packets_to_send:
            packet_callback(packet)
        return 0


def test_run_with_input_output_handlers(test_config):
    """
    Test that run() correctly processes packets through InputHandler
    and publishes via OutputHandler.
    """
    # Create dummy MQTT layer and packet
    dummy_mqtt = DummyMqttLayer()
    dummy_packet = DummyPacket(dummy_mqtt)

    # Create dummy handlers
    input_handler = DummyInputHandler([dummy_packet])
    output_handler = DummyOutputHandler()

    # Run the run() method
    result = sm.run(
        config=test_config,
        input_handler=input_handler,
        output_handler=output_handler
    )

    # Expect run() to return 0 upon graceful shutdown
    assert result == 0, "Expected run() to return 0 on graceful shutdown (KeyboardInterrupt)."

    # Verify that output handler was connected
    assert not output_handler.connected, "Output handler should be disconnected after run()"

    # Verify that a publish call was made
    publish_calls = output_handler.calls
    assert publish_calls, "Expected at least one publish call after processing the packet."

    # Verify the published topic and payload
    published_topic, published_payload = publish_calls[0]
    expected_topic = "/test/topic"
    assert published_topic == expected_topic, (
        f"Expected topic '{expected_topic}', got '{published_topic}'."
    )

    # Check that the payload is valid compact JSON
    payload_obj = json.loads(published_payload)
    assert "properties" in payload_obj, "The published payload should contain 'properties'."


def test_run_with_mqtt_topic_prefix(test_config):
    """
    Test that run() correctly applies MQTT topic prefix.
    """
    # Set global MQTT topic prefix
    test_config.mqtt_topic_prefix = 'solarflow'

    # Create dummy MQTT layer and packet
    dummy_mqtt = DummyMqttLayer()
    dummy_packet = DummyPacket(dummy_mqtt)

    # Create dummy handlers
    input_handler = DummyInputHandler([dummy_packet])
    output_handler = DummyOutputHandler()

    # Run the run() method
    result = sm.run(
        config=test_config,
        input_handler=input_handler,
        output_handler=output_handler
    )
    assert result == 0

    # Verify the published topic includes prefix
    publish_calls = output_handler.calls
    assert publish_calls, "Expected at least one publish call."

    published_topic, _ = publish_calls[0]
    expected_topic = "solarflow/test/topic"
    assert published_topic == expected_topic, (
        f"Expected topic '{expected_topic}', got '{published_topic}'."
    )


def test_run_with_blacklisted_topic(test_config):
    """
    Test that run() correctly filters out blacklisted topics.
    """
    # Set topics blacklist
    test_config.topics_blacklist = {'/test/topic'}

    # Create dummy MQTT layer and packet
    dummy_mqtt = DummyMqttLayer()
    dummy_packet = DummyPacket(dummy_mqtt)

    # Create dummy handlers
    input_handler = DummyInputHandler([dummy_packet])
    output_handler = DummyOutputHandler()

    # Run the run() method
    result = sm.run(
        config=test_config,
        input_handler=input_handler,
        output_handler=output_handler
    )
    assert result == 0

    # Verify that no publish calls were made (topic was blacklisted)
    publish_calls = output_handler.calls
    assert not publish_calls, "Expected no publish calls for blacklisted topic."


def test_output_handler_connection_failure(test_config):
    """
    Test that run() handles output handler connection failure gracefully.
    """
    input_handler = DummyInputHandler([])

    class FailingOutputHandler(DummyOutputHandler):
        """Dummy class which always fails to connect."""

        def connect(self) -> bool:
            return False

    output_handler = FailingOutputHandler()

    # Run the run() method
    result = sm.run(
        config=test_config,
        input_handler=input_handler,
        output_handler=output_handler
    )

    # Expect run() to return -1 on connection failure
    assert result == -1, "Expected run() to return -1 on output handler connection failure."


def test_input_handler_factory(tmp_path):
    """
    Test InputHandlerFactory creates correct handler types.
    """
    # Test live input handler creation
    live_handler = InputHandlerFactory.create_handler(sm.InputType.INTERFACE, source="wlan0")
    assert isinstance(live_handler, LiveInputHandler)
    assert live_handler.interface == "wlan0"

    tmp_file = tmp_path.joinpath("dummy.pcap")
    with tmp_file.open("+a") as fout:
        fout.write("dummy")

    pcap_handler = InputHandlerFactory.create_handler(sm.InputType.PCAP_FILE, source=str(tmp_file))
    assert isinstance(pcap_handler, PcapInputHandler)
    assert pcap_handler.pcap_file == tmp_file


def test_output_handler_factory():
    """
    Test OutputHandlerFactory creates correct handler types.
    """
    # Test MQTT output handler creation
    mqtt_handler = OutputHandlerFactory.create_handler(
        sm.OutputType.MQTT,
        mqtt_host="localhost",
        mqtt_port=1883,
        mqtt_user="test",
        mqtt_pass="pass"
    )
    assert isinstance(mqtt_handler, MqttOutputHandler)
    assert mqtt_handler.host == "localhost"
    assert mqtt_handler.port == 1883

    # Test STDOUT output handler creation
    stdout_handler = OutputHandlerFactory.create_handler(sm.OutputType.STDOUT)
    assert isinstance(stdout_handler, StdoutOutputHandler)
