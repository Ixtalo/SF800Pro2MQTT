#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""PCAP network packet processor."""
from datetime import datetime
import json
import logging
import time
from collections import defaultdict
from typing import Dict

from scapy.all import Packet, wrpcap
from scapy.error import Scapy_Exception
from scapy.contrib.mqtt import MQTT

from .config import Config


def _is_corrupted_topic(topic: str) -> bool:
    """Check if topic contains JSON payload fragments indicating corruption."""
    corruption_indicators = [
        '"deviceId":',
        '"packData":[{"sn":',
    ]
    return any(indicator in topic for indicator in corruption_indicators)


class InvalidMqttPacketError(Exception):
    """Custom exception raised when an MQTT packet is invalid or malformed."""

    # The type/category of the MQTT packet error
    error_type_name: str

    def __init__(self, error_type_name: str, *args: object) -> None:
        """
        Initialize the InvalidMqttPacketError exception.

        Args:
            error_type_name (str): Descriptive name of the specific error type
                                 (e.g., "MALFORMED_HEADER", "INVALID_QOS")
            *args: Additional arguments to pass to the parent Exception class
        """
        self.error_type_name = error_type_name
        super().__init__(*args)


class PacketProcessor:
    """Handles packet processing with encapsulated state."""

    def __init__(self, config: Config, output_handler):
        """Initialize packet processor.

        Args:
            config: Application configuration
            output_handler: Output handler for publishing messages
        """
        self.output_handler = output_handler
        self.last_pub_per_topic: Dict[str, float] = defaultdict(lambda: 0.0)
        self.config = config

    def packet_callback(self, pkt):
        """Handle callback function for each packet captured by scapy."""
        mqtt_layer = pkt.getlayer(MQTT)
        if not (mqtt_layer and mqtt_layer.type == 3):  # PUBLISH
            logging.debug("Ignoring non MQTT-PUBLISH packet: %s", pkt.summary())
        else:
            try:
                topic, payload = self.handle_mqtt_packet(mqtt_layer)
                if topic and payload:
                    if topic in self.config.topics_blacklist:
                        logging.info("Topic '%s' is blacklisted - skipping!", topic)
                    else:
                        # Add MQTT topic prefix if configured
                        if self.config.mqtt_topic_prefix:
                            topic = f"{self.config.mqtt_topic_prefix}/{topic.lstrip('/')}"
                        self.publish_with_throttling(topic, payload)
            except InvalidMqttPacketError as ex:
                if self.config.output_dir:
                    # Saving raw packet to disk for debugging purposes
                    self.save_packet(pkt, suffix=ex.error_type_name)

    def handle_mqtt_packet(self, mqtt_pkt) -> tuple[str, str] | tuple[str, None] | tuple[None, None]:
        """Handle MQTT packet and extract topic and payload."""
        assert mqtt_pkt.type == 3, "Packet must be MQTT PUBLISH packet!"

        # do not do "topic = mqtt_pkt.topic" because it could fail for faulty packets
        topic = getattr(mqtt_pkt, "topic", None)
        if topic is None:
            logging.warning("MQTT packet without topic field: %s", mqtt_pkt.fields)
            raise InvalidMqttPacketError("no-topic")
        if isinstance(topic, bytes):
            try:
                topic = topic.decode("utf8")
            except UnicodeDecodeError as ex:
                raise InvalidMqttPacketError("topic-decode-problem") from ex

        # do not do "payload = mqtt_pkt.payload.value" because it could fail for faulty packets
        payload = getattr(mqtt_pkt, "payload", None)
        if payload is None:
            logging.warning("MQTT packet without payload field: %s", mqtt_pkt.fields)
            raise InvalidMqttPacketError("payload-empty")
        try:
            value = payload.value
            if isinstance(value, bytes):
                value = value.decode("utf-8")
            payload_json = json.loads(value)
        except UnicodeDecodeError as ex:
            logging.warning("Payload decode failed for topic '%s': %s", topic, ex)
            raise InvalidMqttPacketError("payload-decode") from ex
        except json.JSONDecodeError as ex:
            if _is_corrupted_topic(topic):
                # sometimes the topic is garbaged with parts of the MQTT payload
                # just log it with DEBUG level
                log_func = logging.debug
            else:
                log_func = logging.warning
            log_func("Could not JSON decode payload for topic '%s': %s", topic, ex)
            raise InvalidMqttPacketError("payload-json") from ex

        if not payload_json:
            logging.warning("Ignoring packet with empty JSON payload for topic '%s'", topic)
            return topic, None

        # Check for irrelevant messages
        if (
            "properties" in payload_json
            and len(payload_json["properties"]) <= 1     # noqa: W503
            and "packNum" in payload_json["properties"]  # noqa: W503
        ):
            logging.info("Ignoring message with only single packNum property for topic '%s'", topic)
            return topic, None

        # Compact JSON serialization
        payload_compact = json.dumps(payload_json, separators=(',', ':'))
        return topic, payload_compact

    def publish_with_throttling(self, topic: str, payload: str):
        """Publish message with throttling based on publish period."""
        now = time.time()
        last_pub_secs = now - self.last_pub_per_topic[topic]

        if last_pub_secs < self.config.publish_period_seconds:
            logging.debug("Skipping publishing topic '%s' (last published %.1f seconds ago)",
                          topic, last_pub_secs)
        else:
            self.last_pub_per_topic[topic] = now
            logging.info("Publishing topic '%s' ...", topic)
            self.output_handler.publish(topic, payload)

    def save_packet(self, packet: Packet, suffix: str = ""):
        """Save raw packet to disk for debugging purposes."""
        assert self.config.output_dir
        # Generate filename with timestamp including milliseconds
        # Format: YYYYMMDD_HHMMSS_mmm (year, month, day, hour, minute, second, milliseconds)
        # Remove last 3 digits to get milliseconds instead of microseconds
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")[:-3]
        # Generate filename with optional error type classification
        error_suffix = f"_{suffix}" if suffix else ""
        filename = self.config.output_dir.joinpath(f"{timestamp}_mqttpkt{error_suffix}.pcap")
        try:
            # save in PCAP format
            wrpcap(str(filename), packet)
            logging.info("PCAP packet saved to: %s", filename.resolve)
        except Scapy_Exception as ex:
            logging.error("Failed to save raw packet: %s", ex)
