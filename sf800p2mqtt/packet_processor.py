#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""PCAP network packet processor."""
import json
import logging
import time
from collections import defaultdict
from typing import Dict

from scapy.contrib.mqtt import MQTT

from .config import Config


class PacketProcessor:
    """Handles packet processing with encapsulated state."""

    def __init__(self, config: Config, output_handler):
        """Initialize packet processor.

        Args:
            config: Application configuration
            output_handler: Output handler for publishing messages
        """
        self.output_handler = output_handler
        self.publish_period_seconds = config.publish_period_seconds
        self.mqtt_topic_prefix = config.mqtt_topic_prefix
        self.topics_blacklist = config.topics_blacklist
        self.last_pub_per_topic: Dict[str, float] = defaultdict(lambda: 0.0)

    def packet_callback(self, pkt):
        """Handle callback function for each packet captured by scapy."""
        mqtt_layer = pkt.getlayer(MQTT)
        if mqtt_layer and mqtt_layer.type == 3:  # PUBLISH
            topic, payload = self.handle_mqtt_packet(mqtt_layer)
            if topic and payload:
                if topic in self.topics_blacklist:
                    logging.info("Topic '%s' is blacklisted - skipping!", topic)
                else:
                    # Add MQTT topic prefix if configured
                    if self.mqtt_topic_prefix:
                        topic = f"{self.mqtt_topic_prefix}/{topic.lstrip('/')}"
                    self.publish_with_throttling(topic, payload)
        else:
            logging.debug("Ignoring non MQTT-PUBLISH packet: %s", pkt.summary())

    def handle_mqtt_packet(self, mqtt_pkt) -> tuple[str, str] | tuple[str, None] | tuple[None, None]:
        """Handle MQTT packet and extract topic and payload."""
        assert mqtt_pkt.type == 3, "Packet must be MQTT PUBLISH packet!"

        topic = mqtt_pkt.topic
        payload = mqtt_pkt.payload.value

        if not topic:
            logging.warning("No MQTT topic found in packet!")
            return None, None

        if isinstance(topic, bytes):
            topic = topic.decode("utf8")

        if not payload:
            logging.warning("Empty payload for topic '%s'", topic)
            return topic, None

        try:
            payload_json = json.loads(payload)
        except json.JSONDecodeError as ex:
            logging.warning("Invalid JSON payload for topic '%s': %s", topic, ex)
            return topic, None

        if not payload_json:
            logging.warning("Empty JSON payload for topic '%s'", topic)
            return topic, None

        # Check for irrelevant messages
        if (
            "properties" in payload_json
            and len(payload_json["properties"]) <= 1     # noqa: W503
            and "packNum" in payload_json["properties"]  # noqa: W503
        ):
            logging.info("Ignoring irrelevant message for topic '%s'", topic)
            return topic, None

        # Compact JSON serialization
        payload_compact = json.dumps(payload_json, separators=(',', ':'))
        return topic, payload_compact

    def publish_with_throttling(self, topic: str, payload: str):
        """Publish message with throttling based on publish period."""
        now = time.time()
        last_pub_secs = now - self.last_pub_per_topic[topic]

        if last_pub_secs < self.publish_period_seconds:
            logging.debug("Skipping publishing topic '%s' (last published %.1f seconds ago)",
                          topic, last_pub_secs)
        else:
            self.last_pub_per_topic[topic] = now
            logging.info("Publishing topic '%s' ...", topic)
            self.output_handler.publish(topic, payload)
