# -*- coding: utf-8 -*-

import json
from unittest.mock import MagicMock

import pytest
from scapy.all import (  # type: ignore # noqa: F401, pylint: disable=no-name-in-module
    IP, TCP)
from scapy.contrib.mqtt import MQTT, MQTTPublish

from sf800p2mqtt.config import Config
from sf800p2mqtt.packet_processor import PacketProcessor


@pytest.fixture()
def processor():
    config = Config(
        filter_ip="192.168.1.100",
        mqtt_host="127.0.0.1",
        mqtt_port=1883,
        mqtt_user=None,
        mqtt_pass=None,
        mqtt_topic_prefix="",
        publish_period_seconds=30,
        topics_blacklist=set()
    )
    instance = PacketProcessor(config, None)
    return instance


class TestHandleMqttPkt:
    """Test cases for handle_mqtt_packet function."""

    @staticmethod
    def test_handle_mqtt_packet_emptyvalue(processor):
        # prepare
        pkt = MQTT(type=3) / MQTTPublish(topic="/foo/bar", value=b"")
        # action
        topic, payload = processor.handle_mqtt_packet(pkt)
        # check
        assert topic == "/foo/bar"
        assert not payload

    @staticmethod
    def test_handle_mqtt_packet_emptyjson(processor):
        # prepare
        pkt = MQTT(type=3) / MQTTPublish(topic="/foo/bar", value=b"{}")
        # action
        topic, payload = processor.handle_mqtt_packet(pkt)
        # check
        assert topic == "/foo/bar"
        assert not payload

    @staticmethod
    def test_handle_mqtt_packet_invalidjson(processor):
        # prepare
        pkt = MQTT(type=3) / MQTTPublish(topic="/foo/bar", value=b"{invalidjson}")
        # action
        topic, payload = processor.handle_mqtt_packet(pkt)
        # check
        assert topic == "/foo/bar"
        assert not payload

    @staticmethod
    def test_handle_mqtt_packet_porpertiesonly1(processor):
        # prepare
        payload_inp = {"properties": {"onlyone": "field"}}
        pkt = MQTT(type=3) / MQTTPublish(topic="/foo/bar", value=json.dumps(payload_inp))
        # action
        topic, payload = processor.handle_mqtt_packet(pkt)
        # check
        assert topic == '/foo/bar'
        assert payload == '{"properties":{"onlyone":"field"}}'

    @staticmethod
    def test_handle_mqtt_packet_porpertiesonly1packnum(processor):
        # prepare
        payload_inp = {"properties": {"packNum": 123}}
        pkt = MQTT(type=3) / MQTTPublish(topic="/foo/bar", value=json.dumps(payload_inp))
        # action
        topic, payload = processor.handle_mqtt_packet(pkt)
        # check
        assert topic == "/foo/bar"
        assert not payload

    @staticmethod
    def test_handle_mqtt_packet_notopic(processor):
        # prepare
        pkt = MQTT(type=3) / MQTTPublish()
        # action
        topic, payload = processor.handle_mqtt_packet(pkt)
        # check
        assert not topic
        assert not payload


class TestPackketCallback:
    """Test cases for pkt_cb function."""

    @staticmethod
    def test_pkt_cb_publishes(monkeypatch, processor):
        exp_topic = "/foo/bar"
        exp_payload = {"messageId": 123, "value": 42}
        pkt = MQTT(type=3) / MQTTPublish(topic=exp_topic, value=json.dumps(exp_payload))

        # publish mock
        published = []
        monkeypatch.setattr(PacketProcessor, "publish_with_throttling",
                            lambda _, t, p: published.append((t, p)))

        # call
        processor.packet_callback(pkt)

        # expect: published with topic and payload
        assert published == [('/foo/bar', '{"messageId":123,"value":42}')]

    @staticmethod
    def test_pkt_cb_ignores_other_packets(monkeypatch, processor):
        # packet without raw layer
        pkt = IP() / TCP()

        spy = MagicMock()
        monkeypatch.setattr(PacketProcessor, "publish_with_throttling", spy)

        # action
        processor.packet_callback(pkt)

        # check
        spy.assert_not_called()

    @staticmethod
    def test_pkt_cb_publishes_empty_payload(monkeypatch, processor):
        exp_topic = "/foo/bar"
        pkt = MQTT(type=3) / MQTTPublish(topic=exp_topic, value='{}')

        # publish mock
        published = []
        monkeypatch.setattr(PacketProcessor, "publish_with_throttling",
                            lambda t, p: published.append((t, p)))

        # call
        processor.packet_callback(pkt)

        # expect: not published, because payload is empty
        assert not published

    @staticmethod
    def test_pkt_cb_publishes_invalid_payload(monkeypatch, processor):
        exp_topic = "/foo/bar"
        pkt = MQTT(type=3) / MQTTPublish(topic=exp_topic, value='{invalid}')

        # publish mock
        published = []
        monkeypatch.setattr(PacketProcessor, "publish_with_throttling",
                            lambda t, p: published.append((t, p)))

        # call
        processor.packet_callback(pkt)

        # expect: not published, because payload is invalid JSON
        assert not published

    @staticmethod
    def test_pkt_cb_publishes_propertiesonlypacknum(monkeypatch, processor):
        exp_topic = "/foo/bar"
        exp_payload = {"properties": {"packNum": 42}}
        pkt = MQTT(type=3) / MQTTPublish(topic=exp_topic, value=json.dumps(exp_payload))

        # publish mock
        published = []
        monkeypatch.setattr(PacketProcessor, "publish_with_throttling",
                            lambda t, p: published.append((t, p)))

        # call
        processor.packet_callback(pkt)

        # expect: not published, because it contains only one property,
        # and that property is 'packNum'
        assert not published

    @staticmethod
    def test_pkt_cb_publishes_topicblacklist(monkeypatch, processor):
        exp_topic = "/foo/bar"
        exp_payload = {"properties": {"foo": 42}}
        pkt = MQTT(type=3) / MQTTPublish(topic=exp_topic, value=json.dumps(exp_payload))

        # monkeypatch.setattr(processor, "_topics_blacklist", ['/foo/bar'])
        processor.topics_blacklist = {'/foo/bar'}

        # publish mock
        published = []
        monkeypatch.setattr(PacketProcessor, "publish_with_throttling",
                            lambda t, p: published.append((t, p)))

        # call
        processor.packet_callback(pkt)

        # expect: not published, because of blacklisted topic
        assert not published

    @staticmethod
    def test_pkt_cb_publishes_topicblacklist_string(monkeypatch, processor):
        exp_topic = "/foo/bar"
        exp_payload = {"properties": {"foo": 42}}
        pkt = MQTT(type=3) / MQTTPublish(topic=exp_topic, value=json.dumps(exp_payload))

        processor.topics_blacklist = '/foo/bar'  # invalid type: a simple string, not an array

        # publish mock
        published = []
        monkeypatch.setattr(PacketProcessor, "publish_with_throttling",
                            lambda t, p: published.append((t, p)))

        # call
        processor.packet_callback(pkt)

        # expect: not published, because of blacklisted topic
        assert not published

    @staticmethod
    def test_pkt_cb_publishes_topicprefix(monkeypatch, processor):
        exp_topic = "/foo/bar"
        exp_payload = {"properties": {"foo": 42}}
        pkt = MQTT(type=3) / MQTTPublish(topic=exp_topic, value=json.dumps(exp_payload))

        processor.mqtt_topic_prefix = "prefix"

        # publish mock
        published = []
        monkeypatch.setattr(PacketProcessor, "publish_with_throttling",
                            lambda _, t, p: published.append((t, p)))

        # call
        processor.packet_callback(pkt)

        # check
        assert published == [('prefix/foo/bar', '{"properties":{"foo":42}}')]
