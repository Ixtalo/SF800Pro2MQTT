# -*- coding: utf-8 -*-
"""
pytest unit tests
"""
import json
import os
from io import StringIO
from unittest.mock import MagicMock

import pytest
from scapy.all import IP, TCP   # noqa: F401, pylint: disable=no-name-in-module
from scapy.contrib.mqtt import MQTT, MQTTPublish

import sf800psniff2mqtt as sm
from sf800psniff2mqtt import json_dumps_compact, handle_mqtt_pkt, has_cap_net_raw


# pylint: disable=missing-function-docstring, missing-module-docstring, unused-argument


# Run tests with logging DEBUG
# pytest -o log_cli_level=DEBUG -o log_cli_handler=stream -o log_cli=1


@pytest.fixture(scope="session", autouse=True)
def set_environment_variable():
    os.environ["FILTER_IP"] = "192.168.3.100"
    print("\nEnvironment variable FILTER_IP set to:", os.environ["FILTER_IP"])

    yield  # run test

    # cleanup
    del os.environ["FILTER_IP"]
    print("\nEnvironment variable FILTER_IP removed.")


def test_environment_variable():
    assert os.environ["FILTER_IP"] == "192.168.3.100"


class TestJsonCompact:
    """Test cases for json_dumps_compact function."""

    @staticmethod
    def test_empty_dict():
        payload = {}
        expected = '{}'
        assert json_dumps_compact(payload) == expected

    @staticmethod
    def test_empty_list():
        payload = []
        expected = '[]'
        assert json_dumps_compact(payload) == expected

    @staticmethod
    def test_dict():
        payload = {'key1': 'value1', 'key2': 'value2'}
        expected = '{"key1":"value1","key2":"value2"}'
        assert json_dumps_compact(payload) == expected

    @staticmethod
    def test_list_of_dicts():
        payload = [{'key1': 'value1'}, {'key2': 'value2'}]
        expected = '[{"key1":"value1"},{"key2":"value2"}]'
        assert json_dumps_compact(payload) == expected

    @staticmethod
    def test_nested_dict():
        payload = {'key1': {'nestedKey1': 'nestedValue1'}, 'key2': 'value2'}
        expected = '{"key1":{"nestedKey1":"nestedValue1"},"key2":"value2"}'
        assert json_dumps_compact(payload) == expected

    @staticmethod
    def test_with_special_characters():
        payload = {'key1': 'value with spaces', 'key2': 'value with \n newline'}
        expected = '{"key1":"value with spaces","key2":"value with \\n newline"}'
        assert json_dumps_compact(payload) == expected

    @staticmethod
    def test_boolean_and_none():
        payload = {'key1': True, 'key2': None}
        expected = '{"key1":true,"key2":null}'
        assert json_dumps_compact(payload) == expected

    @staticmethod
    def test_numeric_values():
        payload = {'key1': 123, 'key2': 45.67}
        expected = '{"key1":123,"key2":45.67}'
        assert json_dumps_compact(payload) == expected


class TestPktCallback:
    """Test cases for pkt_cb function."""

    @staticmethod
    def test_pkt_cb_publishes(monkeypatch):
        exp_topic = "/foo/bar"
        exp_payload = {"messageId": 123, "value": 42}
        pkt = MQTT(type=3) / MQTTPublish(topic=exp_topic, value=json.dumps(exp_payload))

        # publish mock
        published = []
        monkeypatch.setattr(sm, "publish",
                            lambda t, p: published.append((t, p)))

        # call
        sm.pkt_cb(pkt)

        # expect: published with topic and payload
        assert published == [('/foo/bar', json_dumps_compact(exp_payload))]

    @staticmethod
    def test_pkt_cb_ignores_other_packets(monkeypatch):
        # packet without raw layer
        pkt = IP() / TCP()

        spy = MagicMock()
        monkeypatch.setattr(sm, "publish", spy)

        # action
        sm.pkt_cb(pkt)

        # check
        spy.assert_not_called()

    @staticmethod
    def test_pkt_cb_publishes_empty_payload(monkeypatch):
        exp_topic = "/foo/bar"
        pkt = MQTT(type=3) / MQTTPublish(topic=exp_topic, value='{}')

        # publish mock
        published = []
        monkeypatch.setattr(sm, "publish",
                            lambda t, p: published.append((t, p)))

        # call
        sm.pkt_cb(pkt)

        # expect: not published, because payload is empty
        assert not published

    @staticmethod
    def test_pkt_cb_publishes_invalid_payload(monkeypatch):
        exp_topic = "/foo/bar"
        pkt = MQTT(type=3) / MQTTPublish(topic=exp_topic, value='{invalid}')

        # publish mock
        published = []
        monkeypatch.setattr(sm, "publish",
                            lambda t, p: published.append((t, p)))

        # call
        sm.pkt_cb(pkt)

        # expect: not published, because payload is invalid JSON
        assert not published

    @staticmethod
    def test_pkt_cb_publishes_propertiesonlypacknum(monkeypatch):
        exp_topic = "/foo/bar"
        exp_payload = {"properties": {"packNum": 42}}
        pkt = MQTT(type=3) / MQTTPublish(topic=exp_topic, value=json.dumps(exp_payload))

        # publish mock
        published = []
        monkeypatch.setattr(sm, "publish",
                            lambda t, p: published.append((t, p)))

        # call
        sm.pkt_cb(pkt)

        # expect: not published, because it contains only one property,
        # and that property is 'packNum'
        assert not published

    @staticmethod
    def test_pkt_cb_publishes_topicblacklist(monkeypatch):
        exp_topic = "/foo/bar"
        exp_payload = {"properties": {"foo": 42}}
        pkt = MQTT(type=3) / MQTTPublish(topic=exp_topic, value=json.dumps(exp_payload))

        monkeypatch.setattr(sm, "_topics_blacklist", ['/foo/bar'])

        # publish mock
        published = []
        monkeypatch.setattr(sm, "publish",
                            lambda t, p: published.append((t, p)))

        # call
        sm.pkt_cb(pkt)

        # expect: not published, because of blacklisted topic
        assert not published

    @staticmethod
    def test_pkt_cb_publishes_topicblacklist_string(monkeypatch):
        exp_topic = "/foo/bar"
        exp_payload = {"properties": {"foo": 42}}
        pkt = MQTT(type=3) / MQTTPublish(topic=exp_topic, value=json.dumps(exp_payload))

        monkeypatch.setattr(sm, "_topics_blacklist", '/foo/bar')     # a simple string, not an array

        # publish mock
        published = []
        monkeypatch.setattr(sm, "publish",
                            lambda t, p: published.append((t, p)))

        # call
        sm.pkt_cb(pkt)

        # expect: not published, because of blacklisted topic
        assert not published

    @staticmethod
    def test_pkt_cb_publishes_topicprefix(monkeypatch):
        exp_topic = "/foo/bar"
        exp_payload = {"properties": {"foo": 42}}
        pkt = MQTT(type=3) / MQTTPublish(topic=exp_topic, value=json.dumps(exp_payload))

        monkeypatch.setattr(sm, "_mqtt_topic_prefix", "prefix")

        # publish mock
        published = []
        monkeypatch.setattr(sm, "publish",
                            lambda t, p: published.append((t, p)))

        # call
        sm.pkt_cb(pkt)

        # check
        assert published == [('prefix/foo/bar', json_dumps_compact(exp_payload))]


class TestHandleMqttPkt:
    """Test cases for handle_mqtt_pkt function."""

    @staticmethod
    def test_handle_mqtt_pkt_emptyvalue():
        # prepare
        pkt = MQTT(type=3) / MQTTPublish(topic="/foo/bar", value=b"")
        # action
        topic, payload = handle_mqtt_pkt(pkt)
        # check
        assert topic == "/foo/bar"
        assert not payload

    @staticmethod
    def test_handle_mqtt_pkt_emptyjson():
        # prepare
        pkt = MQTT(type=3) / MQTTPublish(topic="/foo/bar", value=b"{}")
        # action
        topic, payload = handle_mqtt_pkt(pkt)
        # check
        assert topic == "/foo/bar"
        assert not payload

    @staticmethod
    def test_handle_mqtt_pkt_invalidjson():
        # prepare
        pkt = MQTT(type=3) / MQTTPublish(topic="/foo/bar", value=b"{invalidjson}")
        # action
        topic, payload = handle_mqtt_pkt(pkt)
        # check
        assert topic == "/foo/bar"
        assert not payload

    @staticmethod
    def test_handle_mqtt_pkt_porpertiesonly1():
        # prepare
        payload_inp = {"properties": {"onlyone": "field"}}
        pkt = MQTT(type=3) / MQTTPublish(topic="/foo/bar", value=json.dumps(payload_inp))
        # action
        topic, payload = handle_mqtt_pkt(pkt)
        # check
        assert topic == "/foo/bar"
        assert payload == json_dumps_compact(payload_inp)

    @staticmethod
    def test_handle_mqtt_pkt_porpertiesonly1packnum():
        # prepare
        payload_inp = {"properties": {"packNum": 123}}
        pkt = MQTT(type=3) / MQTTPublish(topic="/foo/bar", value=json.dumps(payload_inp))
        # action
        topic, payload = handle_mqtt_pkt(pkt)
        # check
        assert topic == "/foo/bar"
        assert not payload

    @staticmethod
    def test_handle_mqtt_pkt_notopic():
        # prepare
        pkt = MQTT(type=3) / MQTTPublish()
        # action
        topic, payload = handle_mqtt_pkt(pkt)
        # check
        assert not topic
        assert not payload


class TestCheckCapNetRaw:
    @staticmethod
    def test_no_file(monkeypatch):
        """Test that has_cap_net_raw returns False if /proc/self/status is not found."""
        def open_fail(*args, **kwargs):
            raise FileNotFoundError
        monkeypatch.setattr("builtins.open", open_fail)
        assert has_cap_net_raw() is False

    @staticmethod
    def test_cap_net_raw_set(monkeypatch):
        """Test that has_cap_net_raw returns True when CAP_NET_RAW bit is set in CapEff."""
        # CAP_NET_RAW = 1 << 13 = 8192 → hex 0x2000
        fake_file = StringIO("Name:\tsome_process\nCapEff:\t2000\nState:\tR (running)\n")
        monkeypatch.setattr("builtins.open", lambda *args, **kwargs: fake_file)
        assert has_cap_net_raw() is True

    @staticmethod
    def test_cap_net_raw_unset(monkeypatch):
        """Test that has_cap_net_raw returns False when CAP_NET_RAW bit is not set in CapEff."""
        # Example hex value without bit 13 set, e.g. 0x1000
        fake_file = StringIO("Name:\tsome_process\nCapEff:\t1000\nState:\tR (running)\n")
        monkeypatch.setattr("builtins.open", lambda *args, **kwargs: fake_file)
        assert has_cap_net_raw() is False

    @staticmethod
    def test_no_capeff_line(monkeypatch):
        """Test that has_cap_net_raw returns False if CapEff line is missing."""
        fake_file = StringIO("Name:\tsome_process\nState:\tR (running)\n")
        monkeypatch.setattr("builtins.open", lambda *args, **kwargs: fake_file)
        assert has_cap_net_raw() is False
