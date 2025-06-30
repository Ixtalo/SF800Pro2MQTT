"""
pytest unit tests
"""
import json
import os
from unittest.mock import MagicMock

import pytest
from scapy.all import IP, TCP, Raw

import sf800psniff2mqtt as sm


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


def make_raw_frame():
    topic   = b"/deviceModel/deviceId/properties/energy"
    payload = {
        "messageId": 123,
        "value": 42
    }
    raw = b"x" + topic + json.dumps(payload).encode()
    return raw, topic.decode(), json.dumps(payload, separators=(',', ':'))


def test_extract_topic_ok():
    raw, exp_topic, exp_payload = make_raw_frame()
    topic, payload = sm.extract_topic(raw)
    assert topic == exp_topic
    assert payload == exp_payload


def test_extract_topic_no_match():
    topic, payload = sm.extract_topic(b"no mqtt here")
    assert topic is None and payload is None


def test_pkt_cb_publishes(monkeypatch):
    raw, exp_topic, exp_payload = make_raw_frame()

    # build a Scapy packet (inkl. TCP & Raw)
    pkt = IP()/TCP()/Raw(load=raw)

    # safe_publish mock
    published = []
    monkeypatch.setattr(sm, "safe_publish",
                        lambda t, p: published.append((t, p)))

    # call
    sm.pkt_cb(pkt)

    # expect: published with topic and payload
    assert published == [(exp_topic.lstrip('/'), exp_payload)]


def test_pkt_cb_ignores_other_packets(monkeypatch):
    # packet without raw layer
    pkt = IP()/TCP()

    spy = MagicMock()
    monkeypatch.setattr(sm, "safe_publish", spy)

    # action
    sm.pkt_cb(pkt)

    # check
    spy.assert_not_called()
