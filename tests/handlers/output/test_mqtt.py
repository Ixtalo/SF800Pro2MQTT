# -*- coding: utf-8 -*-
import logging
from unittest.mock import Mock

import paho.mqtt.client

from sf800p2mqtt.handlers import MqttOutputHandler

# pylint: disable=missing-module-docstring,redefined-outer-name


class TestMqttOutputHandler:
    """Test cases for MqttOutputHandler class."""

    def test_init_default_params(self, monkeypatch):
        """Test MqttOutputHandler initialization with default parameters."""
        mock_client_class = Mock()
        mock_client = Mock()
        mock_client_class.return_value = mock_client
        monkeypatch.setattr(paho.mqtt.client, "Client", mock_client_class)

        handler = MqttOutputHandler()

        assert handler.host == "127.0.0.1"
        assert handler.port == 1883
        assert handler.username is None
        assert handler.password is None
        assert handler.client == mock_client

        # Verify client setup
        mock_client_class.assert_called_once()
        assert mock_client.on_connect is not None
        assert mock_client.on_disconnect is not None

    def test_init_custom_params(self, monkeypatch):
        """Test MqttOutputHandler initialization with custom parameters."""
        mock_client_class = Mock()
        mock_client = Mock()
        mock_client_class.return_value = mock_client
        monkeypatch.setattr(paho.mqtt.client, "Client", mock_client_class)

        handler = MqttOutputHandler(
            host="mqtt.example.com",
            port=8883,
            username="user",
            password="pass"
        )

        assert handler.host == "mqtt.example.com"
        assert handler.port == 8883
        assert handler.username == "user"
        assert handler.password == "pass"

        # Verify username/password was set
        mock_client.username_pw_set.assert_called_once_with("user", "pass")

    def test_connect_success(self, monkeypatch):
        """Test successful MQTT connection."""
        mock_client_class = Mock()
        mock_client = Mock()
        mock_client_class.return_value = mock_client
        monkeypatch.setattr(paho.mqtt.client, "Client", mock_client_class)

        handler = MqttOutputHandler()
        result = handler.connect()

        assert result is True
        mock_client.connect.assert_called_once_with("127.0.0.1", 1883, keepalive=60)
        mock_client.loop_start.assert_called_once()

    def test_connect_failure(self, monkeypatch, caplog):
        """Test MQTT connection failure."""
        mock_client_class = Mock()
        mock_client = Mock()
        mock_client.connect.side_effect = Exception("Connection failed")
        mock_client_class.return_value = mock_client
        monkeypatch.setattr(paho.mqtt.client, "Client", mock_client_class)

        handler = MqttOutputHandler()

        with caplog.at_level(logging.ERROR):
            result = handler.connect()

        assert result is False
        assert "Failed to connect to MQTT broker: Connection failed" in caplog.text

    def test_publish_success(self, monkeypatch):
        """Test successful MQTT message publishing."""
        mock_client_class = Mock()
        mock_client = Mock()
        mock_client_class.return_value = mock_client
        monkeypatch.setattr(paho.mqtt.client, "Client", mock_client_class)

        handler = MqttOutputHandler()
        result = handler.publish("test/topic", "test payload")

        assert result is True
        mock_client.publish.assert_called_once_with(
            "test/topic", "test payload", qos=0, retain=False
        )

    def test_publish_failure(self, monkeypatch, caplog):
        """Test MQTT publish failure."""
        mock_client_class = Mock()
        mock_client = Mock()
        mock_client.publish.side_effect = Exception("Publish failed")
        mock_client_class.return_value = mock_client
        monkeypatch.setattr(paho.mqtt.client, "Client", mock_client_class)

        handler = MqttOutputHandler()

        with caplog.at_level(logging.ERROR):
            result = handler.publish("test/topic", "test payload")

        assert result is False
        assert "MQTT publish failed: Publish failed" in caplog.text

    def test_disconnect_success(self, monkeypatch):
        """Test successful MQTT disconnection."""
        mock_client_class = Mock()
        mock_client = Mock()
        mock_client_class.return_value = mock_client
        monkeypatch.setattr(paho.mqtt.client, "Client", mock_client_class)

        handler = MqttOutputHandler()
        handler.disconnect()

        mock_client.loop_stop.assert_called_once()
        mock_client.disconnect.assert_called_once()

    def test_disconnect_failure(self, monkeypatch, caplog):
        """Test MQTT disconnection failure."""
        mock_client_class = Mock()
        mock_client = Mock()
        mock_client.loop_stop.side_effect = Exception("Disconnect failed")
        mock_client_class.return_value = mock_client
        monkeypatch.setattr(paho.mqtt.client, "Client", mock_client_class)

        handler = MqttOutputHandler()

        with caplog.at_level(logging.ERROR):
            handler.disconnect()

        assert "MQTT disconnect failed: Disconnect failed" in caplog.text

    def test_on_connect_callback(self, monkeypatch, caplog):
        """Test MQTT on_connect callback."""
        mock_client_class = Mock()
        mock_client = Mock()
        mock_client_class.return_value = mock_client
        monkeypatch.setattr(paho.mqtt.client, "Client", mock_client_class)

        handler = MqttOutputHandler()

        with caplog.at_level(logging.INFO):
            handler._on_connect(mock_client)       # pylint: disable=protected-access

        assert f"MQTT connected ({mock_client})" in caplog.text

    def test_on_disconnect_callback_with_retry(self, monkeypatch, caplog):
        """Test MQTT on_disconnect callback with successful retry."""
        mock_client_class = Mock()
        mock_client = Mock()
        mock_client.reconnect.return_value = None  # Successful reconnect
        mock_client_class.return_value = mock_client
        mock_sleep = Mock()
        monkeypatch.setattr(paho.mqtt.client, "Client", mock_client_class)
        monkeypatch.setattr("time.sleep", mock_sleep)

        handler = MqttOutputHandler()

        with caplog.at_level(logging.WARNING):
            handler._on_disconnect(mock_client, None, None, 1, None)    # pylint: disable=protected-access

        assert "MQTT disconnected (rc=1) – retrying ..." in caplog.text
        mock_client.reconnect.assert_called_once()
