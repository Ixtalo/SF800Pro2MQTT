# -*- coding: utf-8 -*-
"""
Unit tests for STDOUT output handler.
"""
import logging
from unittest.mock import Mock

import sf800p2mqtt.handlers.output.stdout
from sf800p2mqtt.handlers import StdoutOutputHandler


class TestStdoutOutputHandler:
    """Test cases for StdoutOutputHandler class."""

    def test_init(self):
        """Test StdoutOutputHandler initialization."""
        handler = StdoutOutputHandler()
        assert handler.connected is False

    def test_connect(self):
        """Test STDOUT connection (always successful)."""
        handler = StdoutOutputHandler()
        result = handler.connect()
        assert result is True
        assert handler.connected is True

    def test_publish_success(self, monkeypatch):
        """Test successful message publishing to STDOUT."""
        mock_print = Mock()
        monkeypatch.setattr("builtins.print", mock_print)
        mock_strftime = Mock(return_value="2020-01-02 03:04:05")
        monkeypatch.setattr(sf800p2mqtt.handlers.output.stdout, "strftime", mock_strftime)

        handler = StdoutOutputHandler()
        result = handler.publish("test/topic", "test message")

        assert result is True
        mock_print.assert_called_once_with(
            "[2020-01-02 03:04:05] test/topic: test message",
            flush=True
        )

    def test_publish_exception(self, monkeypatch, caplog):
        """Test publish method when print raises exception."""
        mock_print = Mock(side_effect=Exception("Print error"))
        mock_strftime = Mock(return_value="2020-01-02 03:04:05")

        monkeypatch.setattr("builtins.print", mock_print)
        monkeypatch.setattr(sf800p2mqtt.handlers.output.stdout, "strftime", mock_strftime)

        handler = StdoutOutputHandler()

        with caplog.at_level(logging.ERROR):
            result = handler.publish("test/topic", "test message")

        assert result is False
        assert "STDOUT publish failed: Print error" in caplog.text

    def test_disconnect(self):
        """Test STDOUT disconnection."""
        handler = StdoutOutputHandler()
        handler.connected = True

        handler.disconnect()

        assert handler.connected is False
