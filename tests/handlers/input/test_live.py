# -*- coding: utf-8 -*-
"""
Unit tests for PCAP live input handler.
"""
import logging
from unittest.mock import Mock

import sf800p2mqtt.handlers.input.live
from sf800p2mqtt.handlers import LiveInputHandler

# pylint: disable=missing-module-docstring


class TestLiveInputHandler:
    """Test cases for LiveInputHandler class."""

    def test_init(self):
        """Test LiveInputHandler initialization."""
        handler = LiveInputHandler("dummyiface")
        assert handler.interface == "dummyiface"

    def test_start_capture_success(self, monkeypatch, caplog):
        """Test successful live packet capture."""
        mock_sniff = Mock(return_value=None)
        monkeypatch.setattr(sf800p2mqtt.handlers.input.live, "sniff", mock_sniff)
        Mock()

        handler = LiveInputHandler("dummyiface")
        callback = Mock()
        bpf_filter = "tcp port 80"

        with caplog.at_level(logging.INFO):
            result = handler.start_capture(callback, bpf_filter)

        assert result == 0
        assert "Sniffing on dummyiface, filter: 'tcp port 80' ..." in caplog.text

        # Verify sniff was called with correct parameters
        mock_sniff.assert_called_once_with(
            iface="dummyiface",
            filter=bpf_filter,
            prn=callback,
            store=False
        )

    def test_start_capture_keyboard_interrupt(self, monkeypatch, caplog):
        """Test capture handling KeyboardInterrupt."""
        mock_sniff = Mock(side_effect=KeyboardInterrupt())
        monkeypatch.setattr(sf800p2mqtt.handlers.input.live, "sniff", mock_sniff)

        handler = LiveInputHandler("dummyiface")
        callback = Mock()

        with caplog.at_level(logging.INFO):
            result = handler.start_capture(callback, "")

        assert result == 0
        assert "Stopping live capture..." in caplog.text

    def test_start_capture_exception(self, monkeypatch, caplog):
        """Test capture handling generic exceptions."""
        mock_sniff = Mock(side_effect=PermissionError("Access denied"))
        monkeypatch.setattr(sf800p2mqtt.handlers.input.live, "sniff", mock_sniff)

        handler = LiveInputHandler("dummyiface")
        callback = Mock()

        with caplog.at_level(logging.ERROR):
            result = handler.start_capture(callback, "udp")

        assert result == -1
        assert "Error during live sniffing: Access denied" in caplog.text

    def test_start_capture_empty_interface(self, monkeypatch):
        """Test capture with empty interface name."""
        mock_sniff = Mock()
        monkeypatch.setattr(sf800p2mqtt.handlers.input.live, "sniff", mock_sniff)

        handler = LiveInputHandler("")  # empty interface name
        callback = Mock()

        result = handler.start_capture(callback, "")
        assert result == 0
        mock_sniff.assert_called_once()
