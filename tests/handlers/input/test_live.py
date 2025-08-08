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
        mock_partial = Mock()
        mock_partial_class = Mock(return_value=mock_partial)
        monkeypatch.setattr(sf800p2mqtt.handlers.input.live, "partial", mock_partial_class)

        handler = LiveInputHandler("dummyiface")
        callback = Mock()
        bpf_filter = "tcp port 80"

        with caplog.at_level(logging.INFO):
            result = handler.start_capture(callback, bpf_filter)

        assert result == 0
        assert "Sniffing on dummyiface, filter: 'tcp port 80' ..." in caplog.text

        # Verify partial was called to create L2socket class
        mock_partial_class.assert_called_once()
        args, kwargs = mock_partial_class.call_args
        # First argument should be MyL2ListenSocket class
        assert hasattr(args[0], "__name__")
        assert kwargs == {"filter": bpf_filter}

        # Verify sniff was called with correct parameters
        mock_sniff.assert_called_once_with(
            iface="dummyiface",
            L2socket=mock_partial,
            prn=callback,
            store=False
        )

    def test_start_capture_keyboard_interrupt(self, monkeypatch, caplog):
        """Test capture handling KeyboardInterrupt."""
        mock_sniff = Mock(side_effect=KeyboardInterrupt())
        monkeypatch.setattr(sf800p2mqtt.handlers.input.live, "sniff", mock_sniff)
        mock_partial_class = Mock()
        monkeypatch.setattr(sf800p2mqtt.handlers.input.live, "partial", mock_partial_class)

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
        mock_partial_class = Mock()
        monkeypatch.setattr(sf800p2mqtt.handlers.input.live, "partial", mock_partial_class)

        handler = LiveInputHandler("dummyiface")
        callback = Mock()

        with caplog.at_level(logging.ERROR):
            result = handler.start_capture(callback, "udp")

        assert result == -1
        assert "Error during live sniffing: Access denied" in caplog.text

    def test_start_capture_with_complex_filter(self, monkeypatch):
        """Test capture with complex BPF filter."""
        mock_sniff = Mock()
        monkeypatch.setattr(sf800p2mqtt.handlers.input.live, "sniff", mock_sniff)
        mock_partial = Mock()
        mock_partial_class = Mock(return_value=mock_partial)
        monkeypatch.setattr(sf800p2mqtt.handlers.input.live, "partial", mock_partial_class)

        handler = LiveInputHandler("dummyiface")
        callback = Mock()
        complex_filter = "tcp and (port 80 or port 443) and host 192.168.1.1"

        result = handler.start_capture(callback, complex_filter)
        assert result == 0

        # Verify the filter was passed correctly to partial
        mock_partial_class.assert_called_once()
        _args, kwargs = mock_partial_class.call_args
        assert kwargs["filter"] == complex_filter

    def test_start_capture_empty_interface(self, monkeypatch):
        """Test capture with empty interface name."""
        mock_sniff = Mock()
        monkeypatch.setattr(sf800p2mqtt.handlers.input.live, "sniff", mock_sniff)
        mock_partial_class = Mock()
        monkeypatch.setattr(sf800p2mqtt.handlers.input.live, "partial", mock_partial_class)

        handler = LiveInputHandler("")  # empty interface name
        callback = Mock()

        result = handler.start_capture(callback, "")
        assert result == 0
        mock_sniff.assert_called_once()
        _args, kwargs = mock_sniff.call_args
        assert kwargs["iface"] == ""
