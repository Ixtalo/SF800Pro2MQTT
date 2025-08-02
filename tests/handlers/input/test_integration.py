# -*- coding: utf-8 -*-
from pathlib import Path
from unittest.mock import Mock

import sf800p2mqtt.handlers.input.live
import sf800p2mqtt.handlers.input.pcap_file
from sf800p2mqtt.handlers import LiveInputHandler, PcapInputHandler


class TestIntegration:
    """Integration tests for input handlers."""

    def test_handlers_implement_base_interface(self):
        """Test that handlers implement the expected interface."""
        # Test LiveInputHandler
        live_handler = LiveInputHandler("eth0")
        assert hasattr(live_handler, "start_capture")
        assert callable(live_handler.start_capture)

        # Test PcapInputHandler with mocked path
        mock_path = Mock(spec=Path)
        mock_path.exists.return_value = True
        pcap_handler = PcapInputHandler(mock_path)
        assert hasattr(pcap_handler, "start_capture")
        assert callable(pcap_handler.start_capture)

    def test_callback_function_signature(self, monkeypatch):
        """Test that handlers correctly pass packet to callback."""
        # Mock a packet object
        mock_packet = Mock()
        mock_callback = Mock()

        # Mock sniff to call the callback with our packet
        def mock_sniff_behavior(**kwargs):
            prn_callback = kwargs.get('prn')
            if prn_callback:
                prn_callback(mock_packet)

        mock_sniff = Mock(side_effect=mock_sniff_behavior)
        monkeypatch.setattr(sf800p2mqtt.handlers.input.pcap_file, "sniff", mock_sniff)

        # Test with PcapInputHandler
        mock_path = Mock(spec=Path)
        mock_path.exists.return_value = True

        handler = PcapInputHandler(mock_path)
        handler.start_capture(mock_callback, "")

        # Verify callback was called with the packet
        mock_callback.assert_called_once_with(mock_packet)

    def test_live_handler_interface_validation(self, monkeypatch):
        """Test LiveInputHandler interface matches expected signature."""
        mock_sniff = Mock()
        mock_partial = Mock()
        monkeypatch.setattr(sf800p2mqtt.handlers.input.live, "sniff", mock_sniff)
        monkeypatch.setattr("functools.partial", Mock(return_value=mock_partial))

        handler = LiveInputHandler("test_interface")
        callback = Mock()

        # Test method signature
        result = handler.start_capture(callback, "test_filter")

        assert isinstance(result, int)
        assert result in [0, -1]  # Should return success or error code

    def test_pcap_handler_interface_validation(self, monkeypatch):
        """Test PcapInputHandler interface matches expected signature."""
        mock_path = Mock(spec=Path)
        mock_path.exists.return_value = True

        mock_sniff = Mock()
        monkeypatch.setattr(sf800p2mqtt.handlers.input.pcap_file, "sniff", mock_sniff)

        handler = PcapInputHandler(mock_path)
        callback = Mock()

        # Test method signature
        result = handler.start_capture(callback, "test_filter")

        assert isinstance(result, int)
        assert result in [0, -1]  # Should return success or error code
