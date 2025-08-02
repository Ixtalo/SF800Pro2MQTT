# -*- coding: utf-8 -*-
import logging
from pathlib import Path
from unittest.mock import Mock, call

import pytest

import sf800p2mqtt.handlers.input.pcap_file
from sf800p2mqtt.handlers import PcapInputHandler


@pytest.fixture
def mock_valid_pcap_path():
    """Fixture providing a mock Path that exists."""
    mock_path = Mock(spec=Path)
    mock_path.exists.return_value = True
    mock_path.name = "test.pcap"
    mock_path.resolve.return_value = Path("/tmp/test.pcap")
    mock_path.__str__ = Mock(return_value="/tmp/test.pcap")
    return mock_path


@pytest.fixture
def mock_invalid_pcap_path():
    """Fixture providing a mock Path that doesn't exist."""
    mock_path = Mock(spec=Path)
    mock_path.exists.return_value = False
    mock_path.resolve.return_value = Path("/tmp/nonexistent.pcap")
    return mock_path


@pytest.fixture
def mock_sniff(monkeypatch):
    """Fixture providing a mock Path that doesn't exist."""
    mock_sniff = Mock(return_value=None)
    monkeypatch.setattr(sf800p2mqtt.handlers.input.pcap_file, "sniff", mock_sniff)
    return mock_sniff


class TestPcapInputHandler:
    """Test cases for PcapInputHandler class."""

    def test_init_valid_file(self, mock_valid_pcap_path):
        """Test PcapInputHandler initialization with valid file."""
        handler = PcapInputHandler(mock_valid_pcap_path)
        assert handler.pcap_file == mock_valid_pcap_path
        mock_valid_pcap_path.exists.assert_called_once()

    def test_init_nonexistent_file(self, mock_invalid_pcap_path):
        """Test initialization with non-existent file raises FileNotFoundError."""
        with pytest.raises(FileNotFoundError, match="PCAP file not found: /tmp/nonexistent.pcap"):
            PcapInputHandler(mock_invalid_pcap_path)
        mock_invalid_pcap_path.exists.assert_called_once()
        mock_invalid_pcap_path.resolve.assert_called_once()

    def test_start_capture_success(self, caplog, mock_valid_pcap_path, mock_sniff):
        """Test successful PCAP file capture."""
        handler = PcapInputHandler(mock_valid_pcap_path)
        callback = Mock()
        bpf_filter = "icmp"

        with caplog.at_level(logging.INFO):
            result = handler.start_capture(callback, bpf_filter)

        assert result == 0
        assert "Reading PCAP file 'test.pcap', filter: 'icmp' ..." in caplog.text
        assert "Finished reading PCAP file" in caplog.text

        # Verify sniff was called with correct parameters
        mock_sniff.assert_called_once_with(
            offline=str(mock_valid_pcap_path),
            prn=callback,
            filter=bpf_filter
        )

    def test_start_capture_exception(self, monkeypatch, caplog):
        """Test capture handling exceptions during PCAP reading."""
        mock_path = Mock(spec=Path)
        mock_path.exists.return_value = True
        mock_path.name = "corrupted.pcap"
        mock_sniff = Mock(side_effect=IOError("File corrupted"))
        monkeypatch.setattr(sf800p2mqtt.handlers.input.pcap_file, "sniff", mock_sniff)

        handler = PcapInputHandler(mock_path)
        callback = Mock()

        with caplog.at_level(logging.ERROR):
            result = handler.start_capture(callback, "")

        assert result == -1
        assert "Error reading PCAP file: File corrupted" in caplog.text

    def test_start_capture_no_filter(self, mock_sniff):
        """Test capture with empty filter."""
        mock_path = Mock(spec=Path)
        mock_path.exists.return_value = True
        mock_path.name = "capture.pcap"

        handler = PcapInputHandler(mock_path)
        callback = Mock()

        result = handler.start_capture(callback, "")

        assert result == 0
        mock_sniff.assert_called_once_with(
            offline=str(mock_path),
            prn=callback,
            filter=""
        )

    def test_multiple_captures_same_handler(self, monkeypatch, mock_sniff):
        """Test multiple capture calls on same handler instance."""
        mock_path = Mock(spec=Path)
        mock_path.exists.return_value = True
        mock_path.name = "multi.pcap"

        handler = PcapInputHandler(mock_path)
        callback1 = Mock()
        callback2 = Mock()

        # First capture
        result1 = handler.start_capture(callback1, "tcp")
        # Second capture
        result2 = handler.start_capture(callback2, "udp")

        assert result1 == 0
        assert result2 == 0

        # Verify sniff was called twice with different parameters
        expected_calls = [
            call(offline=str(mock_path), prn=callback1, filter="tcp"),
            call(offline=str(mock_path), prn=callback2, filter="udp")
        ]
        assert mock_sniff.call_args_list == expected_calls

    def test_pcap_file_path_conversion(self, mock_sniff):
        """Test that Path object is correctly converted to string."""
        mock_path = Mock(spec=Path)
        mock_path.exists.return_value = True
        mock_path.name = "test.pcap"
        mock_path.__str__ = Mock(return_value="/full/path/test.pcap")

        handler = PcapInputHandler(mock_path)
        callback = Mock()

        handler.start_capture(callback, "")

        # Verify str() was called on the path
        mock_path.__str__.assert_called_once()
        mock_sniff.assert_called_once()
        _args, kwargs = mock_sniff.call_args
        assert kwargs["offline"] == "/full/path/test.pcap"
