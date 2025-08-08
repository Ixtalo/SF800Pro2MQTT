#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Unit tests for logging configuration module."""

import logging
import sys
from io import StringIO
from unittest.mock import mock_open, patch

import colorlog

import sf800p2mqtt.utils.logging
from sf800p2mqtt.utils.logging import should_use_colors, setup_logging


class TestShouldUseColors:
    """Test cases for should_use_colors function."""

    def test_returns_false_when_journal_stream_set(self, monkeypatch):
        """Test that colors are disabled when JOURNAL_STREAM is set."""
        monkeypatch.setenv("JOURNAL_STREAM", "some_value")
        monkeypatch.setattr(sys.stdout, "isatty", lambda: True)
        assert should_use_colors() is False

    def test_returns_false_when_invocation_id_set(self, monkeypatch):
        """Test that colors are disabled when INVOCATION_ID is set."""
        monkeypatch.setenv("INVOCATION_ID", "some_id")
        monkeypatch.setattr(sys.stdout, "isatty", lambda: True)
        assert should_use_colors() is False

    def test_returns_false_when_both_systemd_vars_set(self, monkeypatch):
        """Test that colors are disabled when both systemd variables are set."""
        monkeypatch.setenv("JOURNAL_STREAM", "some_value")
        monkeypatch.setenv("INVOCATION_ID", "some_id")
        monkeypatch.setattr(sys.stdout, "isatty", lambda: True)
        assert should_use_colors() is False

    def test_returns_false_when_not_tty(self, monkeypatch):
        """Test that colors are disabled when stdout is not a TTY."""
        monkeypatch.delenv("JOURNAL_STREAM", raising=False)
        monkeypatch.delenv("INVOCATION_ID", raising=False)
        monkeypatch.setattr(sys.stdout, "isatty", lambda: False)
        assert should_use_colors() is False

    def test_returns_true_when_tty_and_no_systemd(self, monkeypatch):
        """Test that colors are enabled when stdout is TTY and not under systemd."""
        monkeypatch.delenv("JOURNAL_STREAM", raising=False)
        monkeypatch.delenv("INVOCATION_ID", raising=False)
        monkeypatch.setattr(sys.stdout, "isatty", lambda: True)
        assert should_use_colors() is True

    def test_systemd_vars_take_precedence_over_tty(self, monkeypatch):
        """Test that systemd detection takes precedence over TTY check."""
        monkeypatch.setenv("JOURNAL_STREAM", "some_value")
        monkeypatch.setattr(sys.stdout, "isatty", lambda: True)        
        assert should_use_colors() is False


class TestSetupLogging:
    """Test cases for setup_logging function."""

    def setup_method(self):
        """Reset logging configuration before each test."""
        # Clear any existing handlers
        for handler in logging.root.handlers[:]:
            logging.root.removeHandler(handler)
        logging.root.setLevel(logging.WARNING)

    def test_default_parameters(self, monkeypatch):
        """Test setup_logging with default parameters."""
        monkeypatch.setattr(sf800p2mqtt.utils.logging, "should_use_colors", lambda: True)
        
        with patch("logging.basicConfig") as mock_basicConfig:
            handler = setup_logging()
            # Verify handler is StreamHandler with stdout
            assert isinstance(handler, colorlog.StreamHandler)
            assert handler.stream is sys.stdout
            # Verify formatter configuration
            formatter = handler.formatter
            assert isinstance(formatter, colorlog.ColoredFormatter)
            assert formatter._style._fmt == "%(log_color)s%(asctime)s %(levelname)-8s %(message)s"
            assert formatter.datefmt == "%Y-%m-%d %H:%M:%S"
            assert formatter.no_color is False
            # Verify basicConfig was called correctly
            mock_basicConfig.assert_called_once_with(level=logging.INFO, handlers=[handler])

    def test_with_file_output(self, monkeypatch):
        """Test setup_logging with file output."""
        mock_file = StringIO()
        
        with patch("builtins.open", mock_open()) as mock_open_func:
            mock_open_func.return_value = mock_file
            
            with patch("logging.basicConfig") as mock_basicConfig:
                handler = setup_logging(log_file="/path/to/logfile.log")
                # Verify file was opened correctly
                mock_open_func.assert_called_once_with("/path/to/logfile.log", "a", encoding="utf8")
                # Verify handler uses file stream
                assert handler.stream is mock_file
                # Verify colors are disabled for file output
                assert handler.formatter.no_color is True
                mock_basicConfig.assert_called_once_with(level=logging.INFO, handlers=[handler])

    def test_no_color_parameter_true(self, monkeypatch):
        """Test setup_logging with no_color=True."""
        monkeypatch.setattr(sf800p2mqtt.utils.logging, "should_use_colors", lambda: True)
        
        with patch("logging.basicConfig"):
            handler = setup_logging(no_color=True)
            assert handler.formatter.no_color is True

    def test_no_color_parameter_false_uses_should_use_colors(self, monkeypatch):
        """Test that no_color=False uses should_use_colors() result."""
        monkeypatch.setattr(sf800p2mqtt.utils.logging, "should_use_colors", lambda: False)
        
        with patch("logging.basicConfig"):
            handler = setup_logging(no_color=False)
            assert handler.formatter.no_color is True

    def test_should_use_colors_returns_true(self, monkeypatch):
        """Test that colors are enabled when should_use_colors returns True."""
        monkeypatch.setattr(sf800p2mqtt.utils.logging, "should_use_colors", lambda: True)
        
        with patch("logging.basicConfig"):
            handler = setup_logging()
            assert handler.formatter.no_color is False

    def test_custom_log_level(self, monkeypatch):
        """Test setup_logging with custom log level."""
        monkeypatch.setattr(sf800p2mqtt.utils.logging, "should_use_colors", lambda: True)
        
        with patch("logging.basicConfig") as mock_basicConfig:
            setup_logging(level=logging.DEBUG)
            mock_basicConfig.assert_called_once()
            call_args = mock_basicConfig.call_args
            assert call_args.kwargs["level"] == logging.DEBUG

    def test_file_output_forces_no_color_regardless_of_should_use_colors(self, monkeypatch):
        """Test that file output always disables colors regardless of should_use_colors."""
        monkeypatch.setattr(sf800p2mqtt.utils.logging, "should_use_colors", lambda: True)
        
        mock_file = StringIO()
        
        with patch("builtins.open", mock_open()) as mock_open_func:
            mock_open_func.return_value = mock_file
            
            with patch("logging.basicConfig"):
                handler = setup_logging(log_file="/path/to/logfile.log")
                # Colors should be disabled for file output even if should_use_colors returns True
                assert handler.formatter.no_color is True

    def test_handler_stream_configuration(self, monkeypatch):
        """Test that handler stream is configured correctly."""
        monkeypatch.setattr(sf800p2mqtt.utils.logging, "should_use_colors", lambda: True)
        
        # Test stdout configuration
        with patch("logging.basicConfig"):
            handler = setup_logging()
            assert handler.stream is sys.stdout
        
        # Test file configuration
        mock_file = StringIO()
        with patch("builtins.open", mock_open()) as mock_open_func:
            mock_open_func.return_value = mock_file
            
            with patch("logging.basicConfig"):
                handler = setup_logging(log_file="/path/to/logfile.log")
                assert handler.stream is mock_file

    def test_formatter_date_format(self, monkeypatch):
        """Test that formatter uses correct date format."""
        monkeypatch.setattr(sf800p2mqtt.utils.logging, "should_use_colors", lambda: True)
        
        with patch("logging.basicConfig"):
            handler = setup_logging()
            assert handler.formatter.datefmt == "%Y-%m-%d %H:%M:%S"

    def test_integration_with_should_use_colors(self, monkeypatch):
        """Test integration between setup_logging and should_use_colors."""
        # Test when systemd environment is detected
        monkeypatch.setenv("JOURNAL_STREAM", "some_value")
        monkeypatch.setattr(sys.stdout, "isatty", lambda: True)
        
        with patch("logging.basicConfig"):
            handler = setup_logging()
            # Colors should be disabled due to systemd detection
            assert handler.formatter.no_color is True
        
        # Test when no systemd and TTY
        monkeypatch.delenv("JOURNAL_STREAM", raising=False)
        monkeypatch.delenv("INVOCATION_ID", raising=False)
        monkeypatch.setattr(sys.stdout, "isatty", lambda: True)
        
        with patch("logging.basicConfig"):
            handler = setup_logging()
            # Colors should be enabled
            assert handler.formatter.no_color is False
