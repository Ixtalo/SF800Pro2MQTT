#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Unit tests for the logging configuration module."""

import logging
import sys
from unittest.mock import mock_open, patch

import pytest
import colorlog

from sf800p2mqtt.utils.logging import (
    setup_logging,
    is_running_under_systemd,
    is_stdout_tty,
    INTERACTIVE_FORMAT,
    SYSTEMD_FORMAT,
    REDIRECTED_FORMAT
)

# pylint: disable=unused-argument,redefined-outer-name
# pylint: disable=too-many-arguments,too-many-positional-arguments
# pylint: disable=line-too-long


# ============================================================================
# FIXTURES
# ============================================================================

@pytest.fixture
def clean_environment(monkeypatch):
    """Clean environment fixture that removes systemd variables."""
    monkeypatch.delenv("JOURNAL_STREAM", raising=False)
    monkeypatch.delenv("INVOCATION_ID", raising=False)
    return monkeypatch


@pytest.fixture
def reset_logging():
    """Fixture to reset logging configuration before and after tests."""
    # Store original state
    root_logger = logging.getLogger()
    original_handlers = root_logger.handlers[:]
    original_level = root_logger.level

    # Clear current handlers
    for handler in root_logger.handlers[:]:
        root_logger.removeHandler(handler)

    yield

    # Reset to original state
    for handler in root_logger.handlers[:]:
        root_logger.removeHandler(handler)

    for handler in original_handlers:
        root_logger.addHandler(handler)

    root_logger.setLevel(original_level)


@pytest.fixture
def mock_tty_true(monkeypatch):
    """Mock stdout as TTY."""
    monkeypatch.setattr("sys.stdout.isatty", lambda: True)


@pytest.fixture
def mock_tty_false(monkeypatch):
    """Mock stdout as non-TTY."""
    monkeypatch.setattr("sys.stdout.isatty", lambda: False)


@pytest.fixture
def systemd_environment(monkeypatch):
    """Set up systemd environment variables."""
    monkeypatch.setenv("JOURNAL_STREAM", "some_value")
    return monkeypatch


@pytest.fixture
def interactive_environment(clean_environment, mock_tty_true):
    """Set up interactive terminal environment."""
    return clean_environment


# ============================================================================
# TESTS
# ============================================================================

class TestIsRunningUnderSystemd:
    """Tests for is_running_under_systemd function."""

    def test_journal_stream_present(self, monkeypatch):
        """Test detection when JOURNAL_STREAM is set."""
        monkeypatch.setenv("JOURNAL_STREAM", "some_value")
        monkeypatch.delenv("INVOCATION_ID", raising=False)
        assert is_running_under_systemd() is True

    def test_invocation_id_present(self, monkeypatch):
        """Test detection when INVOCATION_ID is set."""
        monkeypatch.delenv("JOURNAL_STREAM", raising=False)
        monkeypatch.setenv("INVOCATION_ID", "some_uuid")
        assert is_running_under_systemd() is True

    def test_both_env_vars_present(self, monkeypatch):
        """Test detection when both environment variables are set."""
        monkeypatch.setenv("JOURNAL_STREAM", "some_value")
        monkeypatch.setenv("INVOCATION_ID", "some_uuid")
        assert is_running_under_systemd() is True

    def test_no_systemd_env_vars(self, clean_environment):
        """Test when no systemd environment variables are present."""
        assert is_running_under_systemd() is False

    def test_empty_env_vars(self, monkeypatch):
        """Test when environment variables are empty strings."""
        monkeypatch.setenv("JOURNAL_STREAM", "")
        monkeypatch.setenv("INVOCATION_ID", "")
        assert is_running_under_systemd() is False


class TestIsStdoutTty:
    """Tests for is_stdout_tty function."""

    def test_stdout_is_tty(self, mock_tty_true):
        """Test when stdout is a TTY."""
        assert is_stdout_tty() is True

    def test_stdout_is_not_tty(self, mock_tty_false):
        """Test when stdout is not a TTY."""
        assert is_stdout_tty() is False


class TestSetupLogging:
    """Tests for setup_logging function."""

    def test_default_setup_interactive_tty(self, reset_logging, interactive_environment):
        """Test default setup in interactive TTY environment."""
        handler = setup_logging()

        assert isinstance(handler, colorlog.StreamHandler)
        assert handler.stream == sys.stdout
        assert INTERACTIVE_FORMAT in handler.formatter._fmt  # pyright: ignore[reportOperatorIssue, reportOptionalMemberAccess], pylint: disable=protected-access
        assert handler.formatter.no_color is False  # pyright: ignore[reportOptionalMemberAccess, reportAttributeAccessIssue]
        assert logging.getLogger().level == logging.INFO

    def test_setup_under_systemd(self, reset_logging, systemd_environment, mock_tty_true):
        """Test setup when running under systemd."""
        handler = setup_logging()

        assert isinstance(handler, colorlog.StreamHandler)
        assert handler.stream == sys.stdout
        assert SYSTEMD_FORMAT in handler.formatter._fmt  # pyright: ignore[reportOperatorIssue, reportOptionalMemberAccess], pylint: disable=protected-access
        assert handler.formatter.no_color is True   # pyright: ignore[reportOptionalMemberAccess, reportAttributeAccessIssue]

    def test_setup_redirected_output(self, reset_logging, clean_environment, mock_tty_false):
        """Test setup when output is redirected (not TTY)."""
        handler = setup_logging()

        assert isinstance(handler, colorlog.StreamHandler)
        assert handler.stream == sys.stdout
        assert REDIRECTED_FORMAT in handler.formatter._fmt  # pyright: ignore[reportOperatorIssue, reportOptionalMemberAccess], pylint: disable=protected-access
        assert handler.formatter.no_color is True   # pyright: ignore[reportOptionalMemberAccess, reportAttributeAccessIssue]

    def test_setup_with_file_logging(self, reset_logging, interactive_environment, tmp_path):
        """Test setup with file logging."""
        log_file = tmp_path / "test.log"

        handler = setup_logging(log_file=str(log_file))

        assert isinstance(handler, colorlog.StreamHandler)
        assert handler.stream.name == str(log_file)
        assert handler.formatter.no_color is True   # pyright: ignore[reportOptionalMemberAccess, reportAttributeAccessIssue]

        # Clean up
        handler.stream.close()

    def test_setup_with_explicit_no_color(self, reset_logging, interactive_environment):
        """Test setup with explicitly disabled colors."""
        handler = setup_logging(no_color=True)
        assert handler.formatter.no_color is True   # pyright: ignore[reportOptionalMemberAccess, reportAttributeAccessIssue]

    def test_setup_with_custom_level(self, reset_logging, interactive_environment):
        """Test setup with custom logging level."""
        setup_logging(level=logging.DEBUG)
        assert logging.getLogger().level == logging.DEBUG

    def test_file_opened_with_correct_params(self, reset_logging, tmp_path):
        """Test that log file is opened with correct parameters."""
        log_file = tmp_path / "test.log"
        with patch("builtins.open", mock_open()) as mock_file:
            setup_logging(log_file=str(log_file))
            mock_file.assert_called_once_with(str(log_file), "a", encoding="utf8")

    def test_formatter_datetime_format(self, reset_logging, interactive_environment):
        """Test that formatter uses correct datetime format."""
        handler = setup_logging()
        assert handler.formatter.datefmt == "%Y-%m-%d %H:%M:%S"  # pyright: ignore[reportOptionalMemberAccess, reportAttributeAccessIssue]

    def test_no_color_overrides_auto_detection(self, reset_logging, interactive_environment):
        """Test that explicit no_color=True overrides auto-detection."""
        handler = setup_logging(no_color=True)

        assert handler.formatter.no_color is True   # pyright: ignore[reportOptionalMemberAccess, reportAttributeAccessIssue]

    def test_no_color_false_allows_auto_detection(self, reset_logging, systemd_environment, mock_tty_true):
        """Test that explicit no_color=False still allows auto-detection."""
        handler = setup_logging(no_color=False)

        # Should still be True due to systemd detection
        assert handler.formatter.no_color is True   # pyright: ignore[reportOptionalMemberAccess, reportAttributeAccessIssue]

    def test_file_logging_forces_no_color(self, reset_logging, interactive_environment, tmp_path):
        """Test that file logging always disables colors."""
        log_file = tmp_path / "test.log"

        handler = setup_logging(log_file=str(log_file), no_color=False)

        assert handler.formatter.no_color is True   # pyright: ignore[reportOptionalMemberAccess, reportAttributeAccessIssue]

        # Clean up
        handler.stream.close()


class TestIntegration:
    """Integration tests for the logging module."""

    def test_logging_works_after_setup(self, reset_logging, interactive_environment, capsys):
        """Test that logging actually works after setup."""
        setup_logging(level=logging.INFO)
        logger = logging.getLogger(__name__)

        logger.info("Test message")

        captured = capsys.readouterr()
        assert "Test message" in captured.out
        assert "INFO" in captured.out

    def test_file_logging_works(self, reset_logging, tmp_path):
        """Test that file logging actually writes to file."""
        log_file = tmp_path / "test.log"

        handler = setup_logging(log_file=str(log_file), level=logging.INFO)
        logger = logging.getLogger(__name__)

        logger.info("Test file message")
        handler.stream.flush()  # Ensure data is written

        assert log_file.exists()
        content = log_file.read_text()
        assert "Test file message" in content
        assert "INFO" in content

        # Clean up
        handler.stream.close()

    def test_debug_level_filtering(self, reset_logging, interactive_environment, capsys):
        """Test that debug messages are filtered when level is INFO."""
        setup_logging(level=logging.INFO)
        logger = logging.getLogger(__name__)

        logger.debug("Debug message")
        logger.info("Info message")

        captured = capsys.readouterr()
        assert "Debug message" not in captured.out
        assert "Info message" in captured.out

    def test_multiple_log_calls(self, reset_logging, interactive_environment, capsys):
        """Test multiple logging calls with different levels."""
        setup_logging(level=logging.DEBUG)
        logger = logging.getLogger(__name__)

        logger.debug("Debug message")
        logger.info("Info message")
        logger.warning("Warning message")
        logger.error("Error message")

        captured = capsys.readouterr()
        assert "Debug message" in captured.out
        assert "Info message" in captured.out
        assert "Warning message" in captured.out
        assert "Error message" in captured.out


class TestEdgeCases:
    """Test edge cases and error conditions."""

    def test_multiple_setup_calls(self, reset_logging, interactive_environment):
        """Test that multiple setup calls work correctly."""
        setup_logging(level=logging.DEBUG)
        handler2 = setup_logging(level=logging.INFO)

        # Should have replaced the handler
        root_logger = logging.getLogger()
        assert len(root_logger.handlers) == 1
        assert root_logger.level == logging.INFO

        # Handler2 should be the active one
        assert handler2 in root_logger.handlers

    def test_nonexistent_log_file_directory(self, reset_logging, tmp_path):
        """Test creating log file in non-existent directory."""
        log_dir = tmp_path / "nonexistent"
        log_file = log_dir / "test.log"

        # This should fail because the directory doesn't exist
        with pytest.raises(FileNotFoundError):
            setup_logging(log_file=str(log_file))

    def test_file_permissions_error(self, reset_logging, tmp_path, monkeypatch):
        """Test handling of file permission errors."""
        log_file = tmp_path / "test.log"

        # Mock open to raise PermissionError
        def mock_open_permission_error(*args, **kwargs):
            if args[0] == str(log_file):
                raise PermissionError("Permission denied")
            return open(*args, **kwargs)    # pylint: disable=unspecified-encoding

        monkeypatch.setattr("builtins.open", mock_open_permission_error)

        with pytest.raises(PermissionError):
            setup_logging(log_file=str(log_file))


# ============================================================================
# PARAMETRIZED TESTS
# ============================================================================

@pytest.mark.parametrize("level,level_name", [
    (logging.DEBUG, "DEBUG"),
    (logging.INFO, "INFO"),
    (logging.WARNING, "WARNING"),
    (logging.ERROR, "ERROR"),
    (logging.CRITICAL, "CRITICAL"),
])
def test_different_log_levels(level, level_name, reset_logging, interactive_environment, capsys):
    """Test setup with different log levels."""
    setup_logging(level=level)
    logger = logging.getLogger(__name__)

    # Log at the specified level
    logger.log(level, "Test %s message", level_name)

    captured = capsys.readouterr()
    assert f"Test {level_name} message" in captured.out
    assert level_name in captured.out


@pytest.mark.parametrize("env_var,env_value,expected", [
    ("JOURNAL_STREAM", "value", True),
    ("INVOCATION_ID", "uuid-value", True),
    ("JOURNAL_STREAM", "", False),
    ("INVOCATION_ID", "", False),
])
def test_systemd_detection_parametrized(env_var, env_value, expected, monkeypatch):
    """Test systemd detection with various environment variable values."""
    # Clean environment first
    monkeypatch.delenv("JOURNAL_STREAM", raising=False)
    monkeypatch.delenv("INVOCATION_ID", raising=False)

    # Set the specific environment variable
    if env_value:
        monkeypatch.setenv(env_var, env_value)

    assert is_running_under_systemd() is expected


@pytest.mark.parametrize("is_systemd,is_tty,expected_format,expected_no_color", [
    (False, True, INTERACTIVE_FORMAT, False),   # Interactive terminal
    (True, True, SYSTEMD_FORMAT, True),         # Systemd service
    (False, False, REDIRECTED_FORMAT, True),    # Redirected output
    (True, False, SYSTEMD_FORMAT, True),        # Systemd + redirected (systemd wins)
])
def test_format_selection_parametrized(is_systemd, is_tty, expected_format, expected_no_color,
                                       reset_logging, monkeypatch):
    """Test format selection based on environment conditions."""
    # Mock systemd detection
    if is_systemd:
        monkeypatch.setenv("JOURNAL_STREAM", "value")
    else:
        monkeypatch.delenv("JOURNAL_STREAM", raising=False)
        monkeypatch.delenv("INVOCATION_ID", raising=False)

    # Mock TTY detection
    monkeypatch.setattr("sys.stdout.isatty", lambda: is_tty)

    handler = setup_logging()

    assert expected_format in handler.formatter._fmt  # pyright: ignore[reportOptionalMemberAccess], pylint: disable=protected-access
    assert handler.formatter.no_color is expected_no_color  # pyright: ignore[reportOptionalMemberAccess, reportAttributeAccessIssue]


# ============================================================================
# PERFORMANCE TESTS
# ============================================================================

def test_setup_performance(reset_logging, interactive_environment):
    """Test that setup_logging performs reasonably fast."""
    import time     # pylint: disable=import-outside-toplevel

    start_time = time.time()
    setup_logging()
    end_time = time.time()

    # Setup should complete in less than 100ms
    assert (end_time - start_time) < 0.1


# ============================================================================
# PROPERTY-BASED TESTS
# ============================================================================

@pytest.mark.parametrize("log_level", [
    logging.NOTSET, logging.DEBUG, logging.INFO,
    logging.WARNING, logging.ERROR, logging.CRITICAL
])
def test_all_valid_log_levels(log_level, reset_logging, interactive_environment):
    """Test setup with all valid logging levels."""
    handler = setup_logging(level=log_level)

    assert isinstance(handler, colorlog.StreamHandler)
    assert logging.getLogger().level == log_level


def test_handler_cleanup_on_multiple_setups(reset_logging, interactive_environment):
    """Test that handlers are properly cleaned up on multiple setups."""
    # First setup
    setup_logging()
    initial_handler_count = len(logging.getLogger().handlers)

    # Multiple additional setups
    for _ in range(5):
        setup_logging()

    # Should still have the same number of handlers (old ones removed)
    final_handler_count = len(logging.getLogger().handlers)
    assert final_handler_count == initial_handler_count
