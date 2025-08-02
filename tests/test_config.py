#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Unit tests for Config class.

This module contains comprehensive unit tests for the Config dataclass,
including initialization, environment variable handling, and CLI argument processing.
"""

from unittest.mock import MagicMock
import pytest

from sf800p2mqtt.config import Config

# Constants for test environment variables
ENV_VARS = [
    "FILTER_IP", "MQTT_HOST", "MQTT_PORT", "MQTT_USER", "MQTT_PASS",
    "MQTT_TOPIC_PREFIX", "PUBLISH_PERIOD_SECONDS", "TOPICS_BLACKLIST"
]


@pytest.fixture
def base_arguments():
    """Provide base CLI arguments for testing."""
    return {
        "<filter-ip>": None,
        "--mqtt-host": None,
        "--mqtt-port": None,
        "--mqtt-user": None,
        "--mqtt-pass": None,
        "--mqtt-prefix": None,
        "--publish-period": None,
        "--topics-blacklist": None
    }


@pytest.fixture
def clean_env(monkeypatch):
    """Clear all test environment variables."""
    for key in ENV_VARS:
        monkeypatch.delenv(key, raising=False)


@pytest.fixture
def mock_dotenv(monkeypatch):
    """Mock dotenv.load_dotenv function."""
    mock_load_dotenv = MagicMock()
    monkeypatch.setattr("dotenv.load_dotenv", mock_load_dotenv)
    return mock_load_dotenv


@pytest.fixture
def setup_test_env(monkeypatch):
    """Set up common test environment variables."""
    env_values = {
        "FILTER_IP": "10.0.0.50",
        "MQTT_HOST": "env.mqtt.com",
        "MQTT_PORT": "1884",
        "MQTT_USER": "envuser",
        "MQTT_PASS": "envpass",
        "MQTT_TOPIC_PREFIX": "env/prefix",
        "PUBLISH_PERIOD_SECONDS": "120",
        "TOPICS_BLACKLIST": "env1,env2"
    }
    for key, value in env_values.items():
        monkeypatch.setenv(key, value)


class TestConfigInitialization:
    """Test Config class initialization and basic functionality."""

    def test_config_initialization_with_all_parameters(self):
        """Test Config initialization with all parameters provided."""
        config = Config(
            filter_ip="192.168.1.100",
            mqtt_host="test.example.com",
            mqtt_port=8883,
            mqtt_user="testuser",
            mqtt_pass="testpass",
            mqtt_topic_prefix="test/prefix",
            publish_period_seconds=60,
            topics_blacklist={"topic1", "topic2"}
        )

        assert config.filter_ip == "192.168.1.100"
        assert config.mqtt_host == "test.example.com"
        assert config.mqtt_port == 8883
        assert config.mqtt_user == "testuser"
        assert config.mqtt_pass == "testpass"
        assert config.mqtt_topic_prefix == "test/prefix"
        assert config.publish_period_seconds == 60
        assert config.topics_blacklist == {"topic1", "topic2"}

    def test_config_post_init_with_none_blacklist(self):
        """Test __post_init__ method initializes empty set for None blacklist."""
        config = Config(
            filter_ip="192.168.1.100",
            mqtt_host="127.0.0.1",
            mqtt_port=1883,
            mqtt_user=None,
            mqtt_pass=None,
            mqtt_topic_prefix="",
            publish_period_seconds=30,
            topics_blacklist=set()
        )

        assert config.topics_blacklist == set()

    def test_config_post_init_with_existing_blacklist(self):
        """Test __post_init__ method preserves existing blacklist."""
        existing_blacklist = {"topic1", "topic2"}
        config = Config(
            filter_ip="192.168.1.100",
            mqtt_host="127.0.0.1",
            mqtt_port=1883,
            mqtt_user=None,
            mqtt_pass=None,
            mqtt_topic_prefix="",
            publish_period_seconds=30,
            topics_blacklist=existing_blacklist
        )

        assert config.topics_blacklist == existing_blacklist


class TestConfigFromArgsAndEnv:
    """Test Config.from_args_and_env class method."""

    def test_from_args_with_cli_arguments_only(self, clean_env, mock_dotenv, base_arguments):
        """Test configuration creation with CLI arguments only."""
        arguments = {
            **base_arguments,
            "<filter-ip>": "192.168.1.100",
            "--mqtt-host": "mqtt.example.com",
            "--mqtt-port": "8883",
            "--mqtt-user": "user123",
            "--mqtt-pass": "pass123",
            "--mqtt-prefix": "sensor/data",
            "--publish-period": "45",
            "--topics-blacklist": "topic1,topic2,topic3"
        }

        config = Config.from_args_and_env(arguments)

        mock_dotenv.assert_called_once_with(verbose=True)
        assert config.filter_ip == "192.168.1.100"
        assert config.mqtt_host == "mqtt.example.com"
        assert config.mqtt_port == 8883
        assert config.mqtt_user == "user123"
        assert config.mqtt_pass == "pass123"
        assert config.mqtt_topic_prefix == "sensor/data"
        assert config.publish_period_seconds == 45
        assert config.topics_blacklist == {"topic1", "topic2", "topic3"}

    def test_from_args_with_env_variables_only(self, setup_test_env, mock_dotenv, base_arguments):
        """Test configuration creation with environment variables only."""
        config = Config.from_args_and_env(base_arguments)

        assert config.filter_ip == "10.0.0.50"
        assert config.mqtt_host == "env.mqtt.com"
        assert config.mqtt_port == 1884
        assert config.mqtt_user == "envuser"
        assert config.mqtt_pass == "envpass"
        assert config.mqtt_topic_prefix == "env/prefix"
        assert config.publish_period_seconds == 120
        assert config.topics_blacklist == {"env1", "env2"}

    def test_cli_args_override_env_variables(self, monkeypatch, mock_dotenv, base_arguments):
        """Test that CLI arguments take precedence over environment variables."""
        # Set environment variables
        monkeypatch.setenv("FILTER_IP", "10.0.0.50")
        monkeypatch.setenv("MQTT_HOST", "env.mqtt.com")
        monkeypatch.setenv("MQTT_PORT", "1884")
        monkeypatch.setenv("MQTT_USER", "envuser")
        monkeypatch.setenv("MQTT_PASS", "envpass")

        arguments = {
            **base_arguments,
            "<filter-ip>": "192.168.1.200",
            "--mqtt-host": "cli.mqtt.com",  # Should override env
            "--mqtt-port": "9883",          # Should override env
            # mqtt_user and mqtt_pass not provided, should use env
        }

        config = Config.from_args_and_env(arguments)

        assert config.filter_ip == "192.168.1.200"  # CLI override
        assert config.mqtt_host == "cli.mqtt.com"   # CLI override
        assert config.mqtt_port == 9883             # CLI override
        assert config.mqtt_user == "envuser"        # From env
        assert config.mqtt_pass == "envpass"        # From env

    def test_default_values_when_no_args_or_env(self, clean_env, mock_dotenv, base_arguments):
        """Test default values are used when no CLI args or env variables."""
        arguments = {
            **base_arguments,
            "<filter-ip>": "192.168.1.100"  # Required field
        }

        config = Config.from_args_and_env(arguments)

        assert config.filter_ip == "192.168.1.100"
        assert config.mqtt_host == "127.0.0.1"     # Default
        assert config.mqtt_port == 1883            # Default
        assert config.mqtt_user is None            # Default
        assert config.mqtt_pass is None            # Default
        assert config.mqtt_topic_prefix == ""      # Default
        assert config.publish_period_seconds == 30  # Default
        assert config.topics_blacklist == set()    # Default

    def test_topic_prefix_trailing_slash_removal(self, clean_env, mock_dotenv, base_arguments):
        """Test that trailing slashes are removed from topic prefix."""
        arguments = {
            **base_arguments,
            "<filter-ip>": "192.168.1.100",
            "--mqtt-prefix": "test/prefix///"
        }

        config = Config.from_args_and_env(arguments)

        assert config.mqtt_topic_prefix == "test/prefix"

    def test_blacklist_parsing_with_spaces_and_empty_values(self, clean_env, mock_dotenv, base_arguments):
        """Test blacklist parsing handles spaces and empty values correctly."""
        arguments = {
            **base_arguments,
            "<filter-ip>": "192.168.1.100",
            "--topics-blacklist": " topic1 , topic2,  ,topic3,  "
        }

        config = Config.from_args_and_env(arguments)

        assert config.topics_blacklist == {"topic1", "topic2", "topic3"}

    def test_empty_blacklist_string(self, clean_env, mock_dotenv, base_arguments):
        """Test empty blacklist string results in empty set."""
        arguments = {
            **base_arguments,
            "<filter-ip>": "192.168.1.100",
            "--topics-blacklist": ""
        }

        config = Config.from_args_and_env(arguments)

        assert config.topics_blacklist == set()

    def test_integer_conversion_error_handling(self, clean_env, mock_dotenv, base_arguments):
        """Test integer conversion handles invalid values."""
        arguments = {
            **base_arguments,
            "<filter-ip>": "192.168.1.100",
            "--mqtt-port": "invalid_port"
        }

        with pytest.raises(ValueError, match="invalid literal for int()"):
            Config.from_args_and_env(arguments)

    def test_env_integer_conversion_error_handling(self, monkeypatch, mock_dotenv, base_arguments):
        """Test integer conversion handles invalid environment values."""
        # Set invalid environment variable
        monkeypatch.setenv("MQTT_PORT", "invalid_env_port")

        arguments = {
            **base_arguments,
            "<filter-ip>": "192.168.1.100"
        }

        with pytest.raises(ValueError, match="invalid literal for int()"):
            Config.from_args_and_env(arguments)

    def test_dotenv_load_called(self, clean_env, mock_dotenv, base_arguments):
        """Test that dotenv.load_dotenv is called with correct parameters."""
        arguments = {
            **base_arguments,
            "<filter-ip>": "192.168.1.100"
        }

        Config.from_args_and_env(arguments)

        mock_dotenv.assert_called_once_with(verbose=True)


class TestConfigHelperFunctions:
    """Test the internal helper functions used in from_args_and_env."""

    def test_get_config_value_cli_precedence(self, monkeypatch, mock_dotenv, base_arguments):
        """Test that CLI args take precedence in get_config_value helper."""
        # Set environment variable
        monkeypatch.setenv("MQTT_HOST", "env_value")

        arguments = {
            **base_arguments,
            "<filter-ip>": "192.168.1.100",
            "--mqtt-host": "cli_value"
        }

        # We can't directly test the helper function as it's nested,
        # but we can test the behavior through the main method
        config = Config.from_args_and_env(arguments)

        # The helper should prefer CLI arg over env
        assert config.mqtt_host == "cli_value"

    def test_none_or_empty_string_handling(self, clean_env, mock_dotenv, base_arguments):
        """Test handling of None and empty string values."""
        arguments = {
            **base_arguments,
            "<filter-ip>": "192.168.1.100",
            "--mqtt-user": "",  # Empty string should become None
            "--mqtt-pass": None
        }

        config = Config.from_args_and_env(arguments)

        assert config.mqtt_user is None
        assert config.mqtt_pass is None


if __name__ == "__main__":
    pytest.main([__file__])
