#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Configuration management module for application settings.

This module provides configuration loading and management functionality,
supporting both command-line arguments and environment variables with
CLI argument precedence over environment settings.
"""
import os
from dataclasses import dataclass
from typing import Optional, Set

import dotenv


@dataclass
class Config:       # pylint: disable=too-many-instance-attributes
    """Application configuration container.

    Holds all configuration parameters for the application including
    network filtering, MQTT connection settings, and publishing options.
    Supports loading from both command-line arguments and environment
    variables with argument precedence.
    """

    filter_ip: str
    mqtt_host: str
    mqtt_port: int
    mqtt_user: Optional[str]
    mqtt_pass: Optional[str]
    mqtt_topic_prefix: str
    publish_period_seconds: int
    topics_blacklist: set

    def __post_init__(self):
        """Initialize mutable default values."""
        if self.topics_blacklist is None:
            self.topics_blacklist = set()

    @classmethod
    def from_args_and_env(cls, arguments: dict) -> 'Config':
        """Create config from CLI args and environment."""
        dotenv.load_dotenv(verbose=True)

        def get_config_value(cli_arg: Optional[str], env_key: str, default: str = "") -> str:
            """Get configuration value with CLI precedence over env."""
            return cli_arg or os.getenv(env_key, default)

        def get_int_config_value(cli_arg: Optional[str], env_key: str, default: int) -> int:
            """Get integer configuration value."""
            if cli_arg:
                return int(cli_arg)
            return int(os.getenv(env_key, str(default)))

        def parse_blacklist(value: str) -> Set[str]:
            """Parse comma-separated blacklist string."""
            return {v.strip() for v in value.split(",") if v.strip()}

        # Build configuration
        return cls(
            filter_ip=get_config_value(arguments["<filter-ip>"], "FILTER_IP"),
            mqtt_host=get_config_value(arguments["--mqtt-host"], "MQTT_HOST", "127.0.0.1"),
            mqtt_port=get_int_config_value(arguments["--mqtt-port"], "MQTT_PORT", 1883),
            mqtt_user=get_config_value(arguments["--mqtt-user"], "MQTT_USER") or None,
            mqtt_pass=get_config_value(arguments["--mqtt-pass"], "MQTT_PASS") or None,
            mqtt_topic_prefix=get_config_value(arguments["--mqtt-prefix"], "MQTT_TOPIC_PREFIX").rstrip("/"),
            publish_period_seconds=get_int_config_value(arguments["--publish-period"], "PUBLISH_PERIOD_SECONDS", 30),
            topics_blacklist=parse_blacklist(get_config_value(arguments["--topics-blacklist"], "TOPICS_BLACKLIST"))
        )
