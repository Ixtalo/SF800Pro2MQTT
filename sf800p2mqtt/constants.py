#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Global constants."""

from enum import Enum


class InputType(Enum):
    """Enum for output types."""

    PCAP_FILE = "pcap"
    INTERFACE = "interface"


class OutputType(Enum):
    """Enum for output types."""

    MQTT = "mqtt"
    STDOUT = "stdout"
