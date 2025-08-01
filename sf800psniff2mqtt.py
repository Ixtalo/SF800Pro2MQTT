#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""sf800psniff2mqtt.py - Solar battery SF800Pro to MQTT translator.

Capture TCP traffic from a SolarFlow 800 Pro solar battery and
extract information for publishing to an own (local) MQTT broker or STDOUT.

The tool is intended for quick, non-intrusive integrations of the "cloud only" /
"app only" IoT device, here the solar battery *SolarFlow 800 Pro*.

Usage:
  sf800psniff2mqtt.py [options] <interface> <filter-ip>
  sf800psniff2mqtt.py [options] --file=FILE <filter-ip>
  sf800psniff2mqtt.py -h | --help
  sf800psniff2mqtt.py --version

Arguments:
  interface-or-pcapfile   Interface name (e.g., wlan0) or PCAP file.
  filter-ip               IP address to filter packets (required).

Options:
  -h --help               Show this screen.
  --logfile=FILE          Logging to FILE, otherwise use STDOUT.
  --no-color              No colored log output.
  --file=FILE             PCAP capture file (e.g. from tcpdump).
  --stdout                Output to STDOUT instead of MQTT.
  --mqtt-host=HOST        MQTT broker host [default: 127.0.0.1].
  --mqtt-port=PORT        MQTT broker port [default: 1883].
  --mqtt-user=USER        MQTT username.
  --mqtt-pass=PASS        MQTT password.
  --mqtt-prefix=PREFIX    MQTT topic prefix.
  --publish-period=SEC    Publish period in seconds [default: 30].
  --topics-blacklist=LIST Comma-separated list of topics to exclude.
  -v --verbose            Be more verbose.
  --version               Show version.
"""
#
# LICENSE:
#
# Copyright (c) 2025 by Ixtalo, ixtalo@gmail.com
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#
import ipaddress
import json
import logging
import os
import sys
import time
from abc import ABC, abstractmethod
from collections import defaultdict
from enum import Enum
from pathlib import Path
from typing import Callable

import colorlog
from docopt import docopt
from scapy.all import sniff, Packet
from scapy.contrib.mqtt import MQTT
from scapy.arch.linux import L2ListenSocket
import paho.mqtt.client as mqtt
import dotenv
from scapy.data import MTU


__appname__ = "SF800Pro2MQTT"
__version__ = "1.7.3"
__date__ = "2025-07-01"
__updated__ = "2025-08-01"
__author__ = "Ixtalo"
__email__ = "ixtalo@gmail.com"
__license__ = "AGPL-3.0+"
__status__ = "Production"


# Global configuration
_publish_period_seconds = 30
_last_pub_per_topic = defaultdict(lambda: 0.0)  # Last publish time per topic
_mqtt_topic_prefix = ""
_topics_blacklist: set = set()
_output_handler = None  # Global output handler instance


# ------------------------------------------------------------------


class MyL2ListenSocket(L2ListenSocket):
    """Override for conf.L2Listen."""

    def recv(self, x: int = MTU, **kwargs) -> Packet | None:
        """Override the recv method and catches exceptions.

        Args:
            x: The number of bytes to read from the socket.

        Returns:
            The received bytes if no error occurs, None if error.
        """
        try:
            return super().recv(x, **kwargs)
        except UnicodeDecodeError as ex:
            logging.warning("UnicodeDecodeError when receiving bytes: %s", ex)
        except Exception as ex:
            logging.exception("recv() failed: %s", ex)
        return None


class OutputType(Enum):
    """Enum for output types."""

    MQTT = "mqtt"
    STDOUT = "stdout"


class OutputHandler(ABC):
    """Abstract base class for output handlers."""

    @abstractmethod
    def connect(self) -> bool:
        """Connect to the output destination. Returns True if successful."""

    @abstractmethod
    def publish(self, topic: str, payload: str) -> bool:
        """Publish a message. Returns True if successful."""

    @abstractmethod
    def disconnect(self):
        """Disconnect from the output destination."""


class MqttOutputHandler(OutputHandler):
    """MQTT output handler implementation."""

    def __init__(self, host="127.0.0.1", port=1883, username=None, password=None):
        """Initialize MQTT output handler.

        Args:
            host: MQTT broker hostname
            port: MQTT broker port
            username: MQTT username (optional)
            password: MQTT password (optional)
        """
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2)
        self._setup_callbacks()

    def _setup_callbacks(self):
        """Set up MQTT client callbacks."""
        self.client.on_connect = self._on_connect
        self.client.on_disconnect = self._on_disconnect
        if self.username and self.password:
            self.client.username_pw_set(self.username, self.password)

    def _on_connect(self, client, *_):
        """Handle callback for MQTT connection established."""
        logging.info("MQTT connected (%s)", client)

    def _on_disconnect(self, client, _userdata, _flags, rc, _properties):
        """Handle callback for MQTT disconnection."""
        logging.warning("MQTT disconnected (rc=%s) – retrying ...", rc)
        # Simple retry loop; exponential back-off would be nicer
        while True:
            try:
                client.reconnect()
                return
            except Exception as e:  # pylint: disable=broad-except
                logging.error("Reconnect failed: %s", e)
                time.sleep(5)

    def connect(self) -> bool:
        """Connect to MQTT broker."""
        try:
            self.client.connect(self.host, self.port, keepalive=60)
            self.client.loop_start()
            return True
        except Exception as e:  # pylint: disable=broad-except
            logging.error("Failed to connect to MQTT broker: %s", e)
            return False

    def publish(self, topic: str, payload: str) -> bool:
        """Publish message to MQTT broker."""
        try:
            self.client.publish(topic, payload, qos=0, retain=False)
            return True
        except Exception as e:  # pylint: disable=broad-except
            logging.error("MQTT publish failed: %s", e)
            return False

    def disconnect(self):
        """Disconnect from MQTT broker."""
        try:
            self.client.loop_stop()
            self.client.disconnect()
        except Exception as e:  # pylint: disable=broad-except
            logging.error("MQTT disconnect failed: %s", e)


class StdoutOutputHandler(OutputHandler):
    """STDOUT output handler implementation."""

    def __init__(self):
        """Initialize STDOUT output handler."""
        self.connected = False

    def connect(self) -> bool:
        """Connect to STDOUT (always successful)."""
        self.connected = True
        return True

    def publish(self, topic: str, payload: str) -> bool:
        """Print message to STDOUT."""
        try:
            timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
            print(f"[{timestamp}] {topic}: {payload}", flush=True)
            return True
        except Exception as e:  # pylint: disable=broad-except
            logging.error("STDOUT publish failed: %s", e)
            return False

    def disconnect(self):
        """Disconnect from STDOUT."""
        self.connected = False


class OutputHandlerFactory:
    """Factory for creating output handlers."""

    @staticmethod
    def create_handler(output_type: OutputType, **kwargs) -> OutputHandler:
        """Create an output handler based on the specified type.

        Args:
            output_type: Type of output handler to create
            **kwargs: Additional arguments for handler initialization

        Returns:
            OutputHandler: The created output handler

        Raises:
            ValueError: If output_type is not supported
        """
        if output_type == OutputType.MQTT:
            return MqttOutputHandler(
                host=kwargs.get('mqtt_host', '127.0.0.1'),
                port=kwargs.get('mqtt_port', 1883),
                username=kwargs.get('mqtt_user'),
                password=kwargs.get('mqtt_pass')
            )
        if output_type == OutputType.STDOUT:
            return StdoutOutputHandler()
        # else
        raise ValueError(f"Unsupported output type: {output_type}")


class InputType(Enum):
    """Enum for output types."""

    PCAP_FILE = "pcap"
    INTERFACE = "interface"


class InputHandler(ABC):
    """Abstract base class for input handlers."""

    @abstractmethod
    def start_capture(self, packet_callback: Callable, bpf_filter: str) -> int:
        """Start packet capture. Returns 0 on success, -1 on error."""


class LiveInputHandler(InputHandler):
    """Live network interface input handler."""

    def __init__(self, interface: str):
        """Initialize live input handler.

        Args:
            interface: Network interface name to capture from
        """
        self.interface = interface

    def start_capture(self, packet_callback: Callable, bpf_filter: str) -> int:
        """Start live packet capture from network interface."""
        logging.info("Sniffing on %s, filter: '%s' ...", self.interface, bpf_filter)
        try:
            from functools import partial
            l2socket_class = partial(MyL2ListenSocket, filter=bpf_filter)
            sniff(iface=self.interface, L2socket=l2socket_class, prn=packet_callback, store=False)
            return 0
        except KeyboardInterrupt:
            logging.info("Stopping live capture...")
            return 0
        except Exception as ex:
            logging.exception("Error during live sniffing: %s", ex)
            return -1


class PcapInputHandler(InputHandler):
    """PCAP file input handler."""

    def __init__(self, pcap_file: Path):
        """Initialize PCAP input handler.

        Args:
            pcap_file: Path to PCAP file to read
        """
        self.pcap_file = pcap_file
        if not pcap_file.exists():
            raise FileNotFoundError(f"PCAP file not found: {pcap_file.resolve()}")

    def start_capture(self, packet_callback: Callable, bpf_filter: str) -> int:
        """Start packet capture from PCAP file."""
        logging.info("Reading PCAP file '%s', filter: '%s' ...", self.pcap_file.name, bpf_filter)
        try:
            sniff(offline=str(self.pcap_file), prn=packet_callback, filter=bpf_filter)
            logging.info("Finished reading PCAP file")
            return 0
        except Exception as ex:
            logging.exception("Error reading PCAP file: %s", ex)
            return -1


class InputHandlerFactory:
    """Factory for creating input handlers."""

    @staticmethod
    def create_handler(input_type: InputType, source: str) -> InputHandler:
        """Create an input handler based on parameters.

        Returns:
            InputHandler: The created input handler
        """
        if input_type == InputType.PCAP_FILE:
            return PcapInputHandler(pcap_file=Path(source))
        if input_type == InputType.INTERFACE:
            return LiveInputHandler(interface=source)
        # else
        raise ValueError(f"Unsupported input type: {input_type}")


def setup_logging(log_file: str | None = None, level: int = logging.INFO, no_color=False):
    """Set up the logging framework."""
    if log_file:
        # pylint: disable=consider-using-with
        stream = open(log_file, "a", encoding="utf8")
        no_color = True
    else:
        stream = sys.stdout
    handler = colorlog.StreamHandler(stream=stream)
    handler.setFormatter(
        colorlog.ColoredFormatter(
            "%(log_color)s%(asctime)s %(levelname)-8s %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
            no_color=no_color
        )
    )
    logging.basicConfig(level=level, handlers=[handler])
    return handler


def has_cap_net_raw() -> bool:
    """Check if the current process has the CAP_NET_RAW capability."""
    try:
        with open("/proc/self/status", encoding="utf8") as f:
            for line in f:
                if line.startswith("CapEff:"):
                    value = int(line.split()[1], 16)    # Hex-String → int
                    CAP_NET_RAW = 1 << 13               # pylint: disable=invalid-name
                    return bool(value & CAP_NET_RAW)    # pylint: disable=invalid-name
    except FileNotFoundError:
        pass
    return False


def handle_mqtt_pkt(mqtt_pkt: Packet) -> tuple[str, str] | tuple[str, None] | tuple[None, None]:
    """Handle MQTT packet and extract topic and payload."""
    # Check if the packet is a valid MQTT PUBLISH packet
    assert mqtt_pkt.type == 3, "Packet must be MQTT PUBLISH packet!"

    topic = mqtt_pkt.topic
    payload = mqtt_pkt.payload.value

    if not topic:
        logging.warning("No MQTT topic found in packet (bytes %d)! Packet: %s", len(mqtt_pkt), mqtt_pkt.summary())
        return None, None

    if isinstance(topic, bytes):
        topic = topic.decode("utf8")

    # Payload (MQTT value) checks
    if not payload:
        logging.warning("Empty payload for topic '%s'", topic)
        return topic, None
    try:
        # Load the JSON to ensure it's valid
        payload_json = json.loads(payload)
    except json.JSONDecodeError as ex:
        logging.warning("Invalid JSON payload for topic '%s': %s", topic, ex)
        return topic, None
    # Check if the payload is empty after loading JSON
    if not payload_json:
        logging.warning("Empty JSON payload for topic '%s'", topic)
        return topic, None

    # Check if a payload with properties contains less than one property
    if "properties" in payload_json and len(payload_json["properties"]) <= 1 \
            and "packNum" in payload_json["properties"]:
        logging.info("Ignoring (irrelevant) message with less than 1 property in 'packNum', topic '%s'", topic)
        return topic, None

    # Compact JSON serialization without whitespace
    payload_compact = json_dumps_compact(payload_json)

    return topic, payload_compact


def pkt_cb(pkt):
    """Handle callback function for each packet captured by scapy."""
    # Check if packet is of type MQTT PUBLISH
    # https://github.com/secdev/scapy/blob/7fb32a173f8567a498e25282da79569b5bf802bb/scapy/contrib/mqtt.py#L71
    mqtt_layer = pkt.getlayer(MQTT)
    if mqtt_layer and mqtt_layer.type == 3:  # type: ignore # 3=PUBLISH
        # Parse and check
        topic, payload = handle_mqtt_pkt(mqtt_layer)
        if topic and payload:
            if topic in _topics_blacklist:
                logging.info("Topic '%s' is blacklisted - skipping!", topic)
            else:
                # Add MQTT topic prefix if configured
                if _mqtt_topic_prefix:
                    topic = f"{_mqtt_topic_prefix}/{topic.lstrip('/')}"
                # Publish via output handler
                publish(topic, payload)
    else:
        logging.debug("Ignoring non MQTT-PUBLISH packet: %s", pkt.summary())


def json_dumps_compact(payload):
    """Compact JSON serialization without whitespace."""
    payload_compact = json.dumps(payload, separators=(',', ':'))
    return payload_compact


def publish(topic, payload):
    """Safely publish a message via the output handler."""
    assert _output_handler, "No useable output handler!"
    now = time.time()
    last_pub_secs = now - _last_pub_per_topic[topic]
    if last_pub_secs < _publish_period_seconds:
        logging.debug("Skipping publishing topic '%s' (last published %.1f seconds ago)", topic, last_pub_secs)
    else:
        _last_pub_per_topic[topic] = now
        logging.info("Publishing topic '%s' ...", topic)
        _output_handler.publish(topic, payload)


def run(input_handler: InputHandler, filter_ip: str, output_handler: OutputHandler):
    """Run the sniffer to produce output messages.

    Args:
        input_handler: Input handler for packet capture
        filter_ip: IP address to filter packets
        output_handler: Output handler for publishing messages
    """
    # Check configuration
    assert filter_ip, "filter_ip (device IP to capture) is mandatory!"
    # Check for valid IP address format
    ipaddress.ip_address(filter_ip)

    # Set global output handler
    global _output_handler
    _output_handler = output_handler

    # Connect output handler
    if not output_handler.connect():
        logging.error("Failed to connect output handler")
        return -1

    # Build a BPF filter to capture only MQTT PUBLISH messages
    bpf = (
        # Limit to IP and MQTT port
        f"(tcp port 1883) and (src host {filter_ip} or dst host {filter_ip})"
        # Limit to MQTT PUBLISH packets
        # PUBLISH = MsgType 3 --> upper Nibble 0x30–0x3F (first byte is 0x3x)
        " and ((tcp[((tcp[12] & 0xf0) >> 2)] & 0xf0) == 0x30)"
    )

    try:
        # Start capture using input handler
        logging.debug("running with handler %s ...", input_handler)
        result = input_handler.start_capture(pkt_cb, bpf)
        logging.debug("input_handler capture result: %s", result)
        return result
    finally:
        # Cleanup
        output_handler.disconnect()


def main():
    """Run main program entry.

    Returns:
        Exit/return code
    """
    version_string = f"{__appname__} {__version__} ({__updated__})"
    arguments = docopt(__doc__, version=version_string)

    # Parse CLI arguments
    arg_filter_ip = arguments["<filter-ip>"]
    arg_interface = arguments["<interface>"]
    arg_pcapfile = arguments["--file"]
    arg_logfile = arguments["--logfile"]
    arg_nocolor = arguments["--no-color"]
    arg_verbose = arguments["--verbose"]
    arg_stdout = arguments["--stdout"]
    arg_mqtt_host = arguments["--mqtt-host"]
    arg_mqtt_port = int(arguments["--mqtt-port"])
    arg_mqtt_user = arguments["--mqtt-user"]
    arg_mqtt_pass = arguments["--mqtt-pass"]
    arg_mqtt_prefix = arguments["--mqtt-prefix"] or ""
    arg_publish_period = int(arguments["--publish-period"])
    arg_topics_blacklist = arguments["--topics-blacklist"] or ""

    # Load environment variables from .env file (or environment) as fallback
    dotenv.load_dotenv(verbose=True)

    # Determine output type
    output_type = OutputType.STDOUT if arg_stdout else OutputType.MQTT

    # MQTT configuration with CLI args taking precedence
    mqtt_host = arg_mqtt_host or os.getenv("MQTT_HOST", "127.0.0.1")
    mqtt_port = arg_mqtt_port if arg_mqtt_port != 1883 else int(os.getenv("MQTT_PORT", "1883"))
    mqtt_user = arg_mqtt_user or os.getenv("MQTT_USER")
    mqtt_pass = arg_mqtt_pass or os.getenv("MQTT_PASS")

    # Global configuration
    global _mqtt_topic_prefix, _publish_period_seconds, _topics_blacklist
    _mqtt_topic_prefix = (arg_mqtt_prefix or os.getenv("MQTT_TOPIC_PREFIX", "")).rstrip("/")
    _publish_period_seconds = arg_publish_period if arg_publish_period != 30 else \
        int(os.getenv("PUBLISH_PERIOD_SECONDS", "30"))
    _topics_blacklist = set([v.strip() for v in
                             (arg_topics_blacklist or os.getenv("TOPICS_BLACKLIST", "")).split(",") if v.strip()])

    # Setup logging
    debug = bool(os.getenv("DEBUG", "").lower() in ("1", "true", "yes"))
    logging_level = logging.DEBUG if debug else \
        (logging.INFO if arg_verbose else logging.WARNING)
    setup_logging(arg_logfile, logging_level, arg_nocolor)
    logging.info(version_string)

    # Determine input
    input_type = None
    source = None
    if arg_pcapfile:
        input_type = InputType.PCAP_FILE
        source = Path(arg_pcapfile)
        assert source.is_file(), f"PCAP input file must exist! ({source.resolve()})"
    elif arg_interface:
        input_type = InputType.INTERFACE
        source = arg_interface
        # Check if the script is run with root privileges or has CAP_NET_RAW capability
        # (only needed for live capture)
        if os.geteuid() != 0 or not has_cap_net_raw():
            logging.warning("This script requires root privileges or CAP_NET_RAW capability for live capture.")
    else:
        raise RuntimeError("unexpected input state")

    # Create input handler using factory
    input_handler = InputHandlerFactory.create_handler(input_type, str(source))

    # Create output handler using factory
    output_handler = OutputHandlerFactory.create_handler(
        output_type,
        mqtt_host=mqtt_host,
        mqtt_port=mqtt_port,
        mqtt_user=mqtt_user,
        mqtt_pass=mqtt_pass
    )

    logging.info("Input type %s, output type %s", input_type.value.upper(), output_type.value.upper())
    return run(input_handler=input_handler,
               filter_ip=arg_filter_ip,
               output_handler=output_handler)


if __name__ == "__main__":
    sys.exit(main())
