#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""sf800psniff2mqtt.py - Solar battery SF800Pro to MQTT translator.

Capture TCP traffic from a SolarFlow 800 Pro solar battery and
extract information for publishing to an own (local) MQTT broker.

The tool is intended for quick, non-intrusive integrations of the “cloud only” /
"app only" IoT device, here the solar battery *SolarFlow 800 Pro*.

Usage:
  sf800psniff2mqtt.py [options]
  sf800psniff2mqtt.py -h | --help
  sf800psniff2mqtt.py --version

Arguments:
  None.

Options:
  -h --help         Show this screen.
  --logfile=FILE    Logging to FILE, otherwise use STDOUT.
  --no-color        No colored log output.
  -v --verbose      Be more verbose.
  --version         Show version.
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
from collections import defaultdict

import colorlog
from docopt import docopt
from scapy.all import sniff, Packet
from scapy.contrib.mqtt import MQTT
import paho.mqtt.client as mqtt
import dotenv


__appname__ = "SF800Pro2MQTT"
__version__ = "1.3.1"
__date__ = "2025-07-01"
__updated__ = "2025-07-19"
__author__ = "Ixtalo"
__email__ = "ixtalo@gmail.com"
__license__ = "AGPL-3.0+"
__status__ = "Production"


# Load environment variables from .env file
# This allows configuration via environment variables or a .env file
dotenv.load_dotenv(verbose=True)

# MQTT configuration
MQTT_HOST = os.getenv("MQTT_HOST", "127.0.0.1")
MQTT_PORT = int(os.getenv("MQTT_PORT", "1883"))
MQTT_USER = os.getenv("MQTT_USER")
MQTT_PASS = os.getenv("MQTT_PASS")
# Prefix for the published messages
MQTT_TOPIC_PREFIX = os.getenv("MQTT_TOPIC_PREFIX", "")
# Period in seconds to wait before publishing MQTT messages
PUBLISH_PERIOD_SECONDS = int(os.getenv("PUBLISH_PERIOD_SECONDS", "30"))
# Interface to sniff on
IFACE = os.getenv("IFACE", "wlan0")
# Limit the sniffing to a specific IP address, i.e., IP of your SolarFlow
FILTER_IP = os.getenv("FILTER_IP")

DEBUG = bool(os.getenv("DEBUG", "").lower() in ("1", "true", "yes"))
_last_pub_per_topic = defaultdict(lambda: 0.0)  # Last publish time per topic
mqtt_cli: mqtt.Client = None  # Global MQTT client instance
topics_blacklist: set = set()


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
    # filter all not TCP
    # if not pkt.haslayer(TCP):
    #    return
    
    mqtt_layer = None

    # Check if packet is of type MQTT PUBLISH
    # https://github.com/secdev/scapy/blob/7fb32a173f8567a498e25282da79569b5bf802bb/scapy/contrib/mqtt.py#L71
    try:
        mqtt_layer = pkt.getlayer(MQTT)
    except Exception as ex:
        logging.exception(ex)
        return
        
    if mqtt_layer and mqtt_layer.type == 3:  # type: ignore # 3=PUBLISH
        # Parse and check
        topic, payload = handle_mqtt_pkt(mqtt_layer)
        if topic and payload:
            if topic in topics_blacklist:
                logging.info("Topic '%s' is blacklisted - skipping!", topic)
            else:
                # Remove leading slash
                topic_new = topic.lstrip('/')
                # Add MQTT topic prefix if configured
                if MQTT_TOPIC_PREFIX:
                    topic_new = f"{MQTT_TOPIC_PREFIX.rstrip('/')}/{topic_new}"
                # Publish to MQTT broker
                safe_publish(topic_new, payload)
    else:
        try:
            logging.debug("Ignoring non MQTT-PUBLISH packet: %s", pkt.summary())
        except UnicodeDecodeError as ex:    # Unicode decoding failsafe
            logging.exception("Ignoring non MQTT-PUBLISH packet (not decodeable): %s", repr(pkt), exc_info=ex)


def json_dumps_compact(payload):
    """Compact JSON serialization without whitespace."""
    payload_compact = json.dumps(payload, separators=(',', ':'))
    return payload_compact


def on_connect(client, *_):
    """Handle callback for MQTT connection established."""
    logging.info("MQTT connected (%s)", client)


def on_disconnect(client, _userdata, _flags, rc, _properties):
    """Handle callback for MQTT disconnection."""
    logging.warning("MQTT disconnected (rc=%s) – retrying ...", rc)
    # simple retry loop; exponential back-off would be nicer
    while True:
        try:
            client.reconnect()
            return
        except Exception as e:  # pylint: disable=broad-except
            logging.error("Reconnect failed: %s", e)
            time.sleep(5)


def safe_publish(topic, payload):
    """Safely publish a message to the MQTT broker."""
    now = time.time()
    last_pub_secs = now - _last_pub_per_topic[topic]
    if last_pub_secs < PUBLISH_PERIOD_SECONDS:
        logging.debug("Skipping publishing topic '%s' (last published %.1f seconds ago)", topic, last_pub_secs)
    else:
        _last_pub_per_topic[topic] = now
        logging.info("Publishing topic '%s' ...", topic)
        try:
            mqtt_cli.publish(topic, payload, qos=0, retain=False)
        except Exception as e:  # pylint: disable=broad-except
            logging.error("publish() failed: %s", e)


def run():
    """Run the sniffer to produce MQTT messages."""
    global mqtt_cli, topics_blacklist       # pylint: disable=global-statement

    # Check configuration
    assert MQTT_HOST, "MQTT_HOST must not be empty!"
    assert 1 <= MQTT_PORT <= 65535, "MQTT_PORT out of range (1-65535)!"
    assert FILTER_IP, "FILTER_IP (device IP to capture) is mandatory!"
    # Check for valid IP address format
    ipaddress.ip_address(FILTER_IP)

    # Check if MQTT_USER and MQTT_PASS are set together
    assert (MQTT_USER is None and MQTT_PASS is None) or \
        (MQTT_USER and MQTT_PASS), \
        "MQTT_USER and MQTT_PASS must be set together!"

    # Check if the interface exists
    assert IFACE in os.listdir('/sys/class/net'), f"Interface {IFACE} not found!"

    # Topics to exclude from publishing
    topics_blacklist = set(os.getenv("TOPICS_BLACKLIST", "").split(","))
    # make sure it's an array
    if isinstance(topics_blacklist, str):
        topics_blacklist = set([topics_blacklist])

    # Establish MQTT connection
    mqtt_cli = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2)
    if MQTT_USER and MQTT_PASS:
        mqtt_cli.username_pw_set(MQTT_USER, MQTT_PASS)
    mqtt_cli.on_connect = on_connect
    mqtt_cli.on_disconnect = on_disconnect
    mqtt_cli.connect(MQTT_HOST, MQTT_PORT, 60)
    mqtt_cli.loop_start()

    # Build a BPF filter to capture only MQTT PUBLISH messages
    bpf = (
        # Limit to IP and MQTT port
        f"(tcp port 1883) and (src host {FILTER_IP} or dst host {FILTER_IP})"
        # Limit to MQTT PUBLISH packets
        # PUBLISH = MsgType 3 --> upper Nibble 0x30–0x3F (first byte is 0x3x)
        " and ((tcp[((tcp[12] & 0xf0) >> 2)] & 0xf0) == 0x30)"
    )
    logging.info("Sniffing on %s, filter: '%s' ...", IFACE, bpf)
    try:
        # Start sniffing on the specified interface with the BPF filter
        # https://scapy.readthedocs.io/en/latest/api/scapy.sendrecv.html#scapy.sendrecv.sniff
        sniff(iface=IFACE, filter=bpf, prn=pkt_cb, store=False)
    except KeyboardInterrupt:
        # Graceful shutdown on Ctrl+C
        logging.info("Stopping ...")
    except Exception as ex:     # pylint: disable=broad-except
        logging.error("Error during sniffing: %s", ex)
        return -1
    finally:
        # cleanup
        mqtt_cli.loop_stop()
        mqtt_cli.disconnect()

    return 0


def main():
    """Run main program entry.

    :return: exit/return code
    """
    version_string = f"{__appname__} {__version__} ({__updated__})"
    arguments = docopt(__doc__, version=version_string)
    # print(arguments)
    arg_logfile = arguments["--logfile"]
    arg_nocolor = arguments["--no-color"]
    arg_verbose = arguments["--verbose"]

    logging_level = logging.DEBUG if DEBUG else \
        (logging.INFO if arg_verbose else logging.WARNING)
    setup_logging(arg_logfile, logging_level, arg_nocolor)
    logging.info(version_string)

    # Check if the script is run with root privileges or has CAP_NET_RAW capability
    if os.geteuid() != 0 or not has_cap_net_raw():
        logging.warning("This script requires root privileges or CAP_NET_RAW capability.")

    return run()


if __name__ == "__main__":
    sys.exit(main())
