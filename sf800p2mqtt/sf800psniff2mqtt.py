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
  --output-dir=PATH       Output directory to store faulty packets.
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
import logging
import os
import sys
from pathlib import Path

from docopt import docopt

from .config import Config
from .constants import InputType, OutputType
from .handlers import (
    InputHandler,
    OutputHandler,
    InputHandlerFactory,
    OutputHandlerFactory
)
from .packet_processor import PacketProcessor
from .utils.logging import setup_logging

__appname__ = "SF800Pro2MQTT"
__version__ = "1.10.4"
__date__ = "2025-07-01"
__updated__ = "2025-08-10"
__author__ = "Ixtalo"
__email__ = "ixtalo@gmail.com"
__license__ = "AGPL-3.0+"
__status__ = "Production"


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


def run(config: Config,
        input_handler: InputHandler,
        output_handler: OutputHandler):
    """Run the sniffer to produce output messages."""
    # Check configuration
    assert config.filter_ip, "filter_ip (device IP to capture) is mandatory!"
    # Check for valid IP address format
    assert ipaddress.ip_address(config.filter_ip)

    # Connect output handler
    if not output_handler.connect():
        logging.error("Failed to connect output handler")
        return -1

    # Build a BPF filter to capture only MQTT PUBLISH messages
    bpf = (
        # Limit to IP and MQTT port
        f"(tcp port 1883) and (src host {config.filter_ip} or dst host {config.filter_ip})"
        # Limit to MQTT PUBLISH packets
        # PUBLISH = MsgType 3 --> upper Nibble 0x30–0x3F (first byte is 0x3x)
        " and ((tcp[((tcp[12] & 0xf0) >> 2)] & 0xf0) == 0x30)"
    )

    # Packet callback
    processor = PacketProcessor(config, output_handler)
    callback = processor.packet_callback

    try:
        # Start capture using input handler
        logging.debug("running with handler %s ...", input_handler)
        result = input_handler.start_capture(callback, bpf)
        logging.debug("input_handler capture result: %s", result)
        return result
    finally:
        # Cleanup
        output_handler.disconnect()


def main():     # pylint: disable=too-many-locals
    """Run main program entry.

    Returns:
        Exit/return code
    """
    version_string = f"{__appname__} {__version__} ({__updated__})"
    arguments = docopt(__doc__, version=version_string)

    arg_interface = arguments["<interface>"]
    arg_pcapfile = arguments["--file"]
    arg_logfile = arguments["--logfile"]
    arg_nocolor = arguments["--no-color"]
    arg_verbose = arguments["--verbose"]
    arg_stdout = arguments["--stdout"]

    config = Config.from_args_and_env(arguments)

    # Setup logging
    debug = bool(os.getenv("DEBUG", "").lower() in ("1", "true", "yes"))
    logging_level = logging.DEBUG if debug else \
        (logging.INFO if arg_verbose else logging.WARNING)
    setup_logging(arg_logfile, logging_level, arg_nocolor)
    # temporarily override level to output INFO level
    logging.getLogger().setLevel(logging.INFO)
    logging.info(version_string)
    logging.getLogger().setLevel(logging_level)

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
        # Check if the script has the right permissions for live capture
        if os.geteuid() != 0 and not has_cap_net_raw():
            logging.warning("This script requires root privileges or CAP_NET_RAW capability for live capture.")
    else:
        raise RuntimeError("unexpected input state")

    # Create input handler using factory
    input_handler = InputHandlerFactory.create_handler(input_type, str(source))

    # Determine output type
    output_type = OutputType.STDOUT if arg_stdout else OutputType.MQTT

    # Create output handler using factory
    output_handler = OutputHandlerFactory.create_handler(
        output_type,
        mqtt_host=config.mqtt_host,
        mqtt_port=config.mqtt_port,
        mqtt_user=config.mqtt_user,
        mqtt_pass=config.mqtt_pass
    )

    logging.info("Input type %s, output type %s", input_type.value.upper(), output_type.value.upper())

    if config.output_dir:
        logging.info("Output directory: %s", config.output_dir.resolve())

    return run(
        config=config,
        input_handler=input_handler,
        output_handler=output_handler
    )


if __name__ == "__main__":
    sys.exit(main())
