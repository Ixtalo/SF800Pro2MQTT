#!/usr/bin/env python3
import ipaddress
import json
import logging
import os
import re
import sys
import time
from collections import defaultdict
from scapy.all import sniff, Raw, TCP
import paho.mqtt.client as mqtt
import dotenv


# Load environment variables from .env file
# This allows configuration via environment variables or a .env file
dotenv.load_dotenv(verbose=True)

# MQTT configuration
MQTT_HOST = os.getenv("MQTT_HOST", "127.0.0.1")
MQTT_PORT = int(os.getenv("MQTT_PORT", 1883))
MQTT_USER = os.getenv("MQTT_USER", None)
MQTT_PASS = os.getenv("MQTT_PASS", None)
# Prefix for the published messages
MQTT_TOPIC_PREFIX = os.getenv("MQTT_TOPIC_PREFIX", "")
# Period in seconds to wait before publishing MQTT messages
PUBLISH_PERIOD_SECONDS=int(os.getenv("PUBLISH_PERIOD_SECONDS", 30))

# Interface to sniff on
IFACE = os.getenv("IFACE", "wlan0")
# Limit the sniffing to a specific IP address, i.e., IP of your SolarFlow
FILTER_IP = os.getenv("FILTER_IP")

# -------------------------------------------------------------------

# regex for extracting MQTT topic and payload from raw packet data
TOPIC_REGEX = re.compile(rb'[^/]*(/\w+/\w+/[\w]+/(?:energy|report|invoke)).*?({.*})', re.S)

_last_pub_per_topic = defaultdict(lambda: 0.0)


def is_systemd() -> bool:
    # Present for all processes started by a systemd unit
    return "INVOCATION_ID" in os.environ


def has_cap_net_raw() -> bool:
    """True if the current process has the CAP_NET_RAW
 capability in the effective set (Linux)."""
    try:
        with open("/proc/self/status") as f:
            for line in f:
                if line.startswith("CapEff:"):
                    value = int(line.split()[1], 16)  # Hex-String → int
                    CAP_NET_RAW = 1 << 13             # Nummer 13 → Bitmaske
                    return bool(value & CAP_NET_RAW)
    except FileNotFoundError:
        pass               # Nicht unter Linux /proc verfügbar
    return False


def extract_topic(raw: bytes):
    """Extracts MQTT topic and payload from raw packet data.
    
    :param raw: Raw packet data as bytes.
    :return: Tuple (topic, payload) or (None, None) if not found.
    """
    m = TOPIC_REGEX.search(raw)
    if not m:
        return None, None
    # Decode the topic and payload from bytes to string
    topic  = m.group(1).decode(errors='ignore')
    payload = m.group(2).decode(errors='ignore')
    # The payload is expected to be a JSON string, so we try to parse it
    try:
        # Load the JSON to ensure it's valid and compact it
        payload = json.dumps(json.loads(payload), separators=(',', ':'))
    except json.JSONDecodeError:
        pass
    return topic, payload


def pkt_cb(pkt):
    """Callback function for each packet captured by scapy."""
    # Check if the packet has TCP and Raw layers
    if not (pkt.haslayer(TCP) and pkt.haslayer(Raw)):
        return
    topic, payload = extract_topic(bytes(pkt[Raw].load))
    if topic:
        # Remove leading slash
        topic = topic.lstrip('/')
        # Add MQTT topic prefix if configured
        if MQTT_TOPIC_PREFIX:
            topic = f"{MQTT_TOPIC_PREFIX.rstrip('/')}/{topic}"
        # Publish to MQTT broker
        safe_publish(topic, payload)


def on_connect(client, *_):
    logging.info("MQTT connected")


def on_disconnect(client, _userdata, _flags, rc, _properties):
    logging.warning("MQTT disconnected (rc=%s) – retrying ...", rc)
    # simple retry loop; exponential back-off would be nicer
    while True:
        try:
            client.reconnect()
            logging.info("MQTT reconnected")
            return
        except Exception as e:
            logging.error("Reconnect failed: %s", e)
            time.sleep(5)


def safe_publish(topic, payload):
    """Safely publish a message to the MQTT broker."""
    now = time.time()
    if now - _last_pub_per_topic[topic] >= PUBLISH_PERIOD_SECONDS:
        _last_pub_per_topic[topic] = now
        logging.info("Publishing for topic '%s' ..." % topic)
        try:
            mqtt_cli.publish(topic, payload, qos=0, retain=False)
        except Exception as e:
            logging.error("publish() failed: %s", e)


def run():
    """Main function to run the MQTT sniffer."""
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
		f"(tcp port 1883) and src host {FILTER_IP} "
        # Limit to MQTT publish packets
		# PUBLISH = MsgType 3 --> upper Nibble 0x30–0x3F
		# first MQTT-Byte = 0x3x
		f"and ((tcp[((tcp[12] & 0xf0) >> 2)] & 0xf0) == 0x30)"
	)
    logging.info(f"Sniffing on {IFACE}, filter: '{bpf}' ...")
    try:
        # Start sniffing on the specified interface with the BPF filter
        sniff(iface=IFACE, filter=bpf, prn=pkt_cb, store=False)
    except KeyboardInterrupt:
        # Graceful shutdown on Ctrl+C
        logging.info("Stopping ...")
    except Exception as ex:
        logging.error("Error during sniffing: %s", ex)
        return -1
    finally:
        # cleanup
        mqtt_cli.loop_stop()
        mqtt_cli.disconnect()
    
    return 0


if __name__ == "__main__":
    # Set up logging
    logging.basicConfig(
        level=logging.WARNING if is_systemd() else logging.INFO, 
        format="%(asctime)s %(levelname)s %(msg)s"
    )

    # Check if the script is run with root privileges or has CAP_NET_RAW capability
    if os.geteuid() != 0 or not has_cap_net_raw():
        logging.warning("This script requires root privileges or CAP_NET_RAW capability.")
        sys.exit(-1)

    sys.exit(run())
