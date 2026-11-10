"""Interactive live packet capture and optional PCAP recording with Scapy."""

import argparse
import errno
import re
import sys
from contextlib import ExitStack
from datetime import datetime, timezone
from pathlib import Path

try:
    from scapy.all import ARP, DNS, ICMP, IP, IPv6, TCP, UDP, conf, sniff
    from scapy.error import Scapy_Exception
    from scapy.layers.inet6 import ICMPv6EchoReply, ICMPv6EchoRequest, _ICMPv6, _IPv6ExtHdr
    from scapy.packet import NoPayload, Padding
    from scapy.utils import PcapWriter
except ModuleNotFoundError as error:
    if error.name != "scapy":
        raise
    sys.exit("Scapy is missing. Run: python -m pip install -r requirements.txt")


PREVIEW_BYTES = 60
SAFE_ASCII = bytes(byte if 32 <= byte <= 126 else ord(".") for byte in range(256))
HTTP_START = re.compile(
    rb"(?:[A-Z][A-Z0-9_-]* [!-~]+ HTTP/1\.[01]\r?\n"
    rb"|HTTP/1\.[01] [1-5][0-9]{2}(?: |\r?\n))"
)
IP_PROTOCOLS = {1: "ICMP", 6: "TCP", 17: "UDP", 58: "ICMP"}


def positive_count(value):
    try:
        count = int(value)
    except ValueError:
        count = 0
    if count < 1:
        raise argparse.ArgumentTypeError("count must be a positive integer")
    return count


def choose_interface():
    interfaces = list(conf.ifaces.values())
    if not interfaces:
        raise RuntimeError("No network interfaces are available for capture.")

    print("Network interfaces:")
    for number, interface in enumerate(interfaces, 1):
        description = ""
        if interface.description and interface.description != interface.name:
            description = f" ({interface.description})"
        print(f"  {number}. {interface.name}{description}")

    while True:
        try:
            choice = int(input("Choose an interface number: "))
        except ValueError:
            choice = 0
        if 1 <= choice <= len(interfaces):
            return interfaces[choice - 1]
        print(f"Enter a number from 1 to {len(interfaces)}.")


def payload_bytes(layer):
    if isinstance(layer, (NoPayload, Padding)):
        return b""

    # Scapy can attach Ethernet padding to the last decoded layer.
    data = bytes(layer)
    padding = layer.getlayer(Padding)
    if padding is not None:
        data = data[: len(data) - len(bytes(padding))]
    return data


def packet_fields(packet):
    # Follow the outer IP header so quoted or tunneled packets cannot supply its ports.
    network = packet
    while not isinstance(network, (IP, IPv6, NoPayload)):
        network = network.payload
    if isinstance(network, NoPayload):
        protocol = "ARP" if ARP in packet else "OTHER"
        return "-", "-", protocol, "-", "-", b""

    header = network
    while isinstance(header.payload, _IPv6ExtHdr):
        header = header.payload
    transport = header.payload
    protocol_number = network.proto if isinstance(network, IP) else header.nh
    protocol = IP_PROTOCOLS.get(protocol_number, f"IP/{protocol_number}")
    source_port = destination_port = "-"

    if isinstance(transport, (TCP, UDP)):
        source_port, destination_port = transport.sport, transport.dport
        data = payload_bytes(transport.payload)
        if isinstance(transport.payload, DNS):
            protocol = "DNS"
        elif isinstance(transport, TCP) and HTTP_START.match(data):
            protocol = "HTTP"
    elif isinstance(transport, (ICMPv6EchoRequest, ICMPv6EchoReply)):
        data = transport.data
    elif isinstance(transport, (ICMP, _ICMPv6)):
        data = payload_bytes(transport.payload)
    else:
        data = payload_bytes(transport)

    return network.src, network.dst, protocol, source_port, destination_port, data


def format_packet(packet):
    timestamp = datetime.fromtimestamp(float(packet.time), timezone.utc)
    source, destination, protocol, source_port, destination_port, data = packet_fields(packet)
    preview = data[:PREVIEW_BYTES].translate(SAFE_ASCII).decode("ascii")
    return (
        f"{timestamp.isoformat(timespec='milliseconds').replace('+00:00', 'Z')} | "
        f"{source} -> {destination} | {protocol} | "
        f"{source_port} -> {destination_port} | {preview or '-'}"
    )


def capture(interface, args):
    captured = 0
    writer = None
    callback_error = None

    with ExitStack() as resources:
        def handle_packet(packet):
            nonlocal captured, writer, callback_error
            # Scapy may handle socket errors internally. Report callback failures here.
            try:
                if args.save is not None:
                    if writer is None:
                        output = resources.enter_context(args.save.open("xb", buffering=0))
                        writer = PcapWriter(output, sync=True, snaplen=65535)
                    writer.write(packet)
                print(format_packet(packet), flush=True)
                captured += 1
            except (OSError, KeyError, Scapy_Exception, ValueError) as error:
                callback_error = error

        def show_header():
            print(f"Capturing on {interface.name}. Press Ctrl+C to stop.")
            print("Timestamp (UTC) | Source IP -> Destination IP | Protocol | "
                  "Source port -> Destination port | Payload preview")

        sniff(
            iface=interface,
            count=args.count,
            filter=args.filter,
            store=False,
            promisc=False,
            prn=handle_packet,
            stop_filter=lambda _: callback_error is not None,
            started_callback=show_header,
        )

    if callback_error is not None:
        raise RuntimeError(f"Could not process or save a packet: {callback_error}")
    print(f"Captured {captured} packet(s).")
    if writer is not None:
        print(f"Saved to {args.save}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--count", type=positive_count, default=0,
        help="stop after this many packets (default: until Ctrl+C)",
    )
    parser.add_argument(
        "--filter", metavar="BPF", help="capture only packets matching this BPF expression",
    )
    parser.add_argument(
        "--save", type=Path, metavar="FILE.pcap", help="save full packets to a new PCAP file",
    )
    args = parser.parse_args()

    try:
        if sys.platform == "win32" and not conf.use_pcap:
            raise RuntimeError("Scapy cannot load Npcap. Install or repair Npcap and try again.")
        if args.save is not None and args.save.exists():
            raise RuntimeError(f"Output already exists: {args.save}. Choose a new file.")
        capture(choose_interface(), args)
    except (KeyboardInterrupt, EOFError):
        print("\nStopped.")
        return 130
    except (OSError, RuntimeError, Scapy_Exception, ValueError) as error:
        print(f"Error: {error}", file=sys.stderr)
        details = str(error).lower()
        if (
            getattr(error, "errno", None) in (errno.EACCES, errno.EPERM)
            or getattr(error, "winerror", None) == 5
            or any(wording in details for wording in (
                "permission denied", "access is denied", "access denied",
                "operation not permitted", "administrator privileges",
            ))
        ):
            if sys.platform == "win32":
                print("For restricted Npcap capture, reopen your terminal as Administrator.",
                      file=sys.stderr)
            else:
                print("Packet capture may require root or packet-capture privileges.",
                      file=sys.stderr)
        elif sys.platform == "win32" and "adapter" in details:
            print("Check that Npcap is running and try an Administrator terminal if capture is restricted.",
                  file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
