#!/usr/bin/env python3

from pathlib import Path

from scapy.layers.dhcp import BOOTP
from scapy.layers.inet import IP, UDP
from scapy.layers.l2 import Ether
from scapy.packet import Raw
from scapy.utils import wrpcap


TEST_DIR = Path(__file__).resolve().parent
MAGIC = bytes.fromhex("63 82 53 63")


def dhcp_ack(options, packet_number, sname=b"", boot_file=b""):
    packet = (
        Ether(src="02:00:00:00:00:01", dst="ff:ff:ff:ff:ff:ff")
        / IP(src="192.0.2.1", dst="255.255.255.255")
        / UDP(sport=67, dport=68)
        / BOOTP(
            op=2,
            htype=1,
            hlen=6,
            xid=0x12345680 + packet_number,
            flags=0x8000,
            yiaddr="192.0.2.100",
            siaddr="192.0.2.1",
            chaddr=bytes.fromhex("02 00 00 00 00 02") + bytes(10),
            sname=sname,
            file=boot_file,
            options=MAGIC,
        )
        / Raw(options)
    )
    packet.time = 1_723_370_500.0 + packet_number
    bootp = bytes(packet[BOOTP])
    assert bootp[44:108].startswith(sname)
    assert bootp[108:236].startswith(boot_file)
    assert bootp.endswith(MAGIC + options)
    return packet


# Option 51 has enough bytes for its value, but its declared length is invalid.
primary_malformed_options = bytes([53, 1, 5, 51, 1, 0, 0, 0x0E, 0x10, 255])

# Option 12 declares five bytes while only two remain in the UDP payload.
primary_truncated_options = bytes([53, 1, 5, 12, 5]) + b"ab"

# Option 52 value 2 selects sname, which contains an invalid option 51 length.
sname_options = bytes([51, 1, 0, 0, 0x0E, 0x10, 255])
overload_sname = bytes([53, 1, 5, 52, 1, 2, 255])

# Option 52 value 1 selects file. Its option declares 127 data bytes, but only
# 126 bytes remain in the fixed-size field after its code and length.
file_options = bytes([12, 127])
overload_file = bytes([53, 1, 5, 52, 1, 1, 255])

packets = [
    dhcp_ack(primary_malformed_options, 1),
    dhcp_ack(primary_truncated_options, 2),
    dhcp_ack(overload_sname, 3, sname=sname_options),
    dhcp_ack(overload_file, 4, boot_file=file_options),
]

wrpcap(str(TEST_DIR / "input.pcap"), packets)
