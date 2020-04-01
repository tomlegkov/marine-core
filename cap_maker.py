import struct
import random
from typing import List, Union, Type
import os

from pypacker.layer12 import ethernet
from pypacker.layer3 import ip
from pypacker.layer4 import tcp, udp

PCAP_HEADER = bytes.fromhex("D4C3B2A10200040000000000000000000000040001000000")

SRC_MAC = "00:00:00:9f:f8:3b"
DST_MAC = "00:00:00:87:7e:0e"
SRC_IP = "88.44.85.145"
DST_IP = "212.110.118.170"
PORTS = list(range(4000, 4020))

# Split evenly between each size
PACKETS_PER_CONVERSATION = 1000

# Split evenly between TCP and UDP
CONVERSATIONS = 210


def write_cap(file_path: str, packets: List[bytes]):
    with open(file_path, "wb") as f:
        f.write(PCAP_HEADER)
        for packet in packets:
            packet_length = len(packet)
            f.write(struct.pack("<IIII", 0, 0, packet_length, packet_length) + packet)


def create_packet(
    protocol: Union[Type[tcp.TCP], Type[udp.UDP]], src_port: int, dst_port: int
) -> bytes:
    protocol_number = ip.IP_PROTO_TCP if protocol == tcp.TCP else ip.IP_PROTO_UDP
    packet = (
        ethernet.Ethernet(src_s=SRC_MAC, dst_s=DST_MAC)
        + ip.IP(p=protocol_number, src_s=SRC_IP, dst_s=DST_IP)
        + protocol(sport=src_port, dport=dst_port)
    )
    packet[protocol].body_bytes = os.urandom(random.randint(500, 1000))
    return packet.bin()


def create_conversation(protocol: Union[Type[tcp.TCP], Type[udp.UDP]]) -> List[bytes]:
    src_port = random.choice(PORTS)
    dst_port = random.choice(PORTS)
    for p in range(PACKETS_PER_CONVERSATION // 2):
        yield create_packet(protocol, src_port, dst_port)
        yield create_packet(protocol, dst_port, src_port)


if __name__ == "__main__":
    packets: List[bytes] = []
    for _ in range(CONVERSATIONS // 2):
        packets.extend(create_conversation(tcp.TCP))
        packets.extend(create_conversation(udp.UDP))

    random.shuffle(packets)

    write_cap("benchmark.cap", packets)
    bpf = " or ".join(f"udp port {port} or tcp port {port}" for port in PORTS)
    display_filter = " or ".join(
        f"udp.port == {port} or tcp.port == {port}" for port in PORTS
    )
    print("BPF:", bpf)
    print("Display filter:", display_filter)
