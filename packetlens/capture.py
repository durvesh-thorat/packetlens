"""Live packet capture with a raw Linux socket (AF_PACKET). Needs root or CAP_NET_RAW."""
import socket
import time

ETH_P_ALL = 0x0003


def live_packets(interface=None):
    """Yield (timestamp, frame_bytes) forever. Captures only traffic you are allowed to observe."""
    if not hasattr(socket, "AF_PACKET"):
        raise RuntimeError("Live capture needs Linux (AF_PACKET). On Windows use WSL2 or a Linux "
                           "virtual machine, or analyse a saved pcap file instead.")
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
    if interface:
        s.bind((interface, 0))
    try:
        while True:
            data, _ = s.recvfrom(65535)
            yield time.time(), data
    finally:
        s.close()
