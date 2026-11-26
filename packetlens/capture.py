"""Live packet capture with a raw Linux socket (AF_PACKET). Needs root or CAP_NET_RAW."""
import socket
import time

from .parsers import LINKTYPE_ETHERNET

ETH_P_ALL = 0x0003
ARPHRD_ETHER = 1
ARPHRD_LOOPBACK = 772
_ETHERNET_HATYPES = {ARPHRD_ETHER, ARPHRD_LOOPBACK}


def live_linktype(hatype):
    """Map a Linux AF_PACKET hardware type to a supported PacketLens linktype, or None."""
    return LINKTYPE_ETHERNET if hatype in _ETHERNET_HATYPES else None


def live_packets(interface=None, stop_event=None, timeout=0.5):
    """Yield (timestamp, frame_bytes, linktype) until stopped.

    Captures only traffic you are allowed to observe.
    """
    if not hasattr(socket, "AF_PACKET"):
        raise RuntimeError("Live capture needs Linux (AF_PACKET). On Windows use WSL2 or a Linux "
                           "virtual machine, or analyse a saved pcap file instead.")
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
    s.settimeout(timeout)
    try:
        if interface:
            s.bind((interface, 0))
            sockname = s.getsockname()
            if isinstance(sockname, tuple) and len(sockname) >= 4:
                if live_linktype(sockname[3]) is None:
                    raise RuntimeError(
                        f"Unsupported live interface hardware type {sockname[3]} on {interface!r}. "
                        "Supported: Ethernet (1) and loopback (772)."
                    )
        while stop_event is None or not stop_event.is_set():
            try:
                data, addr = s.recvfrom(65535)
            except (TimeoutError, socket.timeout):
                continue
            hatype = addr[3] if isinstance(addr, tuple) and len(addr) >= 4 else ARPHRD_ETHER
            linktype = live_linktype(hatype)
            if linktype is None:
                if interface:
                    raise RuntimeError(
                        f"Unsupported live interface hardware type {hatype} on {interface!r}."
                    )
                continue
            yield time.time(), data, linktype
    finally:
        s.close()
