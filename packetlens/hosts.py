"""Bounded in-memory host profiles for packet and incident context."""
from collections import OrderedDict


class _Host:
    __slots__ = ("ip", "first_seen", "last_seen", "packets_in", "packets_out", "bytes_in",
                 "bytes_out", "peers", "peers_truncated", "ports", "protocols", "alert_count")

    def __init__(self, ip, ts):
        self.ip, self.first_seen, self.last_seen = ip, ts, ts
        self.packets_in = self.packets_out = self.bytes_in = self.bytes_out = self.alert_count = 0
        self.peers, self.ports, self.protocols = set(), {}, [0, 0, 0, 0, 0, 0]
        self.peers_truncated = False


class HostTable:
    """Track at most 50,000 hosts, 2,000 peers per host, and 64 candidate ports."""

    MAX_HOSTS = 50000
    MAX_PEERS = 2000
    MAX_PORTS = 64

    def __init__(self, max_hosts=MAX_HOSTS):
        self.max_hosts = max_hosts
        self._hosts = OrderedDict()

    def update(self, packet, protocol=None):
        """Update source/destination profiles; malformed/absent addresses are ignored."""
        try:
            src, dst = packet.src, packet.dst
            ts, size = float(packet.ts), int(packet.length)
            proto, dport = _PROTOCOL_IDS.get(protocol or _protocol_name(packet), 5), int(packet.dport)
            if not src and packet.arp is not None:
                src = packet.arp[2]
        except (AttributeError, TypeError, ValueError, OverflowError):
            return
        if size < 0:
            return
        if src:
            self._update_one(src, dst, ts, size, proto, dport, outbound=True)
        if dst:
            self._update_one(dst, src, ts, size, proto, dport, outbound=False)

    def _update_one(self, ip, peer, ts, size, proto, dport, outbound):
        host = self._hosts.get(ip)
        if host is None:
            host = _Host(ip, ts)
            self._hosts[ip] = host
        else:
            if ts < host.first_seen:
                host.first_seen = ts
            if ts >= host.last_seen:
                host.last_seen = ts
                self._hosts.move_to_end(ip)
        if outbound:
            host.packets_out += 1
            host.bytes_out += size
        else:
            host.packets_in += 1
            host.bytes_in += size
        host.protocols[proto] += 1
        if peer:
            if len(host.peers) < self.MAX_PEERS:
                host.peers.add(peer)
            elif peer not in host.peers:
                host.peers_truncated = True
        if outbound and 0 <= dport <= 65535:
            host.ports[dport] = host.ports.get(dport, 0) + 1
            if len(host.ports) > self.MAX_PORTS:
                host.ports = dict(sorted(host.ports.items(), key=lambda item: item[1], reverse=True)[:10])
        if len(self._hosts) > self.max_hosts:
            self._hosts.popitem(last=False)

    def record_alert(self, src, dst=""):
        """Increment alert counts for known source and destination profiles."""
        for ip in {src, dst} - {"", "many", "-"}:
            host = self._hosts.get(ip)
            if host is not None:
                host.alert_count += 1

    def snapshot(self):
        """Return JSON-compatible profiles; resident state is capped by MAX_HOSTS."""
        result = []
        for host in self._hosts.values():
            result.append({
                "ip": host.ip, "first_seen": host.first_seen, "last_seen": host.last_seen,
                "packets_in": host.packets_in, "packets_out": host.packets_out,
                "bytes_in": host.bytes_in, "bytes_out": host.bytes_out,
                "peers": sorted(host.peers), "peers_truncated": host.peers_truncated,
                "top_ports": [[port, count] for port, count in
                              sorted(host.ports.items(), key=lambda item: item[1], reverse=True)[:10]],
                "protocols": {name: host.protocols[index] for index, name in enumerate(_PROTOCOL_NAMES)
                              if host.protocols[index]},
                "alert_count": host.alert_count,
            })
        return result


_PROTOCOL_NAMES = ("DNS", "TCP", "UDP", "ICMP", "ARP", "Other")
_PROTOCOL_IDS = {name: index for index, name in enumerate(_PROTOCOL_NAMES)}


def _protocol_name(packet):
    if packet.dns is not None:
        return "DNS"
    if packet.proto == 6:
        return "TCP"
    if packet.proto == 17:
        return "UDP"
    if packet.proto in (1, 58):
        return "ICMP"
    return "ARP" if packet.ethertype == 0x0806 else "Other"
