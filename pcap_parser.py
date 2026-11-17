"""Lettore minimale e veloce di file pcap / pcapng (anche .gz).

Estrae solo gli indirizzi IP sorgente/destinazione di ogni pacchetto, senza
dissezionare l'intero stack come fa Scapy: ~100x piu' veloce e a memoria
costante (il file viene letto in streaming).
"""
from __future__ import annotations

import gzip
import socket
import struct
from collections import Counter

# magic pcap classico -> endianness
PCAP_MAGICS = {
    b"\xd4\xc3\xb2\xa1": "<",  # little endian, microsecondi
    b"\xa1\xb2\xc3\xd4": ">",  # big endian, microsecondi
    b"\x4d\x3c\xb2\xa1": "<",  # little endian, nanosecondi
    b"\xa1\xb2\x3c\x4d": ">",  # big endian, nanosecondi
}
PCAPNG_SHB = b"\x0a\x0d\x0d\x0a"

LINKTYPE_NULL = 0
LINKTYPE_ETHERNET = 1
LINKTYPE_RAW_ALT = (12, 14, 101, 228, 229)  # IP "nudo" (v4 o v6, decide il nibble)
LINKTYPE_LOOP = 108
LINKTYPE_LINUX_SLL = 113
LINKTYPE_LINUX_SLL2 = 276

SUPPORTED_LINKTYPES = {
    LINKTYPE_NULL,
    LINKTYPE_ETHERNET,
    LINKTYPE_LOOP,
    LINKTYPE_LINUX_SLL,
    LINKTYPE_LINUX_SLL2,
    *LINKTYPE_RAW_ALT,
}

MAX_PACKET_LEN = 64 * 1024 * 1024  # oltre = file corrotto
PROGRESS_EVERY = 20000  # pacchetti tra una notifica di avanzamento e l'altra


class PcapParseError(ValueError):
    """File non leggibile come pcap/pcapng."""


class CaptureStats:
    def __init__(self, max_pairs=None, progress=None, tell=None):
        self.pairs: Counter = Counter()  # (src_bytes, dst_bytes) -> n pacchetti
        self.protocols: Counter = Counter()
        self.protocol_pairs: dict[str, Counter] = {}
        self.records: list[dict] = []
        self.packets = 0
        self.non_ip = 0
        self.truncated = False
        self.unsupported_linktypes: set[int] = set()
        # tetto alle coppie IP distinte (protegge la RAM con catture tipo scansione)
        self.max_pairs = max_pairs or float("inf")
        self.dropped_packets = 0  # pacchetti con coppie oltre il tetto
        self.progress = progress  # callback(byte_letti, pacchetti)
        self.tell = tell

    @property
    def ip_packets(self):
        return self.packets - self.non_ip

    def add(self, data: bytes, linktype):
        self.packets += 1
        if self.progress is not None and self.packets % PROGRESS_EVERY == 0:
            self.progress(self.tell() if self.tell else 0, self.packets)

        addrs = packet_ip_addrs(data, linktype)
        protos = packet_protocols(data, linktype)
        for proto in protos:
            self.protocols[proto] += 1

        record = {
            "data": data,
            "linktype": linktype,
            "source": None,
            "destination": None,
            "protocols": set(protos),
        }
        if addrs is not None:
            record["source"] = format_ip(addrs[0])
            record["destination"] = format_ip(addrs[1])
        self.records.append(record)

        if addrs is None:
            self.non_ip += 1
            if linktype is not None and linktype not in SUPPORTED_LINKTYPES:
                self.unsupported_linktypes.add(linktype)
            return

        pairs = self.pairs
        if addrs in pairs or len(pairs) < self.max_pairs:
            pairs[addrs] += 1
            for proto in protos:
                self.protocol_pairs.setdefault(proto, Counter())[addrs] += 1
        else:
            self.dropped_packets += 1


def packet_protocols(buf: bytes, linktype):
    """Ritorna una mini lista di protocolli osservati in ogni pacchetto."""
    seen: set[str] = set()

    def add_ip_transport(proto: int, payload: bytes):
        if proto == 1:
            seen.add("icmp")
        elif proto == 6:
            seen.add("tcp")
            if len(payload) >= 4:
                src_port, dst_port = struct.unpack("!HH", payload[:4])
                if src_port == 53 or dst_port == 53:
                    seen.add("dns")
                if src_port in (80, 8080, 8000) or dst_port in (80, 8080, 8000):
                    seen.add("http")
                if src_port in (443, 8443) or dst_port in (443, 8443):
                    seen.add("tls")
        elif proto == 17:
            seen.add("udp")
            if len(payload) >= 4:
                src_port, dst_port = struct.unpack("!HH", payload[:4])
                if src_port == 53 or dst_port == 53:
                    seen.add("dns")
                if src_port in (53, 5353) or dst_port in (53, 5353):
                    seen.add("dns")
                if src_port in (443, 8443) or dst_port in (443, 8443):
                    seen.add("quic")
        elif proto == 58:
            seen.add("icmpv6")
        elif proto == 132:
            seen.add("sctp")

    def add_ip_at_offset(off: int):
        if len(buf) < off + 1:
            return
        version = buf[off] >> 4
        if version == 4:
            seen.add("ipv4")
            if len(buf) >= off + 20:
                add_ip_transport(buf[off + 9], buf[off + 20:])
        elif version == 6:
            seen.add("ipv6")
            if len(buf) >= off + 40:
                add_ip_transport(buf[off + 6], buf[off + 40:])

    def add_ethernet_frame(off: int, ethertype: int):
        while ethertype in (0x8100, 0x88A8, 0x9100):
            if len(buf) < off + 4:
                return
            ethertype = (buf[off + 2] << 8) | buf[off + 3]
            off += 4

        if ethertype == 0x0806:
            seen.add("arp")
        elif ethertype in (0x0800, 0x86DD):
            add_ip_at_offset(off)
        elif ethertype in (0x8847, 0x8848):
            while True:
                if len(buf) < off + 4:
                    return
                bottom = buf[off + 2] & 1
                off += 4
                if bottom:
                    break
            add_ip_at_offset(off)
        elif ethertype == 0x8864:
            if len(buf) >= off + 8:
                add_ip_at_offset(off + 8)

    if linktype == LINKTYPE_ETHERNET:
        seen.add("ethernet")
        if len(buf) >= 14:
            add_ethernet_frame(14, (buf[12] << 8) | buf[13])
    elif linktype in (LINKTYPE_NULL, LINKTYPE_LOOP):
        seen.add("loopback")
        if len(buf) >= 4:
            version = buf[0] >> 4 if buf[0] else 0
            if version == 4:
                seen.add("ipv4")
                if len(buf) >= 20:
                    add_ip_transport(buf[9], buf[20:])
            elif version == 6:
                seen.add("ipv6")
                if len(buf) >= 40:
                    add_ip_transport(buf[6], buf[40:])
    elif linktype in LINKTYPE_RAW_ALT:
        if len(buf) >= 1:
            version = buf[0] >> 4
            if version == 4:
                seen.add("ipv4")
                if len(buf) >= 20:
                    add_ip_transport(buf[9], buf[20:])
            elif version == 6:
                seen.add("ipv6")
                if len(buf) >= 40:
                    add_ip_transport(buf[6], buf[40:])
    elif linktype in (LINKTYPE_LINUX_SLL, LINKTYPE_LINUX_SLL2):
        seen.add("linux-sll")
        off = 16 if linktype == LINKTYPE_LINUX_SLL else 20
        if len(buf) >= off + 2:
            ethertype = (buf[off - 2] << 8) | buf[off - 1]
            if ethertype == 0x0806:
                seen.add("arp")
            elif ethertype in (0x0800, 0x86DD):
                if len(buf) >= off + 20:
                    ip_off = off
                    version = buf[ip_off] >> 4
                    if version == 4:
                        seen.add("ipv4")
                        add_ip_transport(buf[ip_off + 9], buf[ip_off + 20:])
                    elif version == 6:
                        seen.add("ipv6")
                        add_ip_transport(buf[ip_off + 6], buf[ip_off + 40:])

    if not seen and linktype is not None:
        seen.add("non-ip")
    return seen


def _ip_addrs(buf: bytes, off: int):
    if len(buf) <= off:
        return None
    version = buf[off] >> 4
    if version == 4:
        if len(buf) < off + 20:
            return None
        return buf[off + 12 : off + 16], buf[off + 16 : off + 20]
    if version == 6:
        if len(buf) < off + 40:
            return None
        return buf[off + 8 : off + 24], buf[off + 24 : off + 40]
    return None


def _from_ethertype(buf: bytes, off: int, ethertype: int):
    """Salta VLAN / MPLS / PPPoE e restituisce gli IP, se presenti."""
    while ethertype in (0x8100, 0x88A8, 0x9100):  # 802.1Q / QinQ
        if len(buf) < off + 4:
            return None
        ethertype = (buf[off + 2] << 8) | buf[off + 3]
        off += 4

    if ethertype in (0x0800, 0x86DD):
        return _ip_addrs(buf, off)

    if ethertype in (0x8847, 0x8848):  # MPLS
        while True:
            if len(buf) < off + 4:
                return None
            bottom = buf[off + 2] & 1
            off += 4
            if bottom:
                break
        return _ip_addrs(buf, off)

    if ethertype == 0x8864:  # PPPoE session
        if len(buf) < off + 8:
            return None
        return _ip_addrs(buf, off + 8)

    return None


def packet_ip_addrs(buf: bytes, linktype):
    if linktype == LINKTYPE_ETHERNET:
        if len(buf) < 14:
            return None
        return _from_ethertype(buf, 14, (buf[12] << 8) | buf[13])
    if linktype in LINKTYPE_RAW_ALT:
        return _ip_addrs(buf, 0)
    if linktype in (LINKTYPE_NULL, LINKTYPE_LOOP):
        return _ip_addrs(buf, 4)
    if linktype == LINKTYPE_LINUX_SLL:
        if len(buf) < 16:
            return None
        return _from_ethertype(buf, 16, (buf[14] << 8) | buf[15])
    if linktype == LINKTYPE_LINUX_SLL2:
        if len(buf) < 20:
            return None
        return _from_ethertype(buf, 20, (buf[0] << 8) | buf[1])
    return None


def _parse_pcap(f, endian: str, stats: CaptureStats):
    header = f.read(20)  # il resto dell'header globale dopo il magic
    if len(header) < 20:
        raise PcapParseError("Header pcap troncato: il file e' incompleto.")
    linktype = struct.unpack(endian + "I", header[16:20])[0] & 0x0FFFFFFF
    record = struct.Struct(endian + "IIII")

    while True:
        rh = f.read(16)
        if not rh:
            break
        if len(rh) < 16:
            stats.truncated = True
            break
        _, _, incl_len, _ = record.unpack(rh)
        if incl_len > MAX_PACKET_LEN:
            stats.truncated = True  # record incoerente: file corrotto
            break
        data = f.read(incl_len)
        if len(data) < incl_len:
            stats.truncated = True
            break
        stats.add(data, linktype)


def _parse_pcapng(f, stats: CaptureStats):
    endian = "<"
    interfaces: list[int] = []

    while True:
        head = f.read(8)
        if not head:
            break
        if len(head) < 8:
            stats.truncated = True
            break

        if head[:4] == PCAPNG_SHB:
            bom = f.read(4)
            if bom == b"\x4d\x3c\x2b\x1a":
                endian = "<"
            elif bom == b"\x1a\x2b\x3c\x4d":
                endian = ">"
            else:
                raise PcapParseError("Section Header pcapng non valido.")
            total = struct.unpack(endian + "I", head[4:8])[0]
            if total < 28 or total % 4:
                raise PcapParseError("Section Header pcapng corrotto.")
            rest = f.read(total - 12)
            if len(rest) < total - 12:
                stats.truncated = True
                break
            interfaces = []  # ogni sezione riparte con nuove interfacce
            continue

        btype, total = struct.unpack(endian + "II", head)
        if total < 12 or total % 4 or total > MAX_PACKET_LEN:
            stats.truncated = True  # blocco incoerente
            break
        body = f.read(total - 8)
        if len(body) < total - 8:
            stats.truncated = True
            break
        body = body[:-4]  # toglie il total length finale

        if btype == 1 and len(body) >= 8:  # Interface Description Block
            interfaces.append(struct.unpack_from(endian + "H", body, 0)[0])
        elif btype in (6, 2) and len(body) >= 20:  # Enhanced / vecchio Packet Block
            if btype == 6:
                iface = struct.unpack_from(endian + "I", body, 0)[0]
            else:
                iface = struct.unpack_from(endian + "H", body, 0)[0]
            caplen = struct.unpack_from(endian + "I", body, 12)[0]
            data = body[20 : 20 + caplen]
            stats.add(data, interfaces[iface] if iface < len(interfaces) else None)
        elif btype == 3 and len(body) >= 4:  # Simple Packet Block
            stats.add(body[4:], interfaces[0] if interfaces else None)
        # tutti gli altri blocchi (statistiche, nomi, commenti...) si ignorano


def parse_capture(path: str, progress=None, max_pairs=None) -> CaptureStats:
    """Legge un pcap/pcapng (anche .gz) e restituisce le statistiche IP.

    progress(byte_letti, pacchetti) viene chiamata periodicamente.
    max_pairs limita il numero di coppie IP distinte tracciate.
    """
    with open(path, "rb") as raw:
        gz = raw.read(2) == b"\x1f\x8b"
        raw.seek(0)
        f = gzip.GzipFile(fileobj=raw) if gz else raw

        stats = CaptureStats(max_pairs=max_pairs, progress=progress, tell=raw.tell)
        try:
            magic = f.read(4)
            if len(magic) < 4:
                raise PcapParseError("File vuoto o troppo corto.")
            if magic in PCAP_MAGICS:
                _parse_pcap(f, PCAP_MAGICS[magic], stats)
            elif magic == PCAPNG_SHB:
                f.seek(0)
                _parse_pcapng(f, stats)
            else:
                raise PcapParseError(
                    "Formato non riconosciuto: non sembra un file pcap o pcapng."
                )
        except (EOFError, gzip.BadGzipFile, OSError) as exc:
            if stats.packets:
                stats.truncated = True  # gzip troncato: usa quanto letto
            else:
                raise PcapParseError(f"File illeggibile: {exc}") from exc

    if stats.ip_packets == 0 and stats.unsupported_linktypes:
        types = ", ".join(str(t) for t in sorted(stats.unsupported_linktypes))
        raise PcapParseError(
            f"Tipo di link-layer non supportato (linktype {types}). "
            "Sono supportati Ethernet, Linux cooked (SLL/SLL2), loopback e raw IP."
        )
    return stats


def format_ip(raw: bytes) -> str:
    if len(raw) == 4:
        return socket.inet_ntoa(raw)
    return socket.inet_ntop(socket.AF_INET6, raw)
