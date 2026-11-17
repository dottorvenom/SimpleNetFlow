import gzip
import io
import os
import socket
import struct
import tempfile
import time
import unittest

from app import app, build_ip_edges
from pcap_parser import PcapParseError, format_ip, parse_capture


def ipv4(src, dst):
    s = bytes(int(x) for x in src.split("."))
    d = bytes(int(x) for x in dst.split("."))
    return b"\x45\x00\x00\x14\x00\x00\x00\x00\x40\x06\x00\x00" + s + d


def ipv6(src, dst):
    return (b"\x60\x00\x00\x00\x00\x00\x3b\x40" + socket.inet_pton(socket.AF_INET6, src)
            + socket.inet_pton(socket.AF_INET6, dst))


def eth(payload, ethertype=0x0800, vlan=False):
    hdr = b"\xaa" * 6 + b"\xbb" * 6
    if vlan:
        return hdr + b"\x81\x00\x00\x64" + struct.pack(">H", ethertype) + payload
    return hdr + struct.pack(">H", ethertype) + payload


def pcap_file(packets, linktype=1, endian="<"):
    parts = [struct.pack(endian + "IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, linktype)]
    for p in packets:
        parts.append(struct.pack(endian + "IIII", 1, 0, len(p), len(p)))
        parts.append(p)
    return b"".join(parts)


def pcapng_file(packets, linktype=1, endian="<"):
    def block(t, body):
        body += b"\x00" * ((-len(body)) % 4)
        total = 12 + len(body)
        return struct.pack(endian + "II", t, total) + body + struct.pack(endian + "I", total)

    out = block(0x0A0D0D0A, struct.pack(endian + "IHHq", 0x1A2B3C4D, 1, 0, -1))
    out += block(1, struct.pack(endian + "HHI", linktype, 0, 65535))
    for p in packets:
        out += block(6, struct.pack(endian + "IIIII", 0, 0, 0, len(p), len(p)) + p)
    return out


def parse_bytes(data):
    fd, path = tempfile.mkstemp()
    os.write(fd, data)
    os.close(fd)
    try:
        return parse_capture(path)
    finally:
        os.unlink(path)


def pairs_of(stats):
    return {(format_ip(a), format_ip(b)): n for (a, b), n in stats.pairs.items()}


class TestParser(unittest.TestCase):
    def test_build_ip_edges_counts_duplicates(self):
        data = [
            ("10.0.0.1", "10.0.0.2"),
            ("10.0.0.1", "10.0.0.2"),
            ("10.0.0.3", "10.0.0.1"),
            ("10.0.0.3", "10.0.0.2"),
        ]
        result = build_ip_edges(data)
        self.assertEqual(result["nodes"], ["10.0.0.1", "10.0.0.2", "10.0.0.3"])
        self.assertIn({"source": "10.0.0.1", "target": "10.0.0.2", "weight": 2}, result["edges"])
        self.assertIn({"source": "10.0.0.3", "target": "10.0.0.1", "weight": 1}, result["edges"])
        self.assertEqual(result["edges"][0]["weight"], 2)  # ordinati per peso

    def test_build_ip_edges_sorts_ips_increasing_order(self):
        data = [
            ("10.0.0.10", "10.0.0.2"),
            ("192.168.1.1", "10.0.0.1"),
            ("10.0.0.2", "192.168.1.1"),
        ]
        result = build_ip_edges(data)
        self.assertEqual(result["nodes"], ["10.0.0.1", "10.0.0.2", "10.0.0.10", "192.168.1.1"])

    def test_build_ip_edges_keeps_three_digit_first_octet(self):
        data = [
            ("172.16.0.5", "100.64.0.1"),
            ("10.0.0.1", "172.16.0.10"),
            ("100.64.0.2", "10.0.0.2"),
        ]
        result = build_ip_edges(data)
        self.assertEqual(result["nodes"], ["10.0.0.1", "10.0.0.2", "100.64.0.1", "100.64.0.2", "172.16.0.5", "172.16.0.10"])

    def test_result_exposes_full_ip_select_options(self):
        import app as app_module
        old_limit = app_module.MAX_PILLS
        app_module.MAX_PILLS = 2
        try:
            pk = [
                eth(ipv4("10.0.0.1", "100.64.0.1")),
                eth(ipv4("10.0.0.2", "172.16.0.5")),
                eth(ipv4("10.0.0.3", "192.168.0.7")),
            ]
            st = parse_bytes(pcap_file(pk))
            result = app_module.build_result("x.pcap", 1, st)
            self.assertEqual(result["nodes"], ["10.0.0.1", "10.0.0.2"])
            self.assertEqual(result["ip_options"], ["10.0.0.1", "10.0.0.2", "10.0.0.3", "100.64.0.1", "172.16.0.5", "192.168.0.7"])
        finally:
            app_module.MAX_PILLS = old_limit

    def test_pcap_ethernet_v4_v6_vlan(self):
        pk = [
            eth(ipv4("10.0.0.1", "10.0.0.2")),
            eth(ipv4("10.0.0.1", "10.0.0.2"), vlan=True),
            eth(ipv6("2001:db8::1", "2001:db8::2"), 0x86DD),
            eth(b"\x00" * 28, 0x0806),  # ARP
        ]
        st = parse_bytes(pcap_file(pk))
        self.assertEqual(pairs_of(st), {("10.0.0.1", "10.0.0.2"): 2, ("2001:db8::1", "2001:db8::2"): 1})
        self.assertEqual((st.packets, st.non_ip), (4, 1))

    def test_pcap_big_endian(self):
        st = parse_bytes(pcap_file([eth(ipv4("1.1.1.1", "2.2.2.2"))], endian=">"))
        self.assertEqual(pairs_of(st), {("1.1.1.1", "2.2.2.2"): 1})

    def test_other_linktypes(self):
        ip = ipv4("192.168.1.1", "192.168.1.2")
        cases = {
            101: ip,
            0: b"\x02\x00\x00\x00" + ip,
            113: b"\x00" * 14 + b"\x08\x00" + ip,
            276: b"\x08\x00" + b"\x00" * 18 + ip,
        }
        for lt, pkt in cases.items():
            with self.subTest(linktype=lt):
                st = parse_bytes(pcap_file([pkt], linktype=lt))
                self.assertEqual(pairs_of(st), {("192.168.1.1", "192.168.1.2"): 1})

    def test_pcapng_both_endians(self):
        for endian in ("<", ">"):
            with self.subTest(endian=endian):
                st = parse_bytes(pcapng_file([eth(ipv4("10.1.1.1", "10.1.1.2"))] * 3, endian=endian))
                self.assertEqual(pairs_of(st), {("10.1.1.1", "10.1.1.2"): 3})

    def test_gzip(self):
        raw = pcap_file([eth(ipv4("10.0.0.1", "10.0.0.2"))])
        self.assertEqual(parse_bytes(gzip.compress(raw)).ip_packets, 1)

    def test_truncated_file_keeps_readable_part(self):
        raw = pcap_file([eth(ipv4("10.0.0.1", "10.0.0.2"))] * 3)
        st = parse_bytes(raw[:-10])
        self.assertTrue(st.truncated)
        self.assertEqual(st.ip_packets, 2)

    def test_invalid_files(self):
        for bad in (b"questo non e' un pcap", b"", pcap_file([b"\x00" * 40], linktype=105)):
            with self.subTest(bad=bad[:12]):
                with self.assertRaises(PcapParseError):
                    parse_bytes(bad)


class TestApi(unittest.TestCase):
    def setUp(self):
        self.client = app.test_client()

    def send(self, data, name="x.pcap"):
        """Upload come lo fa la UI: corpo grezzo + header X-Filename."""
        return self.client.post("/api/analyze", data=data,
                                headers={"X-Filename": name, "Content-Type": "application/octet-stream"})

    def analyze(self, data, name="x.pcap"):
        """Invia il file e attende la fine dell'analisi. Restituisce (stato, json)."""
        r = self.send(data, name)
        self.assertEqual(r.status_code, 202, r.get_data(as_text=True))
        job_id = r.get_json()["job_id"]
        for _ in range(200):
            j = self.client.get(f"/api/jobs/{job_id}").get_json()
            if j["state"] in ("done", "error"):
                return j["state"], j
            time.sleep(0.02)
        self.fail("analisi non terminata")

    def test_export_filtered_pcap(self):
        import app as app_module
        data = pcap_file([
            eth(ipv4("10.0.0.1", "10.0.0.2")),
            eth(ipv4("10.0.0.9", "10.0.0.1")),
            eth(ipv4("10.0.0.2", "10.0.0.8")),
        ])
        st = parse_bytes(data)
        blob = app_module.build_filtered_pcap(st, selected_ip="10.0.0.1", selected_protocol="tcp")
        self.assertTrue(blob.startswith((b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4")))
        self.assertGreater(len(blob), 24)

    def test_raw_upload_generates_svg(self):
        state, j = self.analyze(pcap_file([eth(ipv4("10.0.0.1", "10.0.0.2"))] * 5),
                                name="cattura%20wireshark.pcapng")
        self.assertEqual(state, "done")
        res = j["result"]
        self.assertIn('id="network-svg"', res["svg"])
        self.assertEqual((res["unique_ips"], res["ip_packets"], res["file_name"]),
                         (2, 5, "cattura wireshark.pcapng"))
        self.assertEqual(j["percent"], 100)

    def test_multipart_still_works(self):
        r = self.client.post("/api/analyze",
                             data={"f": (io.BytesIO(pcap_file([eth(ipv4("10.0.0.1", "10.0.0.2"))])), "a.cap")},
                             content_type="multipart/form-data")
        self.assertEqual(r.status_code, 202)

    def test_pcapng_upload(self):
        state, j = self.analyze(pcapng_file([eth(ipv4("10.1.1.1", "10.1.1.2"))] * 3))
        self.assertEqual((state, j["result"]["ip_packets"]), ("done", 3))

    def test_empty_body(self):
        r = self.send(b"")
        self.assertEqual(r.status_code, 400)
        self.assertIn("error", r.get_json())

    def test_garbage_shows_error(self):
        state, j = self.analyze(b"garbage garbage garbage")
        self.assertEqual(state, "error")
        self.assertIn("non sembra un file pcap", j["error"])

    def test_unknown_job(self):
        r = self.client.get("/api/jobs/nonesiste")
        self.assertEqual(r.status_code, 404)
        self.assertIn("riavviato", r.get_json()["error"])

    def test_too_large(self):
        old = app.config["MAX_CONTENT_LENGTH"]
        app.config["MAX_CONTENT_LENGTH"] = 100
        try:
            r = self.send(b"x" * 5000)
            self.assertEqual(r.status_code, 413)
            self.assertIn("troppo grande", r.get_json()["error"])
        finally:
            app.config["MAX_CONTENT_LENGTH"] = old

    def test_pair_cap_reports_notice(self):
        import app as app_module
        old = app_module.MAX_TRACKED_PAIRS
        app_module.MAX_TRACKED_PAIRS = 3
        try:
            pk = [eth(ipv4("10.0.0.%d" % i, "10.9.9.9")) for i in range(1, 9)]
            state, j = self.analyze(pcap_file(pk))
            self.assertEqual(state, "done")
            self.assertEqual(j["result"]["total_packets"], 8)
            self.assertEqual(j["result"]["unique_ips"], 4)  # 3 coppie -> 3 sorgenti + 1 destinazione
            self.assertTrue(any("moltissime coppie" in n for n in j["result"]["notices"]))
        finally:
            app_module.MAX_TRACKED_PAIRS = old

    def test_progress_callback(self):
        calls = []
        pk = [eth(ipv4("10.0.0.1", "10.0.0.2"))] * 45000
        fd, path = tempfile.mkstemp()
        os.write(fd, pcap_file(pk)); os.close(fd)
        size = os.path.getsize(path)
        try:
            parse_capture(path, progress=lambda b, n: calls.append((b, n)))
        finally:
            os.unlink(path)
        self.assertEqual([n for _, n in calls], [20000, 40000])
        self.assertTrue(0 < calls[0][0] < calls[1][0] <= size)

    def test_large_capture_keeps_all_ips_when_limits_disabled(self):
        import app as app_module
        old_nodes = app_module.MAX_GRAPH_NODES
        old_edges = app_module.MAX_GRAPH_EDGES
        old_pairs = app_module.MAX_TRACKED_PAIRS
        app_module.MAX_GRAPH_NODES = 0
        app_module.MAX_GRAPH_EDGES = 0
        app_module.MAX_TRACKED_PAIRS = 0
        try:
            pk = [eth(ipv4(f"10.0.0.{i}", "10.9.9.9")) for i in range(1, 21)]
            st = parse_bytes(pcap_file(pk))
            result = app_module.build_result("x.pcap", len(pcap_file(pk)), st)
            self.assertEqual(result["nodes_total"], 21)
            self.assertEqual(len(result["nodes"]), 21)
        finally:
            app_module.MAX_GRAPH_NODES = old_nodes
            app_module.MAX_GRAPH_EDGES = old_edges
            app_module.MAX_TRACKED_PAIRS = old_pairs

    def test_protocols_are_counted_across_layers(self):
        data = pcap_file([
            eth(ipv4("10.0.0.1", "10.0.0.2")),
            eth(ipv6("2001:db8::1", "2001:db8::2"), 0x86DD),
            eth(b"\x00" * 28, 0x0806),
            eth(ipv4("10.0.0.3", "10.0.0.4"), vlan=True),
        ])
        st = parse_bytes(data)
        self.assertEqual(st.protocols["ethernet"], 4)
        self.assertEqual(st.protocols["ipv4"], 2)
        self.assertEqual(st.protocols["ipv6"], 1)
        self.assertEqual(st.protocols["arp"], 1)

    # ---- upload a blocchi ----
    def chunked(self, data, name="x.pcap", step=1000):
        r = self.client.post("/api/uploads", json={"name": name, "size": len(data)})
        self.assertEqual(r.status_code, 200)
        uid = r.get_json()["upload_id"]
        for off in range(0, len(data), step):
            r = self.client.put(f"/api/uploads/{uid}/chunk?offset={off}", data=data[off:off + step],
                                headers={"Content-Type": "application/octet-stream"})
            self.assertEqual(r.status_code, 200)
        return uid

    def wait_job(self, job_id):
        for _ in range(200):
            j = self.client.get(f"/api/jobs/{job_id}").get_json()
            if j["state"] in ("done", "error"):
                return j
            time.sleep(0.02)
        self.fail("analisi non terminata")

    def test_chunked_upload_end_to_end(self):
        data = pcap_file([eth(ipv4("10.0.0.1", "10.0.0.2"))] * 50)
        uid = self.chunked(data, name="wireshark%20x.pcapng")
        r = self.client.post(f"/api/uploads/{uid}/finish")
        self.assertEqual(r.status_code, 202)
        j = self.wait_job(r.get_json()["job_id"])
        self.assertEqual((j["state"], j["result"]["ip_packets"]), ("done", 50))

    def test_chunk_retry_is_idempotent(self):
        data = pcap_file([eth(ipv4("10.0.0.1", "10.0.0.2"))] * 20)
        uid = self.client.post("/api/uploads", json={"name": "a", "size": len(data)}).get_json()["upload_id"]
        put = lambda off, chunk: self.client.put(f"/api/uploads/{uid}/chunk?offset={off}", data=chunk)
        self.assertEqual(put(0, data[:500]).get_json()["received"], 500)
        self.assertEqual(put(0, data[:500]).get_json()["received"], 500)       # blocco ritrasmesso
        self.assertEqual(put(300, data[300:900]).get_json()["received"], 900)  # sovrapposto
        self.assertEqual(put(900, data[900:]).get_json()["received"], len(data))
        r = self.client.post(f"/api/uploads/{uid}/finish")
        self.assertEqual(self.wait_job(r.get_json()["job_id"])["result"]["ip_packets"], 20)

    def test_chunk_with_extra_bytes_is_truncated(self):
        data = pcap_file([eth(ipv4("10.0.0.1", "10.0.0.2"))] * 5)
        uid = self.client.post("/api/uploads", json={"name": "a", "size": len(data)}).get_json()["upload_id"]
        payload = data + b"EXTRA"
        r = self.client.put(f"/api/uploads/{uid}/chunk?offset=0", data=payload,
                            headers={"Content-Type": "application/octet-stream"})
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.get_json()["received"], len(data))
        r = self.client.post(f"/api/uploads/{uid}/finish")
        self.assertEqual(self.wait_job(r.get_json()["job_id"])["result"]["ip_packets"], 5)

    def test_chunk_gap_and_incomplete_finish(self):
        data = b"x" * 3000
        uid = self.client.post("/api/uploads", json={"name": "a", "size": 3000}).get_json()["upload_id"]
        r = self.client.put(f"/api/uploads/{uid}/chunk?offset=1000", data=data[:500])
        self.assertEqual((r.status_code, r.get_json()["received"]), (409, 0))
        self.client.put(f"/api/uploads/{uid}/chunk?offset=0", data=data[:1000])
        r = self.client.post(f"/api/uploads/{uid}/finish")
        self.assertEqual(r.status_code, 409)
        self.assertIn("incompleto", r.get_json()["error"])

    def test_upload_unknown_and_invalid(self):
        self.assertEqual(self.client.put("/api/uploads/zzz/chunk?offset=0", data=b"x").status_code, 404)
        self.assertEqual(self.client.post("/api/uploads/zzz/finish").status_code, 404)
        self.assertEqual(self.client.post("/api/uploads", json={"name": "a", "size": 0}).status_code, 400)
        self.assertEqual(self.client.post("/api/uploads", json={"name": "a", "size": 10 ** 13}).status_code, 413)

    def test_index_page(self):
        r = self.client.get("/")
        self.assertEqual(r.status_code, 200)
        self.assertIn('id="pcap-file"', r.get_data(as_text=True))


if __name__ == "__main__":
    unittest.main()
