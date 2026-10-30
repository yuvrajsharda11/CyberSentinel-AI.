"""
Passive PCAP / network traffic analysis.

Beyond the original protocol/port tally, this adds:
  - Byte-based (not just packet-count-based) top talkers.
  - Port-scan detection: one source hitting many distinct destination ports
    on a single host.
  - Beaconing detection: a src/dst pair communicating at suspiciously
    regular intervals (classic C2 callback pattern) via coefficient of
    variation of inter-arrival times.
  - Basic DNS anomaly heuristics: unusually long or high-entropy query
    names, which can indicate DNS tunneling / exfiltration.
  - Clear-text protocol flags (Telnet, FTP control) in addition to the
    original "attack-associated port" list.

Still fully passive: packets are only parsed, never replayed or crafted.
"""
import math
import os
import statistics
import tempfile
from collections import Counter, defaultdict

from scapy.all import PcapReader, IP, IPv6, TCP, UDP, ICMP

try:
    from scapy.layers.dns import DNS, DNSQR
    _HAS_DNS = True
except Exception:
    _HAS_DNS = False

SENSITIVE_PORTS = {
    21: "FTP (clear-text control channel)",
    23: "Telnet (clear-text)",
    445: "SMB (common lateral-movement target)",
    3389: "RDP (common attack target)",
    4444: "Metasploit default handler port",
    6667: "IRC (legacy C2/botnet channel)",
    1337: "Commonly associated with backdoors",
    31337: "Commonly associated with backdoors",
}
PORT_SCAN_DISTINCT_PORT_THRESHOLD = 15
BEACON_MIN_SAMPLES = 6
BEACON_MAX_COEFF_OF_VARIATION = 0.15  # lower = more regular/suspicious
MAX_ANALYZED_PACKETS = 25_000


def _entropy(s):
    if not s:
        return 0.0
    counts = Counter(s)
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def analyze_pcap(data):
    if len(data) > 25 * 1024 * 1024:
        return {"risk_score": 0, "error": "Capture exceeds the 25 MB analysis limit.", "top_connections": []}
    tmp = None
    try:
        with tempfile.NamedTemporaryFile(prefix="cybersentinel_", suffix=".pcap", delete=False) as f:
            f.write(data)
            tmp = f.name
        packets = []
        truncated = False
        with PcapReader(tmp) as reader:
            for index, packet in enumerate(reader):
                if index >= MAX_ANALYZED_PACKETS:
                    truncated = True
                    break
                packets.append(packet)
    except Exception as e:
        return {"risk_score": 80, "error": str(e), "top_connections": []}
    finally:
        if tmp and os.path.exists(tmp):
            os.unlink(tmp)

    protocols = Counter()
    connections = Counter()          # (src,dst,proto) -> packet count
    conn_bytes = Counter()           # (src,dst,proto) -> byte count
    conn_timestamps = defaultdict(list)  # (src,dst) -> [timestamps]
    suspicious = []
    ports = Counter()
    src_dst_ports = defaultdict(set)  # (src,dst) -> set of dst ports touched
    dns_queries = []

    for pkt in packets:
        if IP in pkt:
            src, dst = pkt[IP].src, pkt[IP].dst
        elif IPv6 in pkt:
            src, dst = pkt[IPv6].src, pkt[IPv6].dst
        else:
            continue

        pkt_len = len(pkt)
        proto = "OTHER"
        sport = dport = None
        if TCP in pkt:
            proto = "TCP"
            sport, dport = pkt[TCP].sport, pkt[TCP].dport
        elif UDP in pkt:
            proto = "UDP"
            sport, dport = pkt[UDP].sport, pkt[UDP].dport
        elif ICMP in pkt:
            proto = "ICMP"

        protocols[proto] += 1
        if dport:
            ports[dport] += 1
            src_dst_ports[(src, dst)].add(dport)
        connections[(src, dst, proto)] += 1
        conn_bytes[(src, dst, proto)] += pkt_len
        try:
            conn_timestamps[(src, dst)].append(float(pkt.time))
        except Exception:
            pass

        if dport in SENSITIVE_PORTS:
            suspicious.append({
                "src": src, "dst": dst, "port": dport,
                "reason": SENSITIVE_PORTS[dport],
            })

        if _HAS_DNS and pkt.haslayer(DNS) and pkt.haslayer(DNSQR):
            try:
                qname = pkt[DNSQR].qname.decode(errors="ignore").rstrip(".")
                dns_queries.append(qname)
            except Exception:
                pass

    # --- Port scan detection: many distinct dst ports from one src to one dst ---
    port_scans = []
    for (src, dst), port_set in src_dst_ports.items():
        if len(port_set) >= PORT_SCAN_DISTINCT_PORT_THRESHOLD:
            port_scans.append({
                "src": src, "dst": dst, "distinct_ports_touched": len(port_set),
            })

    # --- Beaconing detection: regular-interval traffic between a src/dst pair ---
    beacons = []
    for (src, dst), times in conn_timestamps.items():
        if len(times) < BEACON_MIN_SAMPLES:
            continue
        times.sort()
        deltas = [t2 - t1 for t1, t2 in zip(times, times[1:]) if t2 > t1]
        if len(deltas) < BEACON_MIN_SAMPLES - 1:
            continue
        mean_delta = statistics.mean(deltas)
        if mean_delta <= 0:
            continue
        stdev_delta = statistics.pstdev(deltas)
        coeff_var = stdev_delta / mean_delta
        if coeff_var <= BEACON_MAX_COEFF_OF_VARIATION:
            beacons.append({
                "src": src, "dst": dst,
                "sample_count": len(times),
                "avg_interval_seconds": round(mean_delta, 2),
                "regularity": round(1 - coeff_var, 3),  # closer to 1.0 = more clock-like
            })

    # --- DNS anomalies: long / high-entropy query names (possible tunneling) ---
    dns_anomalies = []
    seen = set()
    for q in dns_queries:
        if q in seen:
            continue
        seen.add(q)
        label = q.split(".")[0] if "." in q else q
        ent = _entropy(label)
        if len(q) > 60 or (len(label) > 25 and ent > 3.8):
            dns_anomalies.append({"query": q, "length": len(q), "label_entropy": round(ent, 2)})

    # --- Scoring ---
    score = 0
    if len(packets) > 10000:
        score += 10
    score += min(40, len(suspicious) * 4)
    score += min(25, len(port_scans) * 15)
    score += min(20, len(beacons) * 10)
    score += min(15, len(dns_anomalies) * 5)
    if 23 in ports or 21 in ports:
        score += 5
    if 4444 in ports:
        score += 15
    score = min(100, score)

    top_by_packets = [{"source": a, "destination": b, "protocol": c, "packets": n}
                      for (a, b, c), n in connections.most_common(20)]
    top_by_bytes = [{"source": a, "destination": b, "protocol": c, "bytes": n}
                    for (a, b, c), n in conn_bytes.most_common(20)]

    return {
        "risk_score": score,
        "packet_count": len(packets),
        "truncated": truncated,
        "analysis_note": (f"Analysis stopped at {MAX_ANALYZED_PACKETS:,} packets for resource control." if truncated else ""),
        "protocols": dict(protocols),
        "top_ports": dict(ports.most_common(15)),
        "suspicious_connections": suspicious[:50],
        "top_connections": top_by_packets,
        "top_connections_by_bytes": top_by_bytes,
        "port_scan_indicators": port_scans,
        "beaconing_indicators": beacons,
        "dns_anomalies": dns_anomalies,
        "dns_queries_seen": len(seen),
    }
