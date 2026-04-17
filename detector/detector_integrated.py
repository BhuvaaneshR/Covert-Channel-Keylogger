"""
detector_integrated.py
======================
Unified Covert Channel Detection System — updated for Smart Size Routing

Architecture:
  Raw Packet
      |
      v
  FeatureExtractor     <- strips headers, computes features, ZERO decisions
      |
      |-- ICMP Echo Request -> ICMPAnomalyDetector  -> [!!!] ALERT
      |
      |-- DNS Query         -> DNSAnomalyDetector   -> [!!!] ALERT
      |
      +-- Both channels     -> CrossProtocolCorrelator -> [!!!] DUAL-CHANNEL ALERT

Run on Attacker VM (10.0.0.5):
    sudo python3 detector_integrated.py

=======================================================================
WHAT CHANGED WITH SMART SIZE ROUTING — DETECTOR IMPACT ANALYSIS
=======================================================================

PREVIOUS BEHAVIOUR (before smart routing):
  - keylogger_local.py always sent ALL payloads via DNS only.
  - ICMP detector existed but rarely fired in practice.
  - DNS detector saw subdomains of arbitrary length (6 to 30 hex chars).

NEW BEHAVIOUR (after smart routing):
  - Payloads 1-4 chars  -> ICMP Timing Channel exclusively.
  - Payloads 5-15 chars -> DNS Hex Channel exclusively.
  - Both channels now ALWAYS active during a keylogging session.

DETECTOR UPDATES REQUIRED:

  [1] DNS — MIN_SUBDOMAIN_LEN: 6 -> 10
      WHY: With smart routing, the MINIMUM DNS payload is 5 chars
           (since <=4 go via ICMP). 5 source chars x 2 hex per byte = 10.
           Subdomains shorter than 10 hex chars CANNOT be smart-routed
           DNS traffic. Raising the floor eliminates false positives from
           short hex-looking CDN hashes (e.g. "a3f1c0" = 6 chars).

  [2] DNS — MAX_SUBDOMAIN_LEN: unlimited -> 30
      WHY: With smart routing, the MAXIMUM DNS payload is 15 chars
           (the buffer ceiling). 15 chars x 2 hex per byte = 30.
           Any hex subdomain > 30 chars cannot be smart-routed DNS.
           Adding an upper bound eliminates false positives from long
           hex strings that legitimately appear in CDN/cloud traffic.

  [3] ICMP — ICMP_WINDOW: 14 (UNCHANGED)
      WHY: Window still valid. Maximum ICMP payload is 4 chars = 32 bits
           = 32 packets per batch. A window of 14 intervals collects
           enough samples within the first 1-2 chars to detect the
           artificial 0.2s/0.6s clustering pattern.

  [4] CrossProtocolCorrelator — NEW
      WHY: Smart routing creates a forensic fingerprint: a legitimate
           user NEVER generates ICMP pings AND DNS queries to the
           SAME suspicious domain in the same session. If both
           ICMPAnomalyDetector AND DNSAnomalyDetector fire alerts
           within a 120-second window, it is definitive proof of
           a hybrid covert channel attack. Confidence = CRITICAL.
=======================================================================
"""

from scapy.all import sniff, IP, ICMP, UDP, DNS, DNSQR
from collections import deque
import math
import time
import re

# ============================================================
#   SHARED CONFIGURATION
# ============================================================
INTERFACE   = "eth0"
VICTIM_IP   = "10.0.0.6"
ATTACKER_IP = "10.0.0.5"

# ICMP timing constants (from icmp_exfil.py)
DOT_DELAY  = 0.2
DASH_DELAY = 0.6
CHAR_GAP   = 1.2
BATCH_GAP  = 2.0

# ICMP detection constants
TOLERANCE       = 0.15
IGNORE_ABOVE    = 1.0
ICMP_WINDOW     = 14      # UNCHANGED — still sufficient for <=4 char bursts
ALERT_THRESHOLD = 0.80

# DNS constants
TARGET_DOMAIN     = "test.google.com"

# CHANGED: was 6, now 10
# Reason: smart routing sends >=5 chars via DNS -> min hex len = 5*2 = 10
MIN_SUBDOMAIN_LEN = 10

# NEW: upper bound on subdomain length
# Reason: smart routing sends <=15 chars via DNS -> max hex len = 15*2 = 30
MAX_SUBDOMAIN_LEN = 30

# Cross-protocol correlation window (seconds)
# If ICMP alert AND DNS alert both fire within this window -> CRITICAL alert
CORRELATION_WINDOW = 120.0

# Regex patterns
_HEX_RE = re.compile(r'^[0-9a-f]+$')
_B64_RE = re.compile(r'^[A-Za-z0-9+/=_-]+$')
B64_ENTROPY_THRESHOLD = 3.0


# ============================================================
#   LAYER 1 — PURE MATH HELPERS
# ============================================================

def _shannon_entropy(s: str) -> float:
    """H(X) = -Sigma P(x)*log2(P(x))"""
    if not s:
        return 0.0
    length = len(s)
    freq = {}
    for ch in s:
        freq[ch] = freq.get(ch, 0) + 1
    return -sum((c / length) * math.log2(c / length) for c in freq.values())


def _classify_icmp_delta(delta: float) -> str:
    if abs(delta - DOT_DELAY)  <= TOLERANCE: return "DOT"
    if abs(delta - DASH_DELAY) <= TOLERANCE: return "DASH"
    if abs(delta - CHAR_GAP)   <= TOLERANCE: return "CHAR_GAP"
    if abs(delta - BATCH_GAP)  <= TOLERANCE: return "BATCH_GAP"
    return "NOISE"


def _detect_dns_encoding(subdomain: str) -> str:
    """
    Returns 'HEX', 'BASE64', or 'NONE'.

    UPDATED bounds with smart routing:
      HEX requires: MIN_SUBDOMAIN_LEN(10) <= len <= MAX_SUBDOMAIN_LEN(30)
      Previously: MIN=6, no upper bound.
    """
    slen = len(subdomain)

    # UPDATED: apply both min AND max length bounds
    if slen < MIN_SUBDOMAIN_LEN or slen > MAX_SUBDOMAIN_LEN:
        return "NONE"

    # HEX: all [0-9a-f] with even length — matches dns_exfil.py output
    if slen % 2 == 0 and bool(_HEX_RE.match(subdomain)):
        return "HEX"

    # BASE64: uppercase + b64 charset + entropy threshold
    if (any(c.isupper() for c in subdomain)
            and bool(_B64_RE.match(subdomain))
            and _shannon_entropy(subdomain) >= B64_ENTROPY_THRESHOLD):
        return "BASE64"

    return "NONE"


def _decode_payload(subdomain: str, encoding: str) -> str:
    """Reverses encoding to recover stolen keystrokes."""
    if encoding == "HEX":
        try:
            return bytes.fromhex(subdomain).decode('utf-8', errors='replace')
        except Exception:
            return "[hex decode failed]"
    if encoding == "BASE64":
        try:
            import base64 as _b64
            pad = subdomain + "=" * ((4 - len(subdomain) % 4) % 4)
            return _b64.urlsafe_b64decode(pad).decode('utf-8', errors='replace')
        except Exception:
            return "[base64 decode failed]"
    return ""


# ============================================================
#   LAYER 2 — FEATURE EXTRACTOR
#   Zero decisions. Strips headers, computes features, dispatches.
# ============================================================

class FeatureExtractor:

    def __init__(self, on_icmp_features, on_dns_features):
        self._on_icmp   = on_icmp_features
        self._on_dns    = on_dns_features
        self._last_icmp = 0.0

    def process(self, packet):
        if not packet.haslayer(IP):
            return
        if packet[IP].src != VICTIM_IP:
            return
        if self._is_icmp_request(packet):
            self._on_icmp(self._icmp_features(packet))
        elif self._is_dns_query(packet):
            feat = self._dns_features(packet)
            if feat:
                self._on_dns(feat)

    @staticmethod
    def _is_icmp_request(pkt) -> bool:
        return pkt.haslayer(ICMP) and pkt[ICMP].type == 8

    @staticmethod
    def _is_dns_query(pkt) -> bool:
        return (pkt.haslayer(UDP) and pkt.haslayer(DNS)
                and pkt.haslayer(DNSQR) and pkt[DNS].qr == 0)

    def _icmp_features(self, pkt) -> dict:
        now   = time.time()
        delta = 0.0 if self._last_icmp == 0.0 else round(now - self._last_icmp, 4)
        self._last_icmp = now
        return {
            "protocol"          : "ICMP",
            "timestamp"         : round(now, 6),
            "source_ip"         : pkt[IP].src,
            "packet_size_bytes" : len(pkt),
            "delta_time_sec"    : delta,
            "delta_class"       : _classify_icmp_delta(delta),
        }

    def _dns_features(self, pkt) -> dict | None:
        try:
            full_query = pkt[DNSQR].qname.decode('utf-8').rstrip('.')
        except Exception:
            return None

        subdomain = full_query.split('.')[0]
        encoding  = _detect_dns_encoding(subdomain)
        decoded   = _decode_payload(subdomain, encoding)

        return {
            "protocol"           : "DNS",
            "timestamp"          : round(time.time(), 6),
            "source_ip"          : pkt[IP].src,
            "packet_size_bytes"  : len(pkt),
            "dns_full_query"     : full_query,
            "dns_targets_domain" : TARGET_DOMAIN in full_query,
            "dns_subdomain"      : subdomain,
            "dns_subdomain_len"  : len(subdomain),
            "dns_entropy"        : round(_shannon_entropy(subdomain), 4),
            "dns_encoding"       : encoding,
            "dns_is_covert"      : encoding != "NONE",
            "dns_decoded_text"   : decoded,
        }


# ============================================================
#   LAYER 3 — ANOMALY DETECTORS
# ============================================================

class CrossProtocolCorrelator:
    """
    NEW — Cross-Protocol Correlation Engine.

    Tracks the timestamps of the last ICMP alert and the last DNS alert.
    If both fire within CORRELATION_WINDOW seconds of each other, it
    raises a CRITICAL dual-channel alert.

    Rationale (smart routing context):
      Under normal conditions, a host either pings OR sends DNS queries.
      Under smart routing, the victim simultaneously uses ICMP for short
      words and DNS for long words. This bimodal traffic pattern is
      essentially impossible for a legitimate user to produce and is a
      definitive indicator of the hybrid keylogger.
    """

    def __init__(self):
        self._last_icmp_alert = 0.0
        self._last_dns_alert  = 0.0

    def record_icmp_alert(self):
        self._last_icmp_alert = time.time()
        self._check_correlation()

    def record_dns_alert(self):
        self._last_dns_alert = time.time()
        self._check_correlation()

    def _check_correlation(self):
        if self._last_icmp_alert == 0.0 or self._last_dns_alert == 0.0:
            return  # Both channels haven't fired yet
        gap = abs(self._last_icmp_alert - self._last_dns_alert)
        if gap <= CORRELATION_WINDOW:
            self._raise_dual_alert(gap)
            # Reset both to prevent repeated firing on same session
            self._last_icmp_alert = 0.0
            self._last_dns_alert  = 0.0

    @staticmethod
    def _raise_dual_alert(gap_seconds: float):
        print("\n" + "#" * 60)
        print("  [!!!] CRITICAL: DUAL-CHANNEL HYBRID KEYLOGGER DETECTED!")
        print(f"        Source IP   : {VICTIM_IP}")
        print(f"        Evidence    : ICMP timing alert + DNS hex alert")
        print(f"        Gap         : {gap_seconds:.1f}s between channel alerts")
        print(f"        Explanation : Smart size routing confirmed.")
        print(f"                      Short words via ICMP, long words via DNS.")
        print(f"        Confidence  : CRITICAL (dual forensic signal)")
        print(f"        Timestamp   : {time.strftime('%Y-%m-%d %H:%M:%S')}")
        print("#" * 60 + "\n")


class ICMPAnomalyDetector:
    """
    Detects the ICMP covert timing channel.

    UNCHANGED algorithm — window of 14 intervals remains valid because:
    - Smart routing sends max 4 chars per ICMP burst = 32 packets.
    - 14 intervals (15 packets) are collected from the first ~2 chars.
    - The 0.2s/0.6s clustering is detectable within that window.

    CHANGE: now notifies CrossProtocolCorrelator on alert.
    """

    def __init__(self, correlator: CrossProtocolCorrelator):
        self._correlator = correlator
        self._timestamps = deque(maxlen=ICMP_WINDOW + 1)

    def analyse(self, features: dict):
        self._timestamps.append(features["timestamp"])
        filled = len(self._timestamps) - 1
        print(
            f"  [ICMP] delta={features['delta_time_sec']:.3f}s "
            f"({features['delta_class']:<9}) | "
            f"window {filled}/{ICMP_WINDOW}          ",
            end="\r"
        )
        if len(self._timestamps) == ICMP_WINDOW + 1:
            self._evaluate()

    def _evaluate(self):
        ts   = list(self._timestamps)
        raw  = [ts[i] - ts[i-1] for i in range(1, len(ts))]
        data = [d for d in raw if d <= IGNORE_ABOVE]
        if len(data) < 4:
            return
        hits = sum(
            1 for d in data
            if abs(d - DOT_DELAY) <= TOLERANCE
            or abs(d - DASH_DELAY) <= TOLERANCE
        )
        match_rate = hits / len(data)
        if match_rate >= ALERT_THRESHOLD:
            self._raise_alert(match_rate)
            self._timestamps.clear()

    def _raise_alert(self, match_rate: float):
        print("\n" + "=" * 60)
        print("  [!!!] ALERT: COVERT ICMP TIMING CHANNEL DETECTED!")
        print(f"        Source IP   : {VICTIM_IP}")
        print(f"        Match Rate  : {match_rate * 100:.1f}% of data-bit packets")
        print(f"        Targets     : {DOT_DELAY}s (bit-0) | {DASH_DELAY}s (bit-1)  +-{TOLERANCE}s")
        print(f"        Confidence  : {'HIGH' if match_rate >= 0.9 else 'MEDIUM'}")
        print(f"        Timestamp   : {time.strftime('%Y-%m-%d %H:%M:%S')}")
        print("=" * 60 + "\n")
        # Notify correlator — may trigger CRITICAL dual-channel alert
        self._correlator.record_icmp_alert()


class DNSAnomalyDetector:
    """
    Detects hex/Base64 covert exfiltration in DNS queries.

    CHANGED parameters with smart routing:

    [Before] MIN_SUBDOMAIN_LEN = 6
      Could match any 6+ char hex-looking CDN string.
      Example false positive: 'a3f1c0' (6 chars) from a CDN request.

    [After]  MIN_SUBDOMAIN_LEN = 10, MAX_SUBDOMAIN_LEN = 30
      Only matches subdomains between 10-30 hex chars.
      10 chars = minimum (5 source chars routed via DNS by smart routing).
      30 chars = maximum (15 source chars = buffer ceiling).
      Any subdomain outside this range is structurally impossible
      to be smart-routed traffic, so it is ignored immediately.
      This eliminates an entire class of false positives.

    CHANGE: now notifies CrossProtocolCorrelator on alert.
    """

    def __init__(self, correlator: CrossProtocolCorrelator):
        self._correlator  = correlator
        self._packet_count = 0

    def analyse(self, features: dict):
        self._packet_count += 1
        enc     = features["dns_encoding"]
        covert  = features["dns_is_covert"]
        targets = features["dns_targets_domain"]
        slen    = features["dns_subdomain_len"]

        print(
            f"  [DNS]  #{self._packet_count:<4} | "
            f"subdomain: {features['dns_subdomain'][:22]:<22} | "
            f"len={slen:3d} | "
            f"H={features['dns_entropy']:.2f} | "
            f"enc={enc:<7} | "
            f"target={targets}     ",
            end="\r"
        )

        if covert and targets:
            self._raise_alert(features)

    def _raise_alert(self, f: dict):
        enc  = f["dns_encoding"]
        slen = f["dns_subdomain_len"]
        print("\n" + "=" * 60)
        print("  [!!!] ALERT: COVERT DNS EXFILTRATION DETECTED!")
        print(f"        Source IP    : {f['source_ip']}")
        print(f"        Full Query   : {f['dns_full_query']}")
        print(f"        Encoding     : {enc}")
        print(f"        Raw Payload  : {f['dns_subdomain']}")
        print(f"        Decoded Text : {f['dns_decoded_text']!r}")
        print(f"        Payload Size : {slen} hex chars ({slen // 2} bytes)")
        print(f"        Length Check : {MIN_SUBDOMAIN_LEN} <= {slen} <= {MAX_SUBDOMAIN_LEN}  [PASS]")
        print(f"        Entropy      : {f['dns_entropy']:.3f} bits")
        print(f"        Confidence   : {'HIGH' if enc == 'HEX' else 'HIGH (Base64)'}")
        print(f"        Timestamp    : {time.strftime('%Y-%m-%d %H:%M:%S')}")
        print("=" * 60 + "\n")
        # Notify correlator — may trigger CRITICAL dual-channel alert
        self._correlator.record_dns_alert()


# ============================================================
#   ENTRY POINT
# ============================================================
if __name__ == "__main__":

    correlator    = CrossProtocolCorrelator()
    icmp_detector = ICMPAnomalyDetector(correlator)
    dns_detector  = DNSAnomalyDetector(correlator)

    extractor = FeatureExtractor(
        on_icmp_features = icmp_detector.analyse,
        on_dns_features  = dns_detector.analyse,
    )

    print("=" * 60)
    print("  Integrated Covert Channel Detector (Smart-Routing Aware)")
    print("=" * 60)
    print(f"  Interface  : {INTERFACE}")
    print(f"  Monitoring : {VICTIM_IP}")
    print(f"  ICMP       : DOT={DOT_DELAY}s | DASH={DASH_DELAY}s | "
          f"+-{TOLERANCE}s | window={ICMP_WINDOW}")
    print(f"  DNS        : target=*.{TARGET_DOMAIN} | "
          f"len=[{MIN_SUBDOMAIN_LEN}-{MAX_SUBDOMAIN_LEN}] hex chars")
    print(f"  Correlator : dual-channel alert within {CORRELATION_WINDOW}s window")
    print("=" * 60 + "\n")

    sniff(
        iface  = INTERFACE,
        filter = f"src host {VICTIM_IP} and (icmp or udp port 53)",
        prn    = extractor.process,
        store  = 0,
    )
