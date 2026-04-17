from scapy.all import sniff, IP, ICMP, UDP, DNS, DNSQR
import math
import time
import json
import re

# ============================================================
#   CONFIGURATION — mirrors constants from existing project files
# ============================================================
INTERFACE   = "eth0"             # Attacker VM interface
VICTIM_IP   = "10.0.0.6"         # Victim machine (Clone of Kali-FYP1)
ATTACKER_IP = "10.0.0.5"         # This machine

# --- ICMP constants (from icmp_exfil.py) ---
DOT_DELAY  = 0.2    # Binary '0' inter-packet delay
DASH_DELAY = 0.6    # Binary '1' inter-packet delay
CHAR_GAP   = 1.2    # End-of-character pause
BATCH_GAP  = 2.0    # End-of-word / batch reset pause
TOLERANCE  = 0.15   # ± jitter margin (from icmp_receiver.py)

# --- DNS constants (from dns_exfil.py) ---
TARGET_DOMAIN     = "test.google.com"   # Covert domain used for exfiltration
MIN_SUBDOMAIN_LEN = 6                   # Ignore trivially short subdomains

# Regex: hex payloads use ONLY [0-9a-f] (lowercase, from .encode().hex())
_HEX_RE = re.compile(r'^[0-9a-f]+$')


# ============================================================
#   PURE MATH HELPERS  (no security decisions here)
# ============================================================

def _shannon_entropy(s: str) -> float:
    """H(X) = -Σ P(x)·log₂(P(x))   — measures character randomness."""
    if not s:
        return 0.0
    length = len(s)
    freq = {}
    for ch in s:
        freq[ch] = freq.get(ch, 0) + 1
    return -sum((c / length) * math.log2(c / length) for c in freq.values())


def _classify_icmp_delta(delta: float) -> str:
    """
    Maps a raw inter-arrival time to its role in the covert ICMP protocol.
    Uses the same ±TOLERANCE window as icmp_receiver.py.
    This is descriptive labelling — NOT a detection decision.

    DOT    = 0.2s ± 0.15  →  Binary '0'
    DASH   = 0.6s ± 0.15  →  Binary '1'
    CHAR   = 1.2s ± 0.15  →  End of character marker
    BATCH  = 2.0s ± 0.15  →  End of word / batch reset
    NOISE  = anything else (normal network jitter)
    """
    if abs(delta - DOT_DELAY)  <= TOLERANCE: return "DOT"
    if abs(delta - DASH_DELAY) <= TOLERANCE: return "DASH"
    if abs(delta - CHAR_GAP)   <= TOLERANCE: return "CHAR_GAP"
    if abs(delta - BATCH_GAP)  <= TOLERANCE: return "BATCH_GAP"
    return "NOISE"


def _is_hex_subdomain(subdomain: str) -> bool:
    """
    Returns True when a subdomain matches the hex-encoding signature
    produced by dns_exfil.py → data.encode('utf-8').hex()

    Three conditions (all must hold):
      1. Every character is in [0-9a-f]   — hex alphabet
      2. Length is even                   — hex always 2 chars per source byte
      3. Length ≥ MIN_SUBDOMAIN_LEN       — filters trivial noise
    """
    if len(subdomain) < MIN_SUBDOMAIN_LEN:
        return False
    if len(subdomain) % 2 != 0:
        return False
    return bool(_HEX_RE.match(subdomain))


def _hex_decode(hex_str: str) -> str:
    """Attempts to reverse dns_exfil.py's hex encoding back to plaintext."""
    try:
        return bytes.fromhex(hex_str).decode('utf-8', errors='replace')
    except Exception:
        return ""


# ============================================================
#   FEATURE EXTRACTOR CLASS
# ============================================================

class FeatureExtractor:
    """
    Observes raw packets, strips headers, and computes protocol-specific
    features. Outputs one JSON record per relevant packet.

    Golden Rule: This class makes ZERO security decisions.
    It never prints [ALERT]. It only formats and dispatches feature records.
    The downstream Anomaly Detection Engine handles all verdicts.
    """

    def __init__(self, target_ip: str):
        self.target_ip      = target_ip
        self._last_icmp_ts  = 0.0   # Timestamp of previous ICMP Echo Request

    # ----------------------------------------------------------
    #   PUBLIC ENTRY — called by Scapy for every packet
    # ----------------------------------------------------------
    def extract_features(self, packet):
        """Routes each packet to the correct protocol extractor."""

        # Discard anything not from our monitored host
        if not packet.haslayer(IP):
            return
        if packet[IP].src != self.target_ip:
            return

        # Route to protocol-specific extractor
        if self._is_icmp_echo_request(packet):
            self._extract_icmp(packet)

        elif self._is_dns_query(packet):
            self._extract_dns(packet)

    # ----------------------------------------------------------
    #   PROTOCOL GUARDS
    # ----------------------------------------------------------
    @staticmethod
    def _is_icmp_echo_request(packet) -> bool:
        """True only for ICMP Echo Requests (type=8) — ignores replies."""
        return packet.haslayer(ICMP) and packet[ICMP].type == 8

    @staticmethod
    def _is_dns_query(packet) -> bool:
        """True for outbound DNS questions (qr=0)."""
        return (packet.haslayer(UDP) and
                packet.haslayer(DNS) and
                packet.haslayer(DNSQR) and
                packet[DNS].qr == 0)

    # ----------------------------------------------------------
    #   ICMP FEATURE EXTRACTION
    # ----------------------------------------------------------
    def _extract_icmp(self, packet):
        """
        Extracts timing features from an ICMP Echo Request.

        Features produced
        -----------------
        protocol          : "ICMP"
        timestamp         : Unix time of arrival
        source_ip         : Packet source (always VICTIM_IP here)
        packet_size_bytes : Total IP packet length
        delta_time_sec    : Seconds since last Echo Request (0.0 for first)
        delta_class       : Descriptive label (DOT / DASH / CHAR_GAP /
                            BATCH_GAP / NOISE) — purely informational
        """
        now = time.time()

        # Inter-arrival time (delta)
        if self._last_icmp_ts == 0.0:
            delta = 0.0          # First packet has no predecessor
        else:
            delta = round(now - self._last_icmp_ts, 4)

        self._last_icmp_ts = now

        features = {
            "protocol"          : "ICMP",
            "timestamp"         : round(now, 6),
            "source_ip"         : packet[IP].src,
            "packet_size_bytes" : len(packet),
            "delta_time_sec"    : delta,
            "delta_class"       : _classify_icmp_delta(delta),
        }

        self._dispatch(features)

    # ----------------------------------------------------------
    #   DNS FEATURE EXTRACTION
    # ----------------------------------------------------------
    def _extract_dns(self, packet):
        """
        Extracts payload and structure features from a DNS query.

        Features produced
        -----------------
        protocol              : "DNS"
        timestamp             : Unix time of arrival
        source_ip             : Packet source
        packet_size_bytes     : Total packet length
        dns_full_query        : e.g. "4b65796c.test.google.com"
        dns_targets_domain    : True if query contains TARGET_DOMAIN
        dns_subdomain         : Isolated left-most label ("4b65796c")
        dns_subdomain_len     : Character count of subdomain
        dns_entropy           : Shannon entropy of subdomain (float)
        dns_is_hex_pattern    : True if subdomain matches hex signature
        dns_decoded_text      : Plaintext recovered by reversing hex encoding
                                (empty string if not a hex payload)
        """
        try:
            full_query = packet[DNSQR].qname.decode('utf-8').rstrip('.')
        except Exception:
            return   # Malformed — skip silently

        subdomain = full_query.split('.')[0]

        is_hex     = _is_hex_subdomain(subdomain)
        decoded    = _hex_decode(subdomain) if is_hex else ""
        entropy    = round(_shannon_entropy(subdomain), 4)
        targets    = TARGET_DOMAIN in full_query

        features = {
            "protocol"           : "DNS",
            "timestamp"          : round(time.time(), 6),
            "source_ip"          : packet[IP].src,
            "packet_size_bytes"  : len(packet),
            "dns_full_query"     : full_query,
            "dns_targets_domain" : targets,
            "dns_subdomain"      : subdomain,
            "dns_subdomain_len"  : len(subdomain),
            "dns_entropy"        : entropy,
            "dns_is_hex_pattern" : is_hex,
            "dns_decoded_text"   : decoded,
        }

        self._dispatch(features)

    # ----------------------------------------------------------
    #   DISPATCH
    # ----------------------------------------------------------
    @staticmethod
    def _dispatch(features: dict):
        """
        Serialises the feature dictionary to a single-line JSON string
        and writes it to stdout.

        This is the handoff point between the Feature Extraction Engine
        and the Anomaly Detection Engine. In production, replace print()
        with a write to Elasticsearch, Kafka, or a shared queue.
        """
        print(json.dumps(features))


# ============================================================
#   ENTRY POINT
# ============================================================
if __name__ == "__main__":
    print(f"[*] Feature Extraction Engine started")
    print(f"[*] Interface    : {INTERFACE}")
    print(f"[*] Monitoring   : {VICTIM_IP}")
    print(f"[*] Protocols    : ICMP Echo Requests  |  DNS Queries → {TARGET_DOMAIN}")
    print(f"[*] ICMP timing  : DOT={DOT_DELAY}s  DASH={DASH_DELAY}s  "
          f"CHAR_GAP={CHAR_GAP}s  BATCH_GAP={BATCH_GAP}s  (±{TOLERANCE}s)")
    print(f"[*] Output       : one JSON record per relevant packet")
    print(f"[*] Decisions    : NONE — feature extraction only\n")

    extractor = FeatureExtractor(target_ip=VICTIM_IP)

    sniff(
        iface=INTERFACE,
        # Kernel-level BPF pre-filter: only let through ICMP and DNS from victim
        filter=f"src host {VICTIM_IP} and (icmp or udp port 53)",
        prn=extractor.extract_features,
        store=0
    )
