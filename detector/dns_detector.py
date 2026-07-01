from scapy.all import sniff, IP, UDP, DNS, DNSQR
import base64
import math
import time
import re

# ============================================================
#   CONFIGURATION — must stay in sync with dns_exfil.py
# ============================================================
INTERFACE    = "eth0"            # Attacker VM interface (check with 'ip a')
VICTIM_IP    = "10.0.0.6"        # Only inspect queries FROM the victim

# Must exactly match dns_exfil.py → TARGET_DOMAIN = "test.google.com"
TARGET_DOMAIN = "test.google.com"

# Minimum subdomain length to analyse.
# Hex-encoding 1 char produces 2 hex digits → smallest real payload = ~6 chars
# (e.g., "a[S]" → "615b535d" = 8 chars). We skip shorter ones to avoid noise.
MIN_SUBDOMAIN_LEN = 6

# ============================================================
#   WHY ENTROPY ALONE FAILS HERE
# ============================================================
# dns_exfil.py uses HEX encoding: data.encode('utf-8').hex()
# Hex subdomains only contain chars [0-9a-f] → 16 possible chars
# Max possible entropy = log2(16) = 4.0 bits
# ACTUAL entropy of hex-encoded English text ≈ 2.5 – 2.9 bits
# That is BELOW the typical entropy of legitimate CDN/cloud subdomains (~3.2 bits)
# So entropy-based detection would produce ZERO alerts for your setup.
#
# The correct primary signal is the HEX CHARACTER PATTERN:
#   Legitimate subdomains use a-z, 0-9, and hyphens in meaningful words.
#   Hex payloads use ONLY [0-9a-f] AND are always EVEN in length.
#   This combination is essentially impossible for real domain names.

# ============================================================
#   ANALYSIS FUNCTIONS
# ============================================================

# Compiled regex — only hex characters (lowercase, as produced by .hex())
HEX_PATTERN = re.compile(r'^[0-9a-f]+$')

# Matches standard and URL-safe Base64 characters
B64_PATTERN = re.compile(r'^[A-Za-z0-9+/=_-]+$')

def is_hex_payload(subdomain: str) -> bool:
    """
    Returns True if the subdomain looks like hex-encoded exfiltration data.
    Three conditions must ALL be true:
      1. Every character is in [0-9a-f]   (hex alphabet)
      2. Length is even                    (hex always encodes 2 chars per byte)
      3. Length >= MIN_SUBDOMAIN_LEN       (rules out trivial strings like 'a1')
    """
    if len(subdomain) < MIN_SUBDOMAIN_LEN:
        return False
    if len(subdomain) % 2 != 0:
        return False
    return bool(HEX_PATTERN.match(subdomain))


def calculate_entropy(data_string: str) -> float:
    """
    Shannon Entropy:  H(X) = -Σ P(x) * log2(P(x))
    Used here as a SECONDARY metric for reporting only — not the alert trigger.
    """
    if not data_string:
        return 0.0
    length = len(data_string)
    frequencies = {}
    for char in data_string:
        frequencies[char] = frequencies.get(char, 0) + 1
    entropy = 0.0
    for count in frequencies.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy


def is_base64_payload(subdomain: str) -> bool:
    """
    Returns True if the subdomain looks like URL-safe Base64 encoded data.
    """
    if len(subdomain) < 8:
        return False
    if not bool(B64_PATTERN.match(subdomain)):
        return False
    if not any(c.isupper() for c in subdomain):
        return False
    if calculate_entropy(subdomain) < 3.0:
        return False
    return True


def try_decode_b64_payload(b64_subdomain: str) -> str:
    """
    Attempts to decode URL-safe Base64 back to plaintext.
    """
    try:
        missing_padding = len(b64_subdomain) % 4
        if missing_padding:
            b64_subdomain += '=' * (4 - missing_padding)
        raw_bytes = base64.urlsafe_b64decode(b64_subdomain)
        return raw_bytes.decode('utf-8', errors='replace')
    except Exception as e:
        return f"[b64 decode failed: {e}]"


def try_decode_payload(hex_subdomain: str) -> str:
    """
    Attempts to hex-decode the subdomain back into the original keystrokes.
    This reconstructs what the victim actually typed, which is powerful for demo.
    """
    try:
        raw_bytes = bytes.fromhex(hex_subdomain)
        return raw_bytes.decode('utf-8', errors='replace')
    except Exception:
        return "[decode failed]"


def _raise_alert(subdomain: str, full_query: str, entropy_score: float, encoding: str = "HEX"):
    """Prints a structured alert showing the detected exfiltration."""
    if encoding == "HEX":
        decoded = try_decode_payload(subdomain)
        payload_desc = f"{len(subdomain)} hex chars ({len(subdomain)//2} bytes)"
        detection_desc = "Hex character pattern + even length"
    else:
        decoded = try_decode_b64_payload(subdomain)
        payload_desc = f"{len(subdomain)} b64 chars"
        detection_desc = "Base64 character pattern + entropy + case mix"

    print("\n" + "=" * 60)
    print("[!!!] ALERT: COVERT DNS EXFILTRATION DETECTED!")
    print(f"      Source IP     : {VICTIM_IP}")
    print(f"      Full Query    : {full_query}")
    print(f"      Payload       : {subdomain} ({encoding})")
    print(f"      Decoded Text  : {decoded!r}")          # ← actual stolen keystrokes
    print(f"      Payload Len   : {payload_desc}")
    print(f"      Entropy Score : {entropy_score:.3f} bits (display only)")
    print(f"      Detection     : {detection_desc}")
    print(f"      Timestamp     : {time.strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 60 + "\n")


# ============================================================
#   PACKET CALLBACK
# ============================================================
def packet_callback(packet):
    """
    Called for every sniffed DNS packet.
    Extracts the queried domain, isolates the subdomain,
    and applies hex-pattern detection.
    """
    # Layer checks
    if not (packet.haslayer(IP) and
            packet.haslayer(UDP) and
            packet.haslayer(DNS) and
            packet.haslayer(DNSQR)):
        return

    # Only inspect queries FROM the victim (replies come FROM attacker — ignore)
    if packet[IP].src != VICTIM_IP:
        return

    # Only DNS Questions (qr=0), not Answers (qr=1)
    if packet[DNS].qr != 0:
        return

    # Decode the queried name — e.g. b'4b65796c.test.google.com.'
    try:
        full_query = packet[DNSQR].qname.decode('utf-8').rstrip('.')
    except Exception:
        return

    # Only process queries targeting our covert domain
    if TARGET_DOMAIN not in full_query:
        return

    # Isolate subdomain — "4b65796c.test.google.com" → "4b65796c"
    subdomain = full_query.split('.')[0]

    # Calculate entropy for display (even though it is not the trigger)
    entropy_score = calculate_entropy(subdomain)

    print(
        f"[*] DNS → {full_query[:50]:<50} | "
        f"len={len(subdomain):3d} | "
        f"H={entropy_score:.2f}",
        end="\r"
    )

    # PRIMARY DETECTION: Hex OR Base64 character pattern
    if is_hex_payload(subdomain):
        _raise_alert(subdomain, full_query, entropy_score, encoding="HEX")
    elif is_base64_payload(subdomain):
        _raise_alert(subdomain, full_query, entropy_score, encoding="BASE64")


# ============================================================
#   ENTRY POINT
# ============================================================
print(f"[*] DNS Covert Channel Detector started")
print(f"[*] Interface   : {INTERFACE}")
print(f"[*] Watching    : {VICTIM_IP}  (UDP Port 53)")
print(f"[*] Target      : *.{TARGET_DOMAIN}")
print(f"[*] Detection   : Hex pattern AND Base64 pattern detection")
print(f"[*] Min length  : {MIN_SUBDOMAIN_LEN} hex chars")
print(f"[*] Note        : Decoded keystrokes shown on every alert")
print(f"[*] Waiting for DNS traffic...\n")

sniff(
    iface=INTERFACE,
    # BPF pre-filter at kernel level — only DNS from the victim reaches Python
    filter=f"udp port 53 and src host {VICTIM_IP}",
    prn=packet_callback,
    store=0
)
