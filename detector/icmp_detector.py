from scapy.all import sniff, IP, ICMP
import time
from collections import deque

# ============================================================
#   CONFIGURATION — must stay in sync with icmp_exfil.py
# ============================================================
INTERFACE   = "eth0"       # Attacker VM interface (check with 'ip a')
VICTIM_IP   = "10.0.0.6"  # Only inspect packets arriving FROM the victim

# Timing constants — must exactly match icmp_exfil.py
# DOT_DELAY  = 0.2s  →  Binary '0'
# DASH_DELAY = 0.6s  →  Binary '1'
# CHAR_GAP   = 1.2s  →  End of character (we IGNORE these — not data)
# BATCH_GAP  = 2.0s  →  Between words   (we IGNORE these — not data)
TARGET_DELTAS = [0.2, 0.6]

# Tolerance — must match icmp_receiver.py (±0.15s accounts for VM jitter)
TOLERANCE = 0.15

# How many inter-arrival intervals to collect before making a verdict.
# Set to 14 because a 15-char buffer produces exactly 15 packets per batch,
# giving 14 inter-arrival deltas — enough for a statistically confident decision.
WINDOW_SIZE = 14

# Ignore long gaps: CHAR_GAP (1.2s) and BATCH_GAP (2.0s) are NOT data bits.
# Any delta above this threshold is skipped during analysis.
IGNORE_ABOVE = 1.0   # seconds

# Alert threshold — if this fraction of valid deltas match TARGET_DELTAS, alert.
ALERT_THRESHOLD = 0.80  # 80%

# ============================================================
#   STATE
# ============================================================
# Stores raw arrival timestamps of the last WINDOW_SIZE+1 packets.
# We store timestamps (not deltas) so we always compute fresh deltas
# from a clean rolling window.
timestamps = deque(maxlen=WINDOW_SIZE + 1)


# ============================================================
#   ANALYSIS
# ============================================================
def analyze_timing():
    """
    Computes inter-arrival deltas from the rolling timestamp window,
    filters out CHAR_GAP / BATCH_GAP pauses, then checks whether
    the remaining deltas cluster around 0.2s or 0.6s.
    """
    if len(timestamps) < WINDOW_SIZE + 1:
        return  # Not enough data yet

    # Step 1 — Compute raw inter-arrival times
    raw_deltas = []
    ts_list = list(timestamps)
    for i in range(1, len(ts_list)):
        raw_deltas.append(ts_list[i] - ts_list[i - 1])

    # Step 2 — Filter out CHAR_GAP and BATCH_GAP intervals.
    #           These are legitimate pauses between characters/words,
    #           not covert data bits, so we exclude them from scoring.
    data_deltas = [d for d in raw_deltas if d <= IGNORE_ABOVE]

    if len(data_deltas) < 4:
        # Too few data-bit intervals to make a confident decision
        return

    # Step 3 — Count how many data deltas fall within ±TOLERANCE
    #           of either TARGET_DELTA (0.2s or 0.6s)
    suspicious_count = 0
    for delta in data_deltas:
        for target in TARGET_DELTAS:
            if abs(delta - target) <= TOLERANCE:
                suspicious_count += 1
                break  # A delta can only match one target

    # Step 4 — Verdict
    match_rate = suspicious_count / len(data_deltas)

    if match_rate >= ALERT_THRESHOLD:
        _raise_alert(match_rate, data_deltas)
        timestamps.clear()   # Reset so we don't spam the same alert


def _raise_alert(match_rate: float, deltas: list):
    """Prints a structured alert when a covert timing channel is detected."""
    print("\n" + "=" * 55)
    print("[!!!] ALERT: COVERT ICMP TIMING CHANNEL DETECTED!")
    print(f"      Source IP  : {VICTIM_IP}")
    print(f"      Match Rate : {match_rate * 100:.1f}% of data packets")
    print(f"      Targets    : {TARGET_DELTAS} seconds (±{TOLERANCE}s)")
    print(f"      Confidence : {'HIGH' if match_rate >= 0.9 else 'MEDIUM'}")
    print(f"      Timestamp  : {time.strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 55 + "\n")


# ============================================================
#   PACKET CALLBACK
# ============================================================
def packet_callback(packet):
    """
    Called for every sniffed ICMP packet.
    Filters to:
      • ICMP Echo Requests only (type=8) — ignores the attacker's own
        Echo Replies sent back to the victim, which would pollute the window.
      • Packets sourced FROM VICTIM_IP only — prevents false positives
        from any other host on the segment.
    """
    if not (packet.haslayer(IP) and packet.haslayer(ICMP)):
        return

    # Only Echo Requests (type 8) from the victim
    if packet[IP].src != VICTIM_IP:
        return
    if packet[ICMP].type != 8:
        return

    timestamps.append(time.time())
    filled = len(timestamps) - 1   # number of intervals available
    print(
        f"[*] ICMP from {VICTIM_IP} | "
        f"Window: {filled}/{WINDOW_SIZE}",
        end="\r"
    )

    if filled >= WINDOW_SIZE:
        analyze_timing()


# ============================================================
#   ENTRY POINT
# ============================================================
print(f"[*] ICMP Covert Channel Detector started")
print(f"[*] Interface : {INTERFACE}")
print(f"[*] Watching  : {VICTIM_IP} (Echo Requests only)")
print(f"[*] Targets   : {TARGET_DELTAS}s  |  Tolerance: ±{TOLERANCE}s")
print(f"[*] Window    : {WINDOW_SIZE} intervals  |  Alert at: {int(ALERT_THRESHOLD*100)}% match")
print(f"[*] Waiting for ICMP traffic...\n")

sniff(
    iface=INTERFACE,
    filter=f"icmp and src host {VICTIM_IP}",  # BPF pre-filter at kernel level
    prn=packet_callback,
    store=0
)
