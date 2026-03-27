from scapy.all import sniff, IP, ICMP, DNS, DNSQR
import math
import time
from collections import defaultdict, deque
import re 

# --- CONFIGURATION ---
INTERFACE = "eth0"         # Your network interface
TARGET_IP = "10.0.0.6"     # The Victim IP we are monitoring

# --- TUNING PARAMETERS ---

# 1. DNS Settings
ENTROPY_THRESHOLD = 3.5
DNS_WINDOW_TIME = 10     # Time window in seconds to count queries
DNS_QUERY_LIMIT = 5      # Alert if > 5 unique queries appear in 10s (Catches low entropy)
SUBDOMAIN_LEN_THRESHOLD = 20 # Alert on single long packets

# 2. ICMP Settings
ICMP_WINDOW_SIZE = 10    # How many packets to analyze at once
# We expect delays around 0.2s (Dot) and 0.6s (Dash).
# We add a tolerance (+/- 0.15s) to account for VM Lag/Jitter.
EXPECTED_BINS = [0.2, 0.6] 
TOLERANCE = 0.15         

# --- STATE TRACKING ---
icmp_timestamps = deque(maxlen=ICMP_WINDOW_SIZE)
dns_tracker = defaultdict(list) # Stores timestamps of queries per domain

# --- ANALYTICS ---

def calculate_shannon_entropy(data):
    """Calculates randomness of the string."""
    if not data: return 0
    entropy = 0
    for x in range(256):
        p_x = float(data.count(chr(x))) / len(data)
        if p_x > 0:
            entropy += - p_x * math.log(p_x, 2)
    return entropy

def analyze_icmp_clustering(packet):
    """
    Checks if delays 'snap' to specific grid values (0.2/0.6)
    instead of being random. Catches the attack even if variance is high.
    """
    current_time = packet.time
    icmp_timestamps.append(current_time)

    if len(icmp_timestamps) < ICMP_WINDOW_SIZE:
        return

    # 1. Calculate Delays
    delays = []
    for i in range(1, len(icmp_timestamps)):
        delays.append(icmp_timestamps[i] - icmp_timestamps[i-1])

    # 2. Check for "Binning" (Do delays look artificial?)
    # We ignore the large BATCH_GAP (>1.0s) and focus on the data bits.
    artificial_count = 0
    valid_delays = 0
    
    for d in delays:
        if d > 1.0: continue # Ignore the long pause between words
        
        valid_delays += 1
        # Check if this delay is close to 0.2 or 0.6
        match_found = False
        for bin_val in EXPECTED_BINS:
            if abs(d - bin_val) < TOLERANCE:
                match_found = True
                break
        
        if match_found:
            artificial_count += 1

    # 3. Detection Logic
    # If >75% of short delays match our known covert bins, it's an attack.
    if valid_delays >= 4: # Only judge if we have enough data points
        ratio = artificial_count / valid_delays
        if ratio > 0.75:
            print(f"\n[!!!] ALERT: ICMP TIMING CHANNEL DETECTED!")
            print(f"      Source: {packet[IP].src}")
            print(f"      Pattern: {int(ratio*100)}% of packets align to hidden grid (0.2s/0.6s).")
            print(f"      Confidence: VERY HIGH (Covert Timing Signature)\n")

def analyze_dns_advanced(packet):
    """
    Combines Entropy, Volume, AND Lexical checks to catch 
    single-packet attacks (like passwords).
    """
    if packet.haslayer(DNS) and packet[DNS].qr == 0:
        try:
            query = packet[DNSQR].qname.decode('utf-8').rstrip('.')
        except: return

        parts = query.split('.')
        if len(parts) < 2: return
        
        subdomain = parts[0]
        root_domain = ".".join(parts[-2:]) 
        
        # --- CHECK 1: LEXICAL SIGNATURE (New!) ---
        # Catch Base64 indicators immediately
        lexical_alert = False
        lexical_reason = ""
        
        # Rule A: Base64 relies on Mixed Case. Normal DNS is usually lowercase.
        if any(c.isupper() for c in subdomain):
            lexical_alert = True
            lexical_reason = "Suspicious Uppercase (Base64 Signature)"
            
        # Rule B: Base64 padding '=' or non-standard chars
        if '=' in subdomain or '+' in subdomain:
            lexical_alert = True
            lexical_reason = "Base64 Padding Detected"
            
        # Rule C: Unusually Long Subdomain (even if entropy is low)
        if len(subdomain) > SUBDOMAIN_LEN_THRESHOLD:
            lexical_alert = True
            lexical_reason = f"Abnormal Length ({len(subdomain)} chars)"

        if lexical_alert:
            print(f"\n[!!!] ALERT: MALICIOUS DNS SIGNATURE DETECTED!")
            print(f"      Source: {packet[IP].src}")
            print(f"      Payload: {subdomain}")
            print(f"      Reason: {lexical_reason}")
            print(f"      Note: Caught Single Packet Attack (Password Exfiltration)\n")
            return # Stop processing this packet (we already caught it)

        # --- CHECK 2: ENTROPY ---
        entropy = calculate_shannon_entropy(subdomain)
        if entropy > ENTROPY_THRESHOLD:
            print(f"\n[!!!] ALERT: HIGH ENTROPY DNS TUNNEL DETECTED!")
            print(f"      Source: {packet[IP].src}")
            print(f"      Reason: High Entropy ({entropy:.2f})\n")
            return

        # --- CHECK 3: VOLUME ---
        now = time.time()
        # Clean old history (> 10s ago)
        dns_tracker[root_domain] = [t for t in dns_tracker[root_domain] if now - t < DNS_WINDOW_TIME]
        
        # Add current query time
        dns_tracker[root_domain].append(now)
        count = len(dns_tracker[root_domain])
        
        if count >= DNS_QUERY_LIMIT:
            print(f"\n[!!!] ALERT: HIGH VOLUME DNS DETECTED!")
            print(f"      Domain: {root_domain}")
            print(f"      Reason: >{DNS_QUERY_LIMIT} queries in {DNS_WINDOW_TIME}s\n")
            # Clear buffer to avoid spam
            dns_tracker[root_domain] = [] 

# --- MAIN LOOP ---

def process_packet(packet):
    if not packet.haslayer(IP): return

    # Only inspect traffic FROM the Victim
    if packet[IP].src == TARGET_IP:

        if packet.haslayer(DNS):
            analyze_dns_advanced(packet) # Updated Function
        
        elif packet.haslayer(ICMP) and packet[ICMP].type == 8: # Echo Request
            analyze_icmp_clustering(packet)

print(f"[*] UNIVERSAL DETECTOR ONLINE (Signatures + Anomaly)")
print(f"[*] Monitoring Victim: {TARGET_IP}")
print(f"[*] Waiting for traffic...\n")

sniff(iface=INTERFACE, prn=process_packet, store=0)
