from scapy.all import sniff, IP, ICMP, DNS, DNSQR
import math
import time
from collections import deque

# --- CONFIGURATION ---
# The Interface to listen on (Attacker's Interface)
INTERFACE = "eth0" 
# The IP of the "Victim" we want to protect/monitor
TARGET_IP = "10.0.0.6" 

# --- THRESHOLDS ---
# DNS: 3.5 is a standard cutoff. English words are usually ~2.5 to 3.0. 
# Encrypted/Base64 data is usually > 4.0.
ENTROPY_THRESHOLD = 3.5 

# ICMP: Window size = how many packets to analyze before judging
ICMP_WINDOW_SIZE = 10 
icmp_timestamps = deque(maxlen=ICMP_WINDOW_SIZE)

# --- MATHEMATICAL FUNCTIONS ---

def calculate_shannon_entropy(data):
    """
    Calculates the randomness of a string (in bits).
    Higher value = More random (likely encrypted/encoded).
    """
    if not data:
        return 0
    entropy = 0
    for x in range(256):
        p_x = float(data.count(chr(x))) / len(data)
        if p_x > 0:
            entropy += - p_x * math.log(p_x, 2)
    return entropy

def analyze_icmp_timing(packet):
    """
    Looks for 'Machine-Like' consistency in ping intervals.
    Humans/Network Jitter = High Variance.
    Scripted Attacks = Low Variance.
    """
    current_time = packet.time
    icmp_timestamps.append(current_time)

    # We need at least 10 packets to make a statistical decision
    if len(icmp_timestamps) < ICMP_WINDOW_SIZE:
        return

    # 1. Calculate Delays (Delta)
    delays = []
    for i in range(1, len(icmp_timestamps)):
        delays.append(icmp_timestamps[i] - icmp_timestamps[i-1])

    # 2. Calculate Variance (How much the delay changes)
    avg_delay = sum(delays) / len(delays)
    variance = sum((d - avg_delay) ** 2 for d in delays) / len(delays)

    # 3. Detection Logic
    # If variance is SUPER low (< 0.05), it means the packets are arriving 
    # at exactly the same interval (e.g., exactly every 0.5s). 
    # That is unnatural for a human or normal network condition.
    if variance < 0.05 and avg_delay > 0.1:
        print(f"\n[!!!] ALERT: ICMP TIMING ANOMALY (COVERT CHANNEL) DETECTED!")
        print(f"      Source: {packet[IP].src}")
        print(f"      Avg Delay: {avg_delay:.4f}s | Variance: {variance:.5f}")
        print(f"      Confidence: HIGH (Traffic is robotic)\n")
    else:
        # Optional: Print stats for debugging
        # print(f"[*] ICMP Stats: Avg={avg_delay:.3f}s Var={variance:.5f}")
        pass

def analyze_dns_entropy(packet):
    """
    Checks if the DNS query looks like a real domain or hidden data.
    """
    # Check if it's a DNS Query (qr=0)
    if packet.haslayer(DNS) and packet[DNS].qr == 0:
        # Extract the query name (e.g., 'secret123.test.google.com.')
        query = packet[DNSQR].qname.decode('utf-8')
        
        # We only analyze the FIRST part (the subdomain)
        # "secret123.test.google.com" -> "secret123"
        subdomain = query.split('.')[0] 
        
        score = calculate_shannon_entropy(subdomain)
        
        if score > ENTROPY_THRESHOLD:
            print(f"\n[!!!] ALERT: HIGH ENTROPY DNS TUNNELING DETECTED!")
            print(f"      Source: {packet[IP].src}")
            print(f"      Suspicious Payload: {subdomain}")
            print(f"      Entropy Score: {score:.2f} (Threshold: {ENTROPY_THRESHOLD})\n")

# --- MAIN PACKET PROCESSOR ---

def process_packet(packet):
    if not packet.haslayer(IP):
        return

    # Only inspect traffic coming FROM the Victim
    if packet[IP].src == TARGET_IP:
        
        # Case A: DNS Traffic
        if packet.haslayer(DNS):
            analyze_dns_entropy(packet)
        
        # Case B: ICMP Traffic (Ping Requests)
        elif packet.haslayer(ICMP) and packet[ICMP].type == 8:
            analyze_icmp_timing(packet)

# --- STARTUP ---
print(f"[*] INTEGRATED ANOMALY DETECTOR ONLINE")
print(f"[*] Listening on: {INTERFACE}")
print(f"[*] Protecting Target: {TARGET_IP}")
print(f"[*] waiting for traffic...\n")

sniff(iface=INTERFACE, prn=process_packet, store=0)
