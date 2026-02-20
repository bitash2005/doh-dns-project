from dnslib import DNSRecord
import socket

SERVER = ("127.0.0.1", 8053)

def query(name: str, qtype: str):
    q = DNSRecord.question(name, qtype=qtype)  # qtype باید string باشد مثل "TXT"
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(2)
    s.sendto(q.pack(), SERVER)
    data, _ = s.recvfrom(4096)
    print(DNSRecord.parse(data))
    print("-" * 60)

query("txt.local", "TXT")
query("example.local", "NS")
query("4.3.2.1.in-addr.arpa", "PTR")
