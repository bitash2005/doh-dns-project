import socket
from dnslib import DNSRecord

SERVER = ("127.0.0.1", 8053)

q = DNSRecord.question("new.local", qtype="A")
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.settimeout(2)

sock.sendto(q.pack(), SERVER)
resp_data, _ = sock.recvfrom(4096)

resp = DNSRecord.parse(resp_data)
print(resp)
