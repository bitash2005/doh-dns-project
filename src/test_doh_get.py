import base64
import urllib.request
from dnslib import DNSRecord

# DNS Query به صورت باینری
query = DNSRecord.question("google.com", qtype="A").pack()

# base64url بدون '=' (طبق RFC 8484)
dns_param = base64.urlsafe_b64encode(query).decode().rstrip("=")

url = f"http://127.0.0.1:8081/dns-query?dns={dns_param}"

with urllib.request.urlopen(url, timeout=3) as resp:
    data = resp.read()

print(DNSRecord.parse(data))
