import urllib.request
from dnslib import DNSRecord

# ساخت DNS Query
query = DNSRecord.question("google.com", qtype="A").pack()

# ارسال POST به DoH Server
req = urllib.request.Request(
    url="http://127.0.0.1:8081/dns-query",
    data=query,
    method="POST",
    headers={
        "Content-Type": "application/dns-message"
    }
)

# دریافت پاسخ
with urllib.request.urlopen(req, timeout=3) as resp:
    response_data = resp.read()

# نمایش پاسخ DNS
print(DNSRecord.parse(response_data))
