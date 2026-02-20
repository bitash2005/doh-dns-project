import os
import socket
import threading
import socketserver
import struct

from cache import DNSCache
from dnslib import DNSRecord, RR, QTYPE, A, AAAA, CNAME, MX, TXT, NS, PTR
from logger import log_event, Timer

from records import RecordStore
from forwarder import forward_to_upstream
from admin_http import start_admin_server
from doh_http import start_doh_server


# -------------------- تنظیمات --------------------
HOST = "127.0.0.1"
PORT = 8053

ADMIN_PORT = 8080
DOH_PORT = 8081

UPSTREAM_DNS = "87.248.145.99"   # DNS بالادستی
UPSTREAM_PORT = 53

LOG_PATH = os.path.join(os.path.dirname(__file__), "dns.log")


# -------------------- رکوردها + کش --------------------
store = RecordStore()
cache = DNSCache(default_ttl=60, max_items=5000)

# رکوردهای اصلی
store.add("test.local", "A", "10.10.10.10", ttl=120)
store.add("ipv6.local", "AAAA", "2001:db8::1", ttl=120)
store.add("alias.local", "CNAME", "test.local", ttl=120)
store.add("mail.local", "MX", "mailserver.local", ttl=120, priority=10)
store.add("mailserver.local", "A", "10.10.10.20", ttl=120)

# رکوردهای امتیازی
store.add("txt.local", "TXT", "hello from doh project", ttl=120)
store.add("example.local", "NS", "ns1.example.local", ttl=120)
store.add("4.3.2.1.in-addr.arpa", "PTR", "example.com", ttl=120)


def add_answers(reply: DNSRecord, qname, records) -> None:
    """رکوردهای آماده را به reply اضافه می‌کند."""
    for rec in records:
        rtype = rec.rtype

        if rtype == "A":
            reply.add_answer(RR(qname, QTYPE.A, rclass=1, ttl=rec.ttl, rdata=A(rec.value)))

        elif rtype == "AAAA":
            reply.add_answer(RR(qname, QTYPE.AAAA, rclass=1, ttl=rec.ttl, rdata=AAAA(rec.value)))

        elif rtype == "CNAME":
            target = rec.value if rec.value.endswith(".") else rec.value + "."
            reply.add_answer(RR(qname, QTYPE.CNAME, rclass=1, ttl=rec.ttl, rdata=CNAME(target)))

        elif rtype == "MX":
            target = rec.value if rec.value.endswith(".") else rec.value + "."
            reply.add_answer(RR(qname, QTYPE.MX, rclass=1, ttl=rec.ttl, rdata=MX(target, rec.priority)))

        elif rtype == "TXT":
            reply.add_answer(RR(qname, QTYPE.TXT, rclass=1, ttl=rec.ttl, rdata=TXT(rec.value)))

        elif rtype == "NS":
            target = rec.value if rec.value.endswith(".") else rec.value + "."
            reply.add_answer(RR(qname, QTYPE.NS, rclass=1, ttl=rec.ttl, rdata=NS(target)))

        elif rtype == "PTR":
            target = rec.value if rec.value.endswith(".") else rec.value + "."
            reply.add_answer(RR(qname, QTYPE.PTR, rclass=1, ttl=rec.ttl, rdata=PTR(target)))


def handle_dns_query(query_bytes: bytes) -> bytes:
    """
    ورودی: DNS Query (bytes)
    خروجی: DNS Response (bytes)
    این تابع مشترک بین UDP / TCP / DoH است.
    """
    t = Timer()

    request = DNSRecord.parse(query_bytes)

    qname = request.q.qname
    qname_s = str(qname)
    qtype_int = request.q.qtype
    qtype_str = QTYPE[qtype_int]

    # 0) Cache
    cached = cache.get(qname_s, qtype_int)
    if cached:
        log_event(LOG_PATH, {
            "qname": qname_s,
            "qtype": qtype_str,
            "source": "CACHE",
            "ms": t.ms(),
            "cache": cache.stats(),
        })
        print(f"[CACHE HIT] {qname_s} TYPE={qtype_str} | stats={cache.stats()}", flush=True)
        return cached

    print(f"[DNS QUERY] {qname_s} TYPE={qtype_str} | stats={cache.stats()}", flush=True)

    # 1) LOCAL
    local_records = store.lookup(qname_s, qtype_str)
    if local_records:
        reply = request.reply()
        reply.header.aa = 1
        add_answers(reply, qname, local_records)

        resp_bytes = reply.pack()
        cache.set_from_response(qname_s, qtype_int, resp_bytes)

        log_event(LOG_PATH, {
            "qname": qname_s,
            "qtype": qtype_str,
            "source": "LOCAL",
            "ms": t.ms(),
            "cache": cache.stats(),
        })
        return resp_bytes

    # 2) UPSTREAM
    try:
        resp_bytes = forward_to_upstream(query_bytes, UPSTREAM_DNS, UPSTREAM_PORT)
        cache.set_from_response(qname_s, qtype_int, resp_bytes)

        log_event(LOG_PATH, {
            "qname": qname_s,
            "qtype": qtype_str,
            "source": "UPSTREAM",
            "ms": t.ms(),
            "upstream": UPSTREAM_DNS,
            "cache": cache.stats(),
        })
        return resp_bytes

    except Exception as e:
        print("❌ Upstream forwarding failed:", e, flush=True)

        log_event(LOG_PATH, {
            "qname": qname_s,
            "qtype": qtype_str,
            "source": "UPSTREAM_FAIL",
            "ms": t.ms(),
            "upstream": UPSTREAM_DNS,
            "error": str(e),
            "cache": cache.stats(),
        })
        return request.reply().pack()


# -------------------- TCP DNS Server (RFC: 2-byte length prefix) --------------------
class ThreadingTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads = True  # هر اتصال در thread جدا، با خروج برنامه قطع می‌شود


class DNSTCPHandler(socketserver.BaseRequestHandler):
    def handle(self):
        try:
            while True:
                hdr = self._recv_exact(2)
                if not hdr:
                    return

                (msg_len,) = struct.unpack("!H", hdr)
                if msg_len <= 0 or msg_len > 65535:
                    return

                query = self._recv_exact(msg_len)
                if not query:
                    return

                dns_handler = getattr(self.server, "dns_handler", None)
                if dns_handler is None:
                    dns_handler = handle_dns_query  # fallback

                resp = dns_handler(query)
                out = struct.pack("!H", len(resp)) + resp
                self.request.sendall(out)

        except ConnectionError:
            return
        except Exception as e:
            print("❌ DNS TCP handler error:", e, flush=True)

    def _recv_exact(self, n: int) -> bytes:
        data = b""
        while len(data) < n:
            chunk = self.request.recv(n - len(data))
            if not chunk:
                return b""
            data += chunk
        return data


def start_dns_tcp_server(dns_handler_func, host=HOST, port=PORT):
    srv = ThreadingTCPServer((host, port), DNSTCPHandler)
    srv.dns_handler = dns_handler_func
    print(f"✅ DNS TCP server listening on {host}:{port}", flush=True)
    srv.serve_forever()


# -------------------- سرویس‌های HTTP --------------------
def start_services():
    """سرویس‌های Admin و DoH را در Thread جدا بالا می‌آورد."""
    threading.Thread(target=start_admin_server, args=(store, ADMIN_PORT), daemon=True).start()
    threading.Thread(target=start_doh_server, args=(handle_dns_query, DOH_PORT), daemon=True).start()


def start_udp_server():
    """UDP DNS Server"""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((HOST, PORT))
    print(f"✅ DNS UDP server listening on {HOST}:{PORT}", flush=True)

    while True:
        data, addr = sock.recvfrom(4096)
        try:
            resp = handle_dns_query(data)
            sock.sendto(resp, addr)
        except Exception as e:
            print("❌ Error while handling UDP query:", e, flush=True)


def main():
    # 1) سرویس‌های HTTP
    start_services()

    # 2) TCP DNS Server (در Thread جدا)
    threading.Thread(target=start_dns_tcp_server, args=(handle_dns_query, HOST, PORT), daemon=True).start()

    # 3) UDP DNS Server (در thread اصلی)
    start_udp_server()


if __name__ == "__main__":
    main()
