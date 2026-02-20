# cli.py
import argparse
import base64
import json
import ssl
import socket
import struct
import urllib.parse
import urllib.request
import urllib.error

from dnslib import DNSRecord, QTYPE


DEFAULT_ADMIN = "http://127.0.0.1:8080"
DEFAULT_DOH = "https://127.0.0.1:8081/dns-query"
DEFAULT_DNS_HOST = "127.0.0.1"
DEFAULT_DNS_PORT = 8053

# ✅ defaults that match your project auth.py
DEFAULT_ADMIN_USER = "admin"
DEFAULT_ADMIN_PASS = "admin123"


def basic_auth_header(user: str, password: str) -> str:
    token = base64.b64encode(f"{user}:{password}".encode("utf-8")).decode("ascii")
    return f"Basic {token}"


def make_ssl_context(insecure: bool) -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    if insecure:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    return ctx


def http_request(url: str, method: str = "GET", data=None, headers=None, insecure=False):
    """
    Safe HTTP helper:
    - returns (status, content_type, body) even for HTTP errors like 401/404
    - avoids ugly tracebacks in CLI output
    """
    headers = headers or {}
    req = urllib.request.Request(url, method=method, data=data, headers=headers)
    ctx = make_ssl_context(insecure) if url.lower().startswith("https://") else None

    try:
        with urllib.request.urlopen(req, context=ctx) as resp:
            body = resp.read()
            ctype = resp.headers.get("Content-Type", "")
            return resp.status, ctype, body
    except urllib.error.HTTPError as e:
        body = e.read() if e.fp else b""
        ctype = e.headers.get("Content-Type", "") if e.headers else ""
        return e.code, ctype, body
    except urllib.error.URLError as e:
        raise SystemExit(f"Connection error: {e.reason}") from None


def ensure_admin_auth(args, headers: dict) -> dict:
    """
    If user didn't provide credentials, use project defaults.
    """
    user = args.user or DEFAULT_ADMIN_USER
    password = args.password or DEFAULT_ADMIN_PASS
    headers["Authorization"] = basic_auth_header(user, password)
    return headers


def print_http_result(status: int, ctype: str, body: bytes):
    print(f"HTTP {status} {ctype}".strip())
    if body:
        try:
            print(body.decode("utf-8", errors="replace"))
        except Exception:
            print(body)


# -------------------- Admin commands --------------------

def cmd_health(args):
    # ✅ FIX: your server health endpoint is /admin/health (not /health)
    url = args.admin_url.rstrip("/") + "/admin/health"

    headers = {}
    # health in your server is protected → always send auth (defaults apply)
    headers = ensure_admin_auth(args, headers)

    status, ctype, body = http_request(url, method="GET", headers=headers, insecure=args.insecure)
    print_http_result(status, ctype, body)

    if status == 401:
        print("Hint: Unauthorized. Use --user admin --password admin123 (or let defaults apply).")
    elif status == 404:
        print("Hint: Endpoint not found. Check admin_http.py routes.")


def cmd_list(args):
    url = args.admin_url.rstrip("/") + "/admin/records"
    headers = {}
    headers = ensure_admin_auth(args, headers)

    status, ctype, body = http_request(url, method="GET", headers=headers, insecure=args.insecure)
    print_http_result(status, ctype, body)

    if status == 401:
        print("Hint: Unauthorized. Use --user admin --password admin123 (or let defaults apply).")


def cmd_add(args):
    url = args.admin_url.rstrip("/") + "/admin/record"
    headers = {"Content-Type": "application/json"}
    headers = ensure_admin_auth(args, headers)

    payload = {
        "domain": args.domain,
        "type": args.rtype,
        "value": args.value,
        "ttl": args.ttl,
        "priority": args.priority,
    }
    data = json.dumps(payload).encode("utf-8")

    status, ctype, body = http_request(url, method="POST", data=data, headers=headers, insecure=args.insecure)
    print_http_result(status, ctype, body)

    if status == 401:
        print("Hint: Unauthorized. Use --user admin --password admin123 (or let defaults apply).")
    elif status == 400:
        print("Hint: Bad request. Check record fields: domain/type/value/ttl/priority.")


def cmd_delete(args):
    url = args.admin_url.rstrip("/") + f"/admin/record/{urllib.parse.quote(args.domain)}"
    headers = {}
    headers = ensure_admin_auth(args, headers)

    status, ctype, body = http_request(url, method="DELETE", headers=headers, insecure=args.insecure)
    print_http_result(status, ctype, body)

    if status == 401:
        print("Hint: Unauthorized. Use --user admin --password admin123 (or let defaults apply).")
    elif status == 404:
        print("Hint: Record/domain not found (or endpoint mismatch).")


# -------------------- DoH commands --------------------

def cmd_doh_get(args):
    q = {"name": args.name, "type": args.qtype}
    url = args.doh_url + "?" + urllib.parse.urlencode(q)
    headers = {"Accept": "application/dns-json"}

    status, ctype, body = http_request(url, method="GET", headers=headers, insecure=args.insecure)
    print_http_result(status, ctype, body)


def cmd_doh_post(args):
    qtype = getattr(QTYPE, args.qtype, None)
    if qtype is None:
        raise SystemExit(f"Unsupported qtype: {args.qtype}")

    q = DNSRecord.question(args.name, args.qtype)
    wire = q.pack()

    headers = {
        "Content-Type": "application/dns-message",
        "Accept": "application/dns-message",
    }

    status, ctype, body = http_request(args.doh_url, method="POST", data=wire, headers=headers, insecure=args.insecure)
    print(f"HTTP {status} {ctype}".strip())

    if status != 200:
        if body:
            print(body.decode("utf-8", errors="replace"))
        return

    if "application/dns-message" in ctype:
        try:
            print(DNSRecord.parse(body))
        except Exception:
            print(body.hex())
    else:
        print(body.decode("utf-8", errors="replace"))


# -------------------- Plain DNS (UDP/TCP) for demo --------------------

def dns_query_udp(host, port, qname, qtype):
    q = DNSRecord.question(qname, qtype).pack()
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(3)
    sock.sendto(q, (host, port))
    data, _ = sock.recvfrom(65535)
    return data


def dns_query_tcp(host, port, qname, qtype):
    q = DNSRecord.question(qname, qtype).pack()
    s = socket.create_connection((host, port), timeout=3)
    s.sendall(struct.pack("!H", len(q)) + q)
    h = s.recv(2)
    if len(h) != 2:
        raise RuntimeError("TCP DNS: failed to read length")
    l = struct.unpack("!H", h)[0]
    data = b""
    while len(data) < l:
        chunk = s.recv(l - len(data))
        if not chunk:
            break
        data += chunk
    return data


def cmd_query(args):
    if args.proto == "udp":
        resp = dns_query_udp(args.dns_host, args.dns_port, args.name, args.qtype)
    else:
        resp = dns_query_tcp(args.dns_host, args.dns_port, args.name, args.qtype)

    print(DNSRecord.parse(resp))


# -------------------- Main --------------------

def main():
    p = argparse.ArgumentParser(description="DoH/DNS Project CLI")
    p.add_argument("--admin-url", default=DEFAULT_ADMIN)
    p.add_argument("--doh-url", default=DEFAULT_DOH)
    p.add_argument("--dns-host", default=DEFAULT_DNS_HOST)
    p.add_argument("--dns-port", type=int, default=DEFAULT_DNS_PORT)

    p.add_argument("--user", help="Admin username (Basic Auth). Default: admin")
    p.add_argument("--password", help="Admin password (Basic Auth). Default: admin123")
    p.add_argument("--insecure", action="store_true", help="Disable TLS verification (self-signed)")

    sub = p.add_subparsers(required=True)

    sp = sub.add_parser("health", help="Admin health check")
    sp.set_defaults(func=cmd_health)

    sp = sub.add_parser("list", help="List DNS records")
    sp.set_defaults(func=cmd_list)

    sp = sub.add_parser("add", help="Add a DNS record")
    sp.add_argument("--domain", required=True)
    sp.add_argument("--type", dest="rtype", required=True)
    sp.add_argument("--value", required=True)
    sp.add_argument("--ttl", type=int, default=60)
    sp.add_argument("--priority", type=int, default=10)
    sp.set_defaults(func=cmd_add)

    sp = sub.add_parser("delete", help="Delete records by domain")
    sp.add_argument("--domain", required=True)
    sp.set_defaults(func=cmd_delete)

    sp = sub.add_parser("doh-get", help="DoH GET query (dns-json)")
    sp.add_argument("--name", required=True)
    sp.add_argument("--type", dest="qtype", default="A")
    sp.set_defaults(func=cmd_doh_get)

    sp = sub.add_parser("doh-post", help="DoH POST query (application/dns-message)")
    sp.add_argument("--name", required=True)
    sp.add_argument("--type", dest="qtype", default="A")
    sp.set_defaults(func=cmd_doh_post)

    sp = sub.add_parser("query", help="Plain DNS query to local DNS server (udp/tcp)")
    sp.add_argument("--proto", choices=["udp", "tcp"], default="udp")
    sp.add_argument("--name", required=True)
    sp.add_argument("--type", dest="qtype", default="A")
    sp.set_defaults(func=cmd_query)

    args = p.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
