import base64
import json
import os
import ssl
import datetime
import ipaddress
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs

from dnslib import DNSRecord, QTYPE

_dns_handler = None


# -----------------------------
# Self-signed certificate helper (no openssl needed)
# -----------------------------
def ensure_self_signed_cert(certfile: str = "cert.pem", keyfile: str = "key.pem"):
    """
    اگر cert.pem / key.pem وجود نداشت، با cryptography خودش می‌سازد.
    """
    if os.path.exists(certfile) and os.path.exists(keyfile):
        return

    try:
        from cryptography import x509
        from cryptography.x509.oid import NameOID
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
    except Exception as e:
        raise RuntimeError(
            "cryptography is not installed. Install it with: python -m pip install cryptography"
        ) from e

    # Private key
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "IR"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Tehran"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "Localhost"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "DoH Project"),
        x509.NameAttribute(NameOID.COMMON_NAME, "127.0.0.1"),
    ])

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.utcnow() - datetime.timedelta(minutes=1))
        .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=365))
        .add_extension(
            x509.SubjectAlternativeName([
                x509.DNSName("localhost"),
                x509.IPAddress(ipaddress.ip_address("127.0.0.1")),
            ]),
            critical=False
        )
        .sign(key, hashes.SHA256())
    )

    # Write key
    with open(keyfile, "wb") as f:
        f.write(
            key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )

    # Write certificate
    with open(certfile, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

    print(f"✅ Self-signed cert generated: {certfile}, {keyfile}", flush=True)


class DoHHandler(BaseHTTPRequestHandler):
    def _send_bytes(self, code: int, body: bytes, content_type: str):
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_json(self, code: int, payload: dict):
        body = json.dumps(payload, indent=2).encode("utf-8")
        # استاندارد رایج در DoH JSON همون dns-json هست
        self.send_response(code)
        self.send_header("Content-Type", "application/dns-json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _safe_dns_call(self, query_bytes: bytes) -> bytes:
        """
        تضمین می‌کند خروجی همیشه bytes معتبر DNS باشد
        """
        try:
            resp = _dns_handler(query_bytes)
            if not resp or not isinstance(resp, (bytes, bytearray)):
                raise ValueError("DNS handler returned invalid response")
            return bytes(resp)
        except Exception as e:
            print("❌ DNS handler error:", e, flush=True)
            # پاسخ DNS خالی ولی معتبر
            try:
                return DNSRecord.parse(query_bytes).reply().pack()
            except Exception:
                try:
                    return DNSRecord().reply().pack()
                except Exception:
                    return b""

    def _dns_to_json(self, resp_bytes: bytes) -> dict:
        record = DNSRecord.parse(resp_bytes)

        def rr_to_dict(rr):
            return {
                "name": str(rr.rname),
                "type": rr.rtype,
                "TTL": rr.ttl,
                "data": str(rr.rdata),
            }

        return {
            "Status": record.header.rcode,
            "TC": int(record.header.tc),
            "RD": int(record.header.rd),
            "RA": int(record.header.ra),
            "AD": int(getattr(record.header, "ad", 0)),
            "CD": int(getattr(record.header, "cd", 0)),
            "Question": [{"name": str(q.qname), "type": q.qtype} for q in record.questions],
            "Answer": [rr_to_dict(a) for a in record.rr],
        }

    def do_GET(self):
        try:
            if not self.path.startswith("/dns-query"):
                self._send_bytes(404, b"Not Found", "text/plain")
                return

            parsed = urlparse(self.path)
            qs = parse_qs(parsed.query)

            accept = self.headers.get("Accept", "")
            want_json = ("application/dns-json" in accept) or (qs.get("ct", [""])[0] == "dns-json")

            # -------------------------
            # 1) DNS-JSON mode
            # /dns-query?name=example.com&type=TXT&ct=dns-json
            # -------------------------
            if "name" in qs and qs["name"]:
                name = qs["name"][0]
                qtype_str = qs.get("type", ["A"])[0].upper().strip()

                # اگر type ناشناخته بود، A
                if not hasattr(QTYPE, qtype_str):
                    qtype_str = "A"

                query = DNSRecord.question(name, qtype_str).pack()
                resp = self._safe_dns_call(query)

                if want_json:
                    self._send_json(200, self._dns_to_json(resp))
                else:
                    self._send_bytes(200, resp, "application/dns-message")
                return

            # -------------------------
            # 2) Binary DoH GET (RFC8484)
            # /dns-query?dns=BASE64URL
            # -------------------------
            if "dns" not in qs or not qs["dns"]:
                self._send_bytes(400, b"Missing dns or name parameter", "text/plain")
                return

            dns_b64 = qs["dns"][0]
            padding = "=" * (-len(dns_b64) % 4)

            try:
                query = base64.urlsafe_b64decode(dns_b64 + padding)
            except Exception:
                self._send_bytes(400, b"Invalid base64url", "text/plain")
                return

            resp = self._safe_dns_call(query)

            if want_json:
                self._send_json(200, self._dns_to_json(resp))
            else:
                self._send_bytes(200, resp, "application/dns-message")

        except Exception as e:
            print("❌ DoH GET fatal error:", e, flush=True)
            # برای اینکه کلاینت‌های dns-json نخوابن:
            self._send_json(200, {"Status": 2, "Answer": []})

    def do_POST(self):
        try:
            if self.path != "/dns-query":
                self._send_bytes(404, b"Not Found", "text/plain")
                return

            if "application/dns-message" not in self.headers.get("Content-Type", ""):
                self._send_bytes(415, b"Unsupported Media Type", "text/plain")
                return

            length = int(self.headers.get("Content-Length", "0"))
            query = self.rfile.read(length)

            resp = self._safe_dns_call(query)
            self._send_bytes(200, resp, "application/dns-message")

        except Exception as e:
            print("❌ DoH POST error:", e, flush=True)
            self._send_bytes(500, b"Internal Server Error", "text/plain")


def start_doh_server(
    dns_handler_func,
    port: int = 8081,
    use_https: bool = True,
    certfile: str = "cert.pem",
    keyfile: str = "key.pem",
):
    global _dns_handler
    _dns_handler = dns_handler_func

    server = HTTPServer(("127.0.0.1", port), DoHHandler)

    if use_https:
        ensure_self_signed_cert(certfile=certfile, keyfile=keyfile)

        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(certfile=certfile, keyfile=keyfile)
        server.socket = context.wrap_socket(server.socket, server_side=True)

        print(f"✅ DoH (HTTPS) listening on https://127.0.0.1:{port}/dns-query", flush=True)
    else:
        print(f"✅ DoH (HTTP) listening on http://127.0.0.1:{port}/dns-query", flush=True)

    server.serve_forever()
