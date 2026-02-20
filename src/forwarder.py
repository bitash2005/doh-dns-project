import socket

def forward_to_upstream(query_bytes: bytes, upstream_ip: str, upstream_port: int = 53, timeout: float = 2.0) -> bytes:
    """
    Query را به DNS بالادستی می‌فرستد و پاسخ خام را برمی‌گرداند.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    sock.sendto(query_bytes, (upstream_ip, upstream_port))
    resp, _ = sock.recvfrom(4096)
    return resp
