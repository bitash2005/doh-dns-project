# auth.py
import base64
import bcrypt

# --- Admin credentials ---
ADMIN_USER = "admin"

# password: admin123
ADMIN_PASS_HASH = b"$2b$12$S6W2gSnMioGg3YlyaRZHYeCrUB6TYAMOwYydUls2vTq0lX2bC9Ggi"


def check_basic_auth(headers) -> bool:
    """
    فقط اعتبارسنجی می‌کند و هیچ پاسخ HTTP ارسال نمی‌کند.
    خروجی: True/False
    """
    auth_header = headers.get("Authorization", "")
    if not auth_header.startswith("Basic "):
        return False

    b64_part = auth_header.split(" ", 1)[1].strip()

    try:
        raw = base64.b64decode(b64_part).decode("utf-8", errors="strict")
        if ":" not in raw:
            return False
        username, password = raw.split(":", 1)
    except Exception:
        return False

    if username.strip() != ADMIN_USER:
        return False

    try:
        return bcrypt.checkpw(password.encode("utf-8"), ADMIN_PASS_HASH)
    except Exception:
        return False
