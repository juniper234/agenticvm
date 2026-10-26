"""Shared checks performed before desktop input reaches guest processes."""
from urllib.parse import urlsplit


def validate_http_url(value: str) -> str:
    """Return a literal, valid UTF-8 HTTP(S) URL or raise a bounded error."""
    message = "Supply an HTTP(S) URL with a valid port, without embedded credentials or control characters."
    if not isinstance(value, str) or len(value) > 4096:
        raise ValueError(message)
    try:
        value.encode("utf-8")
        parsed = urlsplit(value)
        port = parsed.port  # Accessing this property validates syntax/range.
        valid = (parsed.scheme in {"http", "https"} and parsed.hostname
                 and parsed.username is None and parsed.password is None
                 and (port is None or 1 <= port <= 65535)
                 and not any(ord(char) < 32 or ord(char) == 127 for char in value))
    except (ValueError, UnicodeError):
        raise ValueError(message) from None
    if not valid:
        raise ValueError(message)
    return value
