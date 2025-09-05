import socket
from urllib.parse import urlparse


def normalize_url(url: str) -> tuple[str, int]:
    # Ensure scheme; assume http when missing
    if "://" not in url:
        url = "http://" + url

    parsed = urlparse(url)
    scheme = (parsed.scheme or "http").lower()
    host = parsed.hostname or ""

    if parsed.port is not None:
        port = parsed.port
    else:
        if scheme == "https":
            port = 443
        else:
            port = 80

    return host, port


def resolve_ip(host: str) -> str:
    return socket.gethostbyname(host)

