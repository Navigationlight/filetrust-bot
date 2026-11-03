import ipaddress
from urllib.parse import urlparse

SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "cutt.ly",
              "rebrand.ly", "ow.ly", "tiny.cc", "shorturl.at", "t.ly"}


def bad_link_reason(url: str) -> str | None:
  
    try:
        host = urlparse(url.strip()).hostname
    except ValueError:
        return None
    if not host:
        return None
    host = host.lower()
    try:
        ipaddress.ip_address(host)
        return "адреса IP замість домену"
    except ValueError:
        pass
    if host in SHORTENERS:
        return "скорочувач посилань"
    if "xn--" in host:
        return "домен у punycode (можлива підміна символів)"
    return None