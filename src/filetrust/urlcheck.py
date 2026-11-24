
import ipaddress
import re
from urllib.parse import urlsplit

from filetrust.analyzers.common import EXEC_EXTS
from filetrust.analyzers.links import SHORTENERS
from filetrust.models import Finding

MAX_URLS = 10
URL_RE = re.compile(r"(?:https?://|www\.)[^\s<>\"'«»]+", re.I)
SCHEME_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.\-]*://")
DOMAIN_TEXT_RE = re.compile(r"^(?:https?://)?((?:[\w\-]+\.)+[a-z]{2,})(?:[/:?#]|$)", re.I)

DANGEROUS_SCHEMES = ("javascript:", "data:", "vbscript:", "file:")
RISKY_TLDS = {"zip", "mov", "top", "xyz", "click", "tk", "ml", "ga", "cf", "gq",
              "icu", "cyou", "rest", "cfd", "sbs", "quest"}
DOWNLOAD_EXTS = EXEC_EXTS | {".apk", ".iso", ".img", ".dmg"}
SECOND_LEVEL = {"co", "com", "org", "net", "gov", "edu", "ac"}

# бренди, під які найчастіше підробляють сайти
BRANDS = ("paypal", "google", "microsoft", "apple", "icloud", "amazon", "facebook",
          "instagram", "telegram", "whatsapp", "netflix", "binance", "monobank",
          "privatbank", "privat24", "novaposhta", "ukrposhta", "diia", "olx",
          "outlook", "office365", "youtube")
# справжні домени цих брендів
REAL_DOMAINS = {
    "google.com", "googleusercontent.com", "gstatic.com", "youtube.com", "youtu.be",
    "microsoft.com", "live.com", "office.com", "office365.com", "microsoftonline.com",
    "outlook.com", "apple.com", "icloud.com", "amazon.com", "amazonaws.com",
    "facebook.com", "fb.com", "instagram.com", "telegram.org", "t.me", "telegra.ph",
    "whatsapp.com", "netflix.com", "paypal.com", "binance.com", "olx.ua",
    "privatbank.ua", "privat24.ua", "monobank.ua", "novaposhta.ua", "ukrposhta.ua",
    "diia.gov.ua",
}


def _d(host: str) -> str:
    """Домен у безпечному вигляді, щоб Telegram не робив його клікабельним."""
    return host.replace(".", "[.]")


def registered_domain(host: str) -> str:
    labels = host.split(".")
    if len(labels) >= 3 and len(labels[-1]) == 2 and labels[-2] in SECOND_LEVEL:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def extract_urls(text: str, entities=None) -> list[tuple[str, str | None]]:
    """Посилання з тексту і з прихованих посилань (адреса, видимий текст)."""
    found: dict[str, str | None] = {}
    for e in entities or []:
        try:
            if e.type == "text_link" and e.url:
                found.setdefault(e.url, e.extract_from(text))
            elif e.type == "url":
                found.setdefault(e.extract_from(text), None)
        except Exception:
            continue
    for m in URL_RE.finditer(text or ""):
        found.setdefault(m.group(0).rstrip(".,;:!?)]}"), None)
    return list(found.items())[:MAX_URLS]


def check_url(url: str, shown: str | None = None) -> list[Finding]:
    url = url.strip()
    low = url.lower()
    if low.startswith(DANGEROUS_SCHEMES):
        return [Finding("LINK_DANGEROUS_SCHEME", 60,
                        "Посилання виконує код або відкриває локальний файл")]
    explicit = bool(SCHEME_RE.match(url))
    try:
        parts = urlsplit(url if explicit else "https://" + url)
        host = (parts.hostname or "").lower().rstrip(".")
        port = parts.port
    except ValueError:
        return []
    if not host:
        return []

    out: list[Finding] = []
    reg = registered_domain(host)
    tld = host.rsplit(".", 1)[-1]

    if "@" in parts.netloc:
        out.append(Finding(
            "LINK_USERINFO", 50,
            f"У адресі є @: справжній сайт {_d(host)}, а текст перед @ лише маскування"))
    try:
        ipaddress.ip_address(host)
        out.append(Finding("LINK_IP", 35, "Адреса IP замість домену"))
    except ValueError:
        if "xn--" in host or any(ord(c) > 127 for c in host):
            out.append(Finding(
                "LINK_PUNYCODE", 35,
                "Домен із незвичними символами, літери можуть бути підмінені на схожі"))
        if host in SHORTENERS:
            out.append(Finding(
                "LINK_SHORTENER", 30,
                "Скорочене посилання: не видно, куди воно веде насправді"))
        if tld in RISKY_TLDS:
            out.append(Finding("LINK_RISKY_TLD", 15,
                               f"Зона .{tld} часто використовується у шахрайських сайтах"))
        for brand in BRANDS:
            if brand in host and reg not in REAL_DOMAINS:
                label = reg.split(".")[0]
                if label == brand and tld not in RISKY_TLDS:
                    continue
                out.append(Finding(
                    "LINK_BRAND", 40,
                    f"Схоже на підробку «{brand}», але справжній домен {_d(reg)}"))
                break
        if host.count(".") >= 4 or len(host) > 60 or host.count("-") >= 4:
            out.append(Finding("LINK_LONG_HOST", 15,
                               "Дуже довга або заплутана назва сайту"))
    if low.startswith("http://"):
        out.append(Finding("LINK_NO_TLS", 10, "Без шифрування (http), дані видно в мережі"))
    if port not in (None, 80, 443):
        out.append(Finding("LINK_ODD_PORT", 10, f"Нестандартний порт {port}"))
    path = parts.path.lower()
    if any(path.endswith(ext) for ext in DOWNLOAD_EXTS):
        out.append(Finding("LINK_EXEC_DOWNLOAD", 40,
                           "Посилання веде на завантаження виконуваного файлу"))
    if shown:
        m = DOMAIN_TEXT_RE.match(shown.strip())
        if m and registered_domain(m.group(1).lower()) != reg:
            out.append(Finding(
                "LINK_TEXT_MISMATCH", 50,
                f"Текст показує {_d(m.group(1))}, а посилання веде на {_d(host)}"))
    return out
