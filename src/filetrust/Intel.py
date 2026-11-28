
import logging
import os
import string
import time
from pathlib import Path

from filetrust.models import Finding

log = logging.getLogger(__name__)
TOP_POPULAR = 100_000      
TOP_TYPO = 10_000         
STALE_DAYS = 14
ALPHABET = string.ascii_lowercase + string.digits + "-"
RISKY = {"top", "xyz", "click", "cfd", "sbs", "icu", "cyou", "quest", "rest", "tk", "ml", "ga", "cf", "gq", "zip", "mov"}


PLATFORMS = (
    "blogspot.com", "github.io", "gitlab.io", "herokuapp.com", "netlify.app", "vercel.app", "pages.dev",
    "workers.dev", "web.app", "firebaseapp.com", "weebly.com", "wixsite.com", "000webhostapp.com",
    "azurewebsites.net", "azureedge.net", "cloudfront.net", "s3.amazonaws.com", "appspot.com",
    "sites.google.com", "forms.gle", "notion.site", "godaddysites.com", "glitch.me", "repl.co",
    "ngrok.io", "ngrok-free.app", "trycloudflare.com", "r2.dev", "myshopify.com", "carrd.co",
)


def _lines(path: Path):
    if not path.exists():
        return
    with path.open(encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip().lower()
            if line and not line.startswith("#"):
                yield line


def norm_url(url: str) -> str:
    u = url.strip().lower().split("#", 1)[0]
    for p in ("https://", "http://"):
        if u.startswith(p):
            u = u[len(p):]
    return u.rstrip("/")


def on_platform(host: str) -> bool:
    return any(host == p or host.endswith("." + p) for p in PLATFORMS)


class Intel:
    def __init__(self, folder: str | Path | None):
        self.folder = Path(folder) if folder else None
        self.phish_domains: set[str] = set()
        self.phish_urls: set[str] = set()
        self.rank: dict[str, int] = {}
        self.typo_pool: set[str] = set()
        self.loaded_at = 0.0
        if self.folder:
            self._load()

    def _load(self) -> None:
        d = self.folder
        self.phish_domains = set(_lines(d / "phishing-domains-ACTIVE.txt"))
        self.phish_urls = {norm_url(x) for x in _lines(d / "phishing-links-ACTIVE.txt")}
        for line in _lines(d / "top-1m.csv"):
            rank, _, dom = line.partition(",")
            if rank.isdigit() and dom and int(rank) <= TOP_POPULAR:
                self.rank[dom] = int(rank)
        self.typo_pool = {x for x, r in self.rank.items() if r <= TOP_TYPO and len(x) >= 7}
        self.loaded_at = time.time()
        log.info("intel: фішинг доменів %d, адрес %d, Tranco %d", len(self.phish_domains),
                 len(self.phish_urls), len(self.rank))

    @property
    def active(self) -> bool:
        return bool(self.phish_domains or self.phish_urls or self.rank)

    def stale(self) -> bool:
        files = [p for p in (self.folder.glob("*") if self.folder and self.folder.exists() else [])]
        return bool(files) and time.time() - min(p.stat().st_mtime for p in files) > STALE_DAYS * 86400

    def is_popular(self, reg: str) -> bool:
        return reg in self.rank and not on_platform(reg)

    def phish(self, host: str, url: str) -> bool:
        if norm_url(url) in self.phish_urls or host in self.phish_domains:
            return True
        parts = host.split(".")
        for i in range(1, len(parts) - 1):                      
            parent = ".".join(parts[i:])
            if parent in self.phish_domains and not self.is_popular(parent) and not on_platform(parent):
                return True
        return False

    def typosquat(self, reg: str) -> str | None:
       
        if not self.typo_pool or reg in self.rank or on_platform(reg) or len(reg) < 7:
            return None
        label, _, tld = reg.partition(".")
        for v in _edits1(label):
            for cand in (f"{v}.{tld}",):
                if cand in self.typo_pool:
                    return cand
        if tld in RISKY:
            for cand in self.typo_pool:
                if cand.partition(".")[0] == label and len(label) >= 5:
                    return cand
        return None

    def findings(self, host: str, url: str, reg: str) -> list[Finding]:
        out: list[Finding] = []
        if self.phish(host, url):
            out.append(Finding("LINK_PHISH_DB", 80, "Ця адреса є у списку відомого фішингу Phishing.Database"))
        elif (hit := self.typosquat(reg)):
            out.append(Finding("LINK_TYPOSQUAT", 40, f"Домен майже збігається з популярним {hit}, схоже на підробку"))
        return out


def _edits1(w: str):
   
    n = len(w)
    for i in range(n):
        yield w[:i] + w[i + 1:]
    for i in range(n - 1):
        yield w[:i] + w[i + 1] + w[i] + w[i + 2:]
    for i in range(n):
        for c in ALPHABET:
            if c != w[i]:
                yield w[:i] + c + w[i + 1:]
    for i in range(n + 1):
        for c in ALPHABET:
            yield w[:i] + c + w[i:]


_default: Intel | None = None


def get() -> Intel:
    global _default
    if _default is None:
        _default = Intel(os.getenv("INTEL_DIR", "data/intel"))
    return _default


def set_default(intel: Intel | None) -> None:
    global _default
    _default = intel
