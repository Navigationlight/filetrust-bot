
import logging
import time

import aiohttp

from filetrust.models import Finding

log = logging.getLogger(__name__)
ENDPOINT = "https://safebrowsing.googleapis.com/v4/threatMatches:find"
TYPES = ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"]
NAMES = {"MALWARE": "шкідливе ПЗ", "SOCIAL_ENGINEERING": "фішинг або шахрайство",
         "UNWANTED_SOFTWARE": "небажане ПЗ", "POTENTIALLY_HARMFUL_APPLICATION": "потенційно шкідливий застосунок"}
CACHE_SEC = 600
_cache: dict[str, tuple[float, set[str]]] = {}


def build_request(urls: list[str]) -> dict:
    return {"client": {"clientId": "filetrust", "clientVersion": "1.0"},
            "threatInfo": {"threatTypes": TYPES, "platformTypes": ["ANY_PLATFORM"],
                           "threatEntryTypes": ["URL"], "threatEntries": [{"url": u} for u in urls]}}


def parse(payload: dict) -> dict[str, set[str]]:
    out: dict[str, set[str]] = {}
    for m in payload.get("matches", []) or []:
        try:
            out.setdefault(m["threat"]["url"], set()).add(m["threatType"])
        except (KeyError, TypeError):
            continue
    return out


def findings_for(types: set[str] | None) -> list[Finding]:
    if not types:
        return []
    what = ", ".join(NAMES.get(t, t.lower()) for t in sorted(types))
    return [Finding("LINK_SAFEBROWSING", 80, f"Google Safe Browsing позначає адресу як небезпечну ({what})")]


async def lookup(urls: list[str], key: str, timeout: float = 5.0) -> dict[str, set[str]] | None:
   
    if not key or not urls:
        return None
    now = time.time()
    fresh = {u: _cache[u][1] for u in urls if u in _cache and now - _cache[u][0] < CACHE_SEC}
    todo = [u for u in urls if u not in fresh][:500]
    result = {u: t for u, t in fresh.items() if t}
    if todo:
        try:
            async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=timeout)) as s:
                async with s.post(ENDPOINT, params={"key": key}, json=build_request(todo)) as r:
                    if r.status != 200:
                        log.warning("Safe Browsing відповів %s", r.status)
                        return result or None
                    found = parse(await r.json())
        except (aiohttp.ClientError, TimeoutError, ValueError) as exc:
            log.warning("Safe Browsing недоступний: %s", exc)
            return result or None
        for u in todo:
            _cache[u] = (now, found.get(u, set()))
        result.update(found)
    return result
