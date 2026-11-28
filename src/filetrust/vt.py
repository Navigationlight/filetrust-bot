
import logging

import aiohttp

log = logging.getLogger(__name__)
URL = "https://www.virustotal.com/api/v3/files/{}"


def parse(payload: dict) -> dict | None:
    try:
        st = payload["data"]["attributes"]["last_analysis_stats"]
        total = sum(int(v) for v in st.values())
        mal, sus = int(st.get("malicious", 0)), int(st.get("suspicious", 0))
        return {"malicious": mal, "suspicious": sus, "bad": mal + sus, "total": total}
    except (KeyError, TypeError, ValueError):
        return None


async def lookup(sha256: str, key: str, timeout: float = 6.0) -> dict | None:
    """None, якщо ключа немає або сервіс не відповів. {"unknown": True}, якщо хешу немає у базі."""
    if not key:
        return None
    try:
        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=timeout)) as s:
            async with s.get(URL.format(sha256), headers={"x-apikey": key}) as r:
                if r.status == 404:
                    return {"unknown": True}
                if r.status != 200:
                    log.warning("VirusTotal відповів %s", r.status)
                    return None
                return parse(await r.json())
    except (aiohttp.ClientError, TimeoutError, ValueError) as exc:
        log.warning("VirusTotal недоступний: %s", exc)
        return None
