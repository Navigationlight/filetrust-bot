
import asyncio
import types

from filetrust import intel, sb
from filetrust.analyzers.urlcheck import check_url
from filetrust.scoring.engine import score

TOP = ["google.com", "youtube.com", "facebook.com", "paypal.com", "binance.com", "microsoft.com", "apple.com",
       "amazon.com", "netflix.com", "instagram.com", "github.com", "blogspot.com", "googleblog.com", "monobank.ua",
       "privatbank.ua", "novaposhta.ua", "wikipedia.org", "telegram.org", "whatsapp.com", "linkedin.com"]


def make(tmp_path, phish=("evil-login.top", "bad.example-phish.com"), links=("http://exact.phish-url.net/a/b",)):
    (tmp_path / "phishing-domains-ACTIVE.txt").write_text("\n".join(phish), encoding="utf-8")
    (tmp_path / "phishing-links-ACTIVE.txt").write_text("\n".join(links), encoding="utf-8")
    (tmp_path / "top-1m.csv").write_text("\n".join(f"{i},{d}" for i, d in enumerate(TOP, 1)), encoding="utf-8")
    db = intel.Intel(tmp_path)
    intel.set_default(db)
    return db


def ids(url):
    return {f.id for f in check_url(url)}


def test_known_phishing_domain_and_subdomain(tmp_path):
    try:
        make(tmp_path)
        assert "LINK_PHISH_DB" in ids("http://evil-login.top/a")
        assert "LINK_PHISH_DB" in ids("https://secure.evil-login.top/")
        assert "LINK_PHISH_DB" in ids("https://bad.example-phish.com/x")
        assert score(check_url("https://evil-login.top/"))[0] >= 60
    finally:
        intel.set_default(None)


def test_exact_url_from_list(tmp_path):
    try:
        make(tmp_path)
        assert "LINK_PHISH_DB" in ids("https://exact.phish-url.net/a/b/")
    finally:
        intel.set_default(None)


def test_popular_domain_is_not_flagged_as_brand_fake(tmp_path):
    try:
        make(tmp_path)
        assert "LINK_BRAND" not in ids("https://googleblog.com/post")
    finally:
        intel.set_default(None)


def test_platform_subdomain_is_not_trusted_by_tranco(tmp_path):
    try:
        make(tmp_path)
        assert "LINK_BRAND" in ids("https://paypal-login.blogspot.com/")
    finally:
        intel.set_default(None)


def test_typosquat_one_edit_and_risky_tld(tmp_path):
    try:
        make(tmp_path)
        assert "LINK_TYPOSQUAT" in ids("https://paypa1.com/")
        assert "LINK_TYPOSQUAT" in ids("https://micr0soft.com/")
        assert "LINK_TYPOSQUAT" in ids("https://novaposhta.xyz/")
        assert "LINK_TYPOSQUAT" in ids("https://monobnak.ua/")
    finally:
        intel.set_default(None)


def test_unrelated_and_popular_domains_are_quiet(tmp_path):
    try:
        make(tmp_path)
        for u in ("https://paypal.com/signin", "https://my-small-bakery.com/", "https://wikipedia.org/wiki/X",
                  "https://exampleshop.net/cart"):
            assert not ids(u) & {"LINK_TYPOSQUAT", "LINK_PHISH_DB"}, u
    finally:
        intel.set_default(None)


def test_missing_intel_folder_is_harmless(tmp_path):
    try:
        intel.set_default(intel.Intel(tmp_path / "nope"))
        assert not intel.get().active
        assert not ids("https://example-site.com/") & {"LINK_PHISH_DB", "LINK_TYPOSQUAT"}
    finally:
        intel.set_default(None)


def test_safe_browsing_request_parse_and_findings():
    req = sb.build_request(["http://a.test/"])
    assert req["threatInfo"]["threatEntries"] == [{"url": "http://a.test/"}]
    got = sb.parse({"matches": [{"threatType": "SOCIAL_ENGINEERING", "threat": {"url": "http://a.test/"}}]})
    assert got == {"http://a.test/": {"SOCIAL_ENGINEERING"}}
    assert sb.parse({}) == {}
    f = sb.findings_for({"MALWARE"})
    assert f[0].id == "LINK_SAFEBROWSING" and f[0].points >= 60 and sb.findings_for(set()) == []


def test_safe_browsing_lookup_without_key_does_nothing():
    assert asyncio.run(sb.lookup(["http://a.test/"], "")) is None


def test_safe_browsing_lookup_with_fake_server_and_cache():
    calls = []

    class Resp:
        status = 200
        async def json(self): return {"matches": [{"threatType": "MALWARE", "threat": {"url": "http://bad.test/"}}]}
        async def __aenter__(self): return self
        async def __aexit__(self, *a): return False

    class Session:
        def __init__(self, **kw): pass
        def post(self, url, params=None, json=None):
            calls.append(json)
            return Resp()
        async def __aenter__(self): return self
        async def __aexit__(self, *a): return False

    real = sb.aiohttp
    sb.aiohttp = types.SimpleNamespace(ClientSession=Session, ClientTimeout=lambda total: None, ClientError=Exception)
    sb._cache.clear()
    try:
        r1 = asyncio.run(sb.lookup(["http://bad.test/", "http://ok.test/"], "k"))
        r2 = asyncio.run(sb.lookup(["http://bad.test/", "http://ok.test/"], "k"))
    finally:
        sb.aiohttp = real
    assert r1 == {"http://bad.test/": {"MALWARE"}} and r2 == r1
    assert len(calls) == 1          # другий раз із кешу
