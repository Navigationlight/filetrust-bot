import pytest

from filetrust.analyzers.urlcheck import check_url, extract_urls, registered_domain
from filetrust.scoring.explain import assess

BAD = {
    "https://google.com@evil.com/login": "LINK_USERINFO",
    "http://paypal-secure-login.xyz/verify": "LINK_BRAND",
    "https://bit.ly/3abcd": "LINK_SHORTENER",
    "http://185.10.20.30/pay": "LINK_IP",
    "https://xn--pple-43d.com/id": "LINK_PUNYCODE",
    "https://files.example.org/setup.exe": "LINK_EXEC_DOWNLOAD",
    "javascript:alert(1)": "LINK_DANGEROUS_SCHEME",
    "https://secure.monobank-ua-card.top/pay": "LINK_BRAND",
}
GOOD = [
    "https://www.google.com/search?q=filetrust",
    "https://github.com/Navigationlight/filetrust-bot",
    "https://google.com.ua/maps",
    "https://diia.gov.ua/services",
    "https://t.me/somechannel",
    "https://uk.wikipedia.org/wiki/Python",
]


@pytest.mark.parametrize("url,fid", BAD.items())
def test_bad_links_are_flagged(url, fid):
    ids = {f.id for f in check_url(url)}
    assert fid in ids
    assert assess(check_url(url)).total >= 30 or fid in ("LINK_PUNYCODE", "LINK_IP")


@pytest.mark.parametrize("url", GOOD)
def test_normal_links_are_clean(url):
    assert assess(check_url(url)).total < 30


def test_hidden_link_text_mismatch():
    ids = {f.id for f in check_url("https://evil.example.net/x", shown="paypal.com")}
    assert "LINK_TEXT_MISMATCH" in ids
    assert not check_url("https://paypal.com/x", shown="paypal.com")


def test_garbage_does_not_crash():
    for u in ["", "http://", "https://[::1", "://", "http://a b", "\x00", "http://" + "a" * 5000]:
        check_url(u)


def test_extract_urls_dedup_and_cap():
    text = " ".join(f"https://site{i}.example.com/a" for i in range(30)) + " https://site0.example.com/a"
    assert len(extract_urls(text)) == 10
    assert extract_urls("див. https://example.com/x.") == [("https://example.com/x", None)]


def test_registered_domain():
    assert registered_domain("a.b.example.com") == "example.com"
    assert registered_domain("shop.site.co.uk") == "site.co.uk"
    assert registered_domain("diia.gov.ua") == "diia.gov.ua"
