
from filetrust.analyzers.urlcheck import check_url
from filetrust.scoring.engine import score


def sc(u):
    return score(check_url(u))[0]


def test_js_library_names_are_not_downloads():
    for u in ("http://travis-ci.org/indutny/hash.js", "https://stackoverflow.com/questions/tagged/async.js",
              "https://cdn.example.org/lib/one.js"):
        assert "LINK_EXEC_DOWNLOAD" not in {f.id for f in check_url(u)}


def test_real_exe_download_still_flagged():
    assert sc("https://files.evil-site.top/update.exe") >= 40


def test_local_and_test_addresses_are_ignored():
    for u in ("http://127.0.0.1:5000/", "http://localhost:8080/x", "http://10.255.255.1", "http://example.com/a.js"):
        assert sc(u) == 0


def test_public_ip_still_flagged():
    assert sc("http://185.220.101.4/diia/pay") >= 30


def test_real_google_service_domains_are_not_brand_fakes():
    assert sc("https://ajax.googleapis.com/ajax/libs/jquery/3.7.1/jquery.min.js") < 30
    assert sc("https://ai.googleblog.com/2020/02/autoflip.html") < 30


def test_digit_and_hyphen_typosquats_are_caught():
    assert sc("https://secure-paypa1.com/login") >= 30
    assert sc("http://mono-bank.ua.pay-card.top/") >= 30
