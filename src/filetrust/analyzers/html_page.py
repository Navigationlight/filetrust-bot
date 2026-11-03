import re
from html.parser import HTMLParser

from filetrust.analyzers.links import bad_link_reason
from filetrust.models import FileInfo, Finding

MAX_READ = 5 * 1024 * 1024
BASE64_RE = re.compile(r"[A-Za-z0-9+/=]{2000,}")
JS_REDIRECT_RE = re.compile(
    r'''location(?:\.href)?\s*=\s*["'](https?://[^"']+)["']''')
JS_REPLACE_RE = re.compile(
    r'''location\.replace\(\s*["'](https?://[^"']+)["']''')
REFRESH_RE = re.compile(r'''url\s*=\s*["']?([^"']+)''', re.I)
OBFUSCATION_MARKERS = ("eval(", "unescape(", "fromcharcode", "atob(")


def _is_external(url: str) -> bool:
    return url.strip().lower().startswith(("http://", "https://", "//"))


class _Scan(HTMLParser):
    """Збирає з HTML усе, що нам цікаво. Файл не виконується."""

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.password_inputs = 0
        self.form_actions: list[str] = []
        self.links: list[str] = []
        self.hidden_iframes = 0
        self.refresh_urls: list[str] = []
        self.scripts: list[str] = []
        self._in_script = False

    def handle_starttag(self, tag, attrs):
        a = {k.lower(): (v or "") for k, v in attrs}
        if tag == "input" and a.get("type", "").lower() == "password":
            self.password_inputs += 1
        elif tag == "form" and a.get("action"):
            self.form_actions.append(a["action"])
        elif tag == "a" and a.get("href"):
            self.links.append(a["href"])
        elif tag == "iframe":
            style = a.get("style", "").replace(" ", "").lower()
            w = a.get("width", "").strip().lower().rstrip("px")
            h = a.get("height", "").strip().lower().rstrip("px")
            if (w in ("0", "1") or h in ("0", "1")
                    or "display:none" in style
                    or "visibility:hidden" in style):
                self.hidden_iframes += 1
        elif tag == "meta" and a.get("http-equiv", "").lower() == "refresh":
            m = REFRESH_RE.search(a.get("content", ""))
            if m:
                self.refresh_urls.append(m.group(1).strip())
        elif tag == "script":
            self._in_script = True

    def handle_endtag(self, tag):
        if tag == "script":
            self._in_script = False

    def handle_data(self, data):
        if self._in_script:
            self.scripts.append(data)


def check_html(info: FileInfo) -> list[Finding]:
    with info.path.open("rb") as f:
        text = f.read(MAX_READ).decode("utf-8", errors="ignore")

    scan = _Scan()
    try:
        scan.feed(text)
        scan.close()
    except Exception:
        pass  # зламана розмітка не повинна валити бота

    js = "\n".join(scan.scripts)
    low = js.lower()
    findings: list[Finding] = []

    if scan.password_inputs:
        findings.append(Finding(
            "HTML_PASSWORD_FORM", 40,
            "На сторінці є поле для пароля: ознака підробної форми входу"))

    external = [a for a in scan.form_actions if _is_external(a)]
    if external:
        findings.append(Finding(
            "HTML_FORM_EXTERNAL", 40,
            f"Форма надсилає дані на зовнішню адресу: {external[0][:80]}"))

    blob = "new blob" in low and any(
        k in low for k in ("createobjecturl", "mssaveblob", "mssaveoropenblob"))
    if blob and ("atob(" in low or BASE64_RE.search(js)):
        findings.append(Finding(
            "HTML_SMUGGLING", 60,
            "Сторінка збирає файл у браузері через JavaScript (HTML smuggling)"))

    if sum(m in low for m in OBFUSCATION_MARKERS) >= 2:
        findings.append(Finding(
            "HTML_OBFUSCATED_JS", 30,
            "JavaScript схожий на заплутаний (обфускований)"))

    redirects = [u for u in scan.refresh_urls if _is_external(u)]
    for rx in (JS_REDIRECT_RE, JS_REPLACE_RE):
        redirects += [m.group(1) for m in rx.finditer(js)]
    if redirects:
        findings.append(Finding(
            "HTML_REDIRECT", 30,
            f"Сторінка перенаправляє на зовнішню адресу: {redirects[0][:80]}"))

    if scan.hidden_iframes:
        findings.append(Finding(
            "HTML_HIDDEN_IFRAME", 30,
            "На сторінці є прихований вбудований фрейм"))

    reasons = []
    for u in scan.links + scan.form_actions + redirects:
        why = bad_link_reason(u)
        if why:
            reasons.append(f"{u[:60]} ({why})")
    if reasons:
        findings.append(Finding(
            "HTML_SUSPICIOUS_LINK", 30,
            "Підозрілі посилання: " + "; ".join(reasons[:3])))
    return findings