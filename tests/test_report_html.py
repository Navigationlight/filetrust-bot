"""Формат відповідей: Telegram HTML, екранування, ліміт, відсутність клікабельних посилань."""
from html.parser import HTMLParser
from pathlib import Path

from filetrust.models import FileInfo, Finding
from filetrust.report import format_links, format_report, format_short, strip_tags
from filetrust.scoring.explain import assess

ALLOWED = {"b", "i", "code", "pre", "blockquote", "a"}


class Checker(HTMLParser):
    def __init__(self):
        super().__init__()
        self.stack, self.bad = [], []

    def handle_starttag(self, tag, attrs):
        if tag not in ALLOWED:
            self.bad.append(tag)
        self.stack.append(tag)

    def handle_endtag(self, tag):
        if not self.stack or self.stack.pop() != tag:
            self.bad.append("/" + tag)


def valid(text: str) -> bool:
    c = Checker()
    c.feed(text)
    c.close()
    return not c.bad and not c.stack


def info(name="a.exe"):
    return FileInfo(name, Path("x"), 2048, "ab" * 32, "application/x-dosexec", "exe")


def test_report_is_valid_html_and_escapes_name():
    a = assess([Finding("EXEC_FILE", 60, "x <script> & y")])
    text = format_report(info("<b>evil</b>&.exe"), a.total, a.verdict, a.findings, a.story)
    assert valid(text)
    assert "<b>evil</b>" not in text and "&lt;b&gt;evil" in text
    assert "&lt;script&gt;" in text


def test_report_has_characteristics_hash_and_tech_block():
    a = assess([Finding("EXEC_FILE", 60, "Це виконуваний файл")])
    text = format_report(info(), a.total, a.verdict, a.findings, a.story)
    assert "ab" * 32 in text and "<blockquote expandable>" in text and "EXEC_FILE" in text
    assert "2.0 КБ" in text


def test_long_report_stays_valid_and_within_limit():
    a = assess([Finding("EXEC_FILE", 60, "довгий <текст> & " * 40) for _ in range(80)])
    text = format_report(info("n" * 300), a.total, a.verdict, a.findings, a.story)
    assert valid(text) and len(text) <= 4100
    assert "Що робити:" in text and "Технічні деталі" in text


def test_links_report_has_no_clickable_urls():
    a = assess([Finding("LINK_BRAND", 60, "Імітує бренд http://paypa1-login.xyz/a")])
    for short in (False, True):
        text = format_links([("http://paypa1-login.xyz/a", a)], short=short)
        assert valid(text) and "http://" not in text and "hxxp" in text


def test_short_report_valid_and_no_ping():
    a = assess([Finding("EXEC_FILE", 60, "Це виконуваний файл")])
    text = format_short("@all<1>.exe", a)
    assert valid(text) and "@all" not in text.replace("@\u200ball", "")


def test_strip_tags_fallback():
    assert strip_tags("<b>a &lt;b&gt;</b>") == "a <b>"
