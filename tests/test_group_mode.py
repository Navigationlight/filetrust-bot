import asyncio
from types import SimpleNamespace

import pytest

from filetrust import handlers
from filetrust.isolated import analyze_isolated
from filetrust.models import FileInfo, Finding
from filetrust.report import format_links, format_report, format_short, limit
from filetrust.scoring.explain import assess
from filetrust.store import SettingsStore


class FakeMsg:
    def __init__(self, chat_type="supergroup", chat_id=-100, user_id=1, text=None):
        self.chat = SimpleNamespace(id=chat_id, type=chat_type)
        self.from_user = SimpleNamespace(id=user_id, is_bot=False)
        self.text, self.entities, self.sent = text, None, []
        self.reply_to_message = None

    async def reply(self, text, **kw):
        self.sent.append((text, kw))


def info(name="x.pdf.exe"):
    return FileInfo(name=name, path=None, size=1, sha256="a" * 64, mime="text/plain", kind="text")


def fake_scan(findings, name="x.pdf.exe"):
    async def scan(bot, doc):
        return info(name), assess(findings)
    return scan


@pytest.fixture(autouse=True)
def fresh(monkeypatch):
    monkeypatch.setattr(handlers, "_store", SettingsStore(":memory:"))
    handlers._cooldown.clear()


def run(coro):
    return asyncio.run(coro)


def test_group_quiet_green_file_is_silent(monkeypatch):
    monkeypatch.setattr(handlers, "scan_document", fake_scan([]))
    m = FakeMsg()
    run(handlers.handle_document(None, m, SimpleNamespace()))
    assert m.sent == []


def test_group_risky_file_gets_short_silent_reply(monkeypatch):
    monkeypatch.setattr(handlers, "scan_document", fake_scan([Finding("EXEC_FILE", 60, "Це виконуваний файл")]))
    m = FakeMsg()
    run(handlers.handle_document(None, m, SimpleNamespace()))
    text, kw = m.sent[0]
    assert "ВИСОКИЙ" in text and kw["disable_notification"] is True


def test_private_chat_always_full_report(monkeypatch):
    monkeypatch.setattr(handlers, "scan_document", fake_scan([]))
    m = FakeMsg(chat_type="private", chat_id=5)
    run(handlers.handle_document(None, m, SimpleNamespace()))
    assert "НИЗЬКИЙ" in m.sent[0][0]


def test_group_files_off_is_silent(monkeypatch):
    monkeypatch.setattr(handlers, "scan_document", fake_scan([Finding("EXEC_FILE", 60, "x")]))
    handlers.store().toggle(-100, "files")
    m = FakeMsg()
    run(handlers.handle_document(None, m, SimpleNamespace()))
    assert m.sent == []


def test_group_cooldown_is_silent(monkeypatch):
    monkeypatch.setattr(handlers, "scan_document", fake_scan([Finding("EXEC_FILE", 60, "x")]))
    m = FakeMsg()
    run(handlers.handle_document(None, m, SimpleNamespace()))
    run(handlers.handle_document(None, m, SimpleNamespace()))
    assert len(m.sent) == 1


def test_manual_check_overrides_quiet_and_off(monkeypatch):
    monkeypatch.setattr(handlers, "scan_document", fake_scan([]))
    handlers.store().toggle(-100, "files")
    m = FakeMsg()
    run(handlers.handle_document(None, m, SimpleNamespace(), force=True))
    assert len(m.sent) == 1


def test_links_in_group(monkeypatch):
    bad, ok = FakeMsg(), FakeMsg(user_id=2)
    run(handlers.handle_text(bad, "дивись http://paypal-login.xyz/a", None))
    run(handlers.handle_text(ok, "ось https://github.com/x", None))
    assert len(bad.sent) == 1 and "hxxp" in bad.sent[0][0] and ok.sent == []


def test_links_off_in_group():
    handlers.store().toggle(-100, "links")
    m = FakeMsg()
    run(handlers.handle_text(m, "http://paypal-login.xyz/a", None))
    assert m.sent == []


def test_no_mentions_in_group_reports():
    a = assess([Finding("EXEC_FILE", 60, "Це виконуваний файл")])
    text = format_short("@everyone.exe", a)
    assert "@everyone" not in text


def test_reports_fit_telegram_limit():
    findings = [Finding("EXEC_FILE", 60, "довгий текст " * 40) for _ in range(60)]
    a = assess(findings)
    assert len(format_report(info("n" * 200), a.total, a.verdict, a.findings, a.story)) <= 4000
    assert len(limit("x" * 10_000)) <= 4000


def test_settings_toggle_persists():
    s = SettingsStore(":memory:")
    assert s.get(1).quiet is True
    assert s.toggle(1, "quiet").quiet is False
    assert s.get(1).quiet is False and s.get(2).quiet is True
    with pytest.raises(ValueError):
        s.toggle(1, "x; DROP TABLE")


# ---------- ізоляція процесу ----------
def test_isolated_matches_inline(tmp_path):
    from filetrust.pipeline import analyze
    p = tmp_path / "s.bin"
    p.write_bytes(b"MZ" + b"\x90\x00" * 100)
    i1, f1 = run(analyze_isolated(p, "a.pdf.exe"))
    i2, f2 = analyze(p, "a.pdf.exe")
    assert i1.sha256 == i2.sha256 and {f.id for f in f1} == {f.id for f in f2}


def test_isolated_timeout_kills_process(tmp_path):
    p = tmp_path / "s.bin"
    p.write_bytes(b"hello")
    with pytest.raises(asyncio.TimeoutError):
        run(analyze_isolated(p, "a.txt", timeout=0.01))
