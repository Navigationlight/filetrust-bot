
import html
import re

from filetrust.models import FileInfo, Finding
from filetrust.scoring.explain import ORDER, category_of
from filetrust.scoring.mitre import technique, techniques

URL_RE = re.compile(r"https?://[^\s)»]+")

ADVICE = {
    "ВИСОКИЙ": "Що робити. Не відкривайте файл, видаліть його, запитайте відправника іншим каналом.",
    "ПІДОЗРІЛО": "Що робити. Відкривайте лише якщо впевнені у відправнику, бажано у пісочниці.",
    "НИЗЬКИЙ": "Що робити. Явних ознак загрози немає, але обережність не зайва.",
}
ICONS = {"Маскування": "🎭", "Виконання коду": "⚙️", "Фішинг": "🎣",
         "Контейнер": "📦", "Інше": "▫️", "Комбінація": "🔗"}

TG_LIMIT = 4000       # ліміт Telegram 4096 символів, лишаємо запас
TECH_LINES = 20       # скільки рядків показуємо у блоці для технарів


def esc(text: str) -> str:
    return html.escape(str(text), quote=False)


def limit(text: str, size: int = TG_LIMIT) -> str:
  
    return text if len(text) <= size else text[:size - 1] + "…"


def fit(blocks: list[str], size: int = TG_LIMIT) -> str:
    
    out, used = [], 0
    for i, b in enumerate(blocks):
        if used + len(b) + 1 > size and i > 0:
            break
        out.append(b)
        used += len(b) + 1
    return "\n".join(out)


def strip_tags(text: str) -> str:
   
    return html.unescape(re.sub(r"<[^>]+>", "", text))


def no_ping(text: str) -> str:
   
    return text.replace("@", "@\u200b")


def defang(text: str) -> str:
   
    def fix(m):
        return m.group(0).replace("http", "hxxp", 1).replace(".", "[.]")
    return URL_RE.sub(fix, text)


def human_size(n: int) -> str:
    for unit in ("Б", "КБ", "МБ", "ГБ"):
        if n < 1024 or unit == "ГБ":
            return f"{n} Б" if unit == "Б" else f"{n:.1f} {unit}"
        n /= 1024
    return f"{n} Б"


def bar(total: int, width: int = 10) -> str:
    filled = round(width * max(0, min(100, total)) / 100)
    return "▰" * filled + "▱" * (width - filled)


def _advice(verdict: str) -> str:
    for key, text in ADVICE.items():
        if key in verdict:
            return text
    return ""


def plain(text: str) -> str:
    """Людський текст без двокрапок і тире: у чаті так читається легше."""
    t = re.sub(r"\s*[:]\s+", ", ", str(text))
    t = re.sub(r"\s+[\u2014\u2013-]\s+", ", ", t)
    return t.replace("\u2014", ",").rstrip(":")


def _vt_line(vt: dict | None) -> str:
    if not vt:
        return ""
    if vt.get("unknown"):
        return "VirusTotal  у базі немає"
    mark = "🔴" if vt["bad"] >= 5 else "🟡" if vt["bad"] else "✅"
    return f"VirusTotal  {vt['bad']} із {vt['total']} движків {mark}"


COMPRESSED = {"zip", "ooxml", "7z", "rar", "gz", "image", "pdf"}


def entropy_label(kind: str, e: float) -> tuple[str, str]:
    
    if kind in COMPRESSED:
        return "✅", "висока, формат стиснутий" if e >= 7.0 else "звичайна"
    if kind in ("exe", "elf"):
        if e >= 7.2:
            return "🔥", "висока, ймовірно упаковано"
        return ("⚠️", "підвищена") if e >= 6.6 else ("✅", "звичайна")
    if kind in ("text", "html"):
        if e >= 6.0:
            return "🔥", "висока для тексту, можлива обфускація"
        return ("⚠️", "підвищена") if e >= 5.2 else ("✅", "звичайна")
    return ("⚠️", "схоже на шифрування") if e >= 7.5 else ("✅", "звичайна")


def sev(points: int) -> str:
    return "🔴" if points >= 50 else "🟠" if points >= 25 else "🟡"


def _row(label: str, value: str) -> str:
    return f"{label:<12}" + (" " if len(label) >= 12 else "") + value


def _card_rows(info: FileInfo) -> list[str]:
    m = info.meta or {}
    mime = info.mime if len(info.mime) <= 34 else info.mime.rsplit(".", 1)[-1]
    rows = [_row("Тип", f"{info.kind} ({mime})"),
            _row("Розмір", human_size(info.size))]
    ext = m.get("ext_chain")
    if ext:
        from filetrust.analyzers.common import EXPECTED_KIND
        last = "." + ext.rsplit(".", 1)[-1]
        want = EXPECTED_KIND.get(last)
        bad = ext.count(".") >= 2 or (want and want != info.kind and not (want == "ooxml" and info.kind == "zip"))
        rows.append(_row("Розширення", ext + ("  ⚠️ не збігається з вмістом" if bad and want else "  ⚠️ подвійне" if ext.count(".") >= 2 else "")))
    if "entropy" in m:
        icon, word = entropy_label(info.kind, m["entropy"])
        rows.append(_row("Ентропія", f"{m['entropy']}/8  {icon} {word}"))
    return rows


def _detail_rows(info: FileInfo) -> list[str]:
    """Структура файлу залежно від виду. Підказки: ⚠️ варто звернути увагу, 🔴 небезпечно."""
    m, k = info.meta or {}, info.kind
    r: list[str] = []
    if k == "exe" and "arch" in m:
        r.append(_row("Архітектура", m["arch"]))
        if m.get("compiled"):
            r.append(_row("Компіляція", m["compiled"] + ("  ⚠️ дата схожа на підроблену" if m.get("compiled_fake") else "")))
        top = max(m.get("sec_ent") or [], key=lambda x: x[1], default=None)
        r.append(_row("Секцій", f"{m.get('sections', 0)}" + (f", макс. ентропія {top[0]} {top[1]}" if top else "")))
        r.append(_row("Підпис", "є ✅" if m.get("signed") else "немає ⚠️"))
        if "imports" in m:
            r.append(_row("Імпортів", str(m["imports"])))
        if m.get("overlay", 0) > 4096:
            r.append(_row("Дописано", f"{human_size(m['overlay'])} після програми ⚠️"))
    elif k in ("zip", "ooxml") and "entries" in m:
        r.append(_row("Файлів", f"{m['entries']}, розпаковано {human_size(m.get('unpacked', 0))}"))
        if m.get("execs"):
            r.append(_row("Виконуваних", f"{m['execs']} ⚠️"))
        if m.get("encrypted"):
            r.append(_row("Під паролем", f"{m['encrypted']} ⚠️"))
        if k == "ooxml":
            r.append(_row("Макроси", "є 🔴" if m.get("macro") else "немає ✅"))
            if m.get("embedded") or m.get("activex"):
                r.append(_row("Вкладено", f"об'єктів {m.get('embedded', 0)}, ActiveX {'є' if m.get('activex') else 'ні'} ⚠️"))
            if m.get("external_rels"):
                r.append(_row("Зовнішні зв'язки", f"{m['external_rels']} ⚠️"))
            who = m.get("author")
            if who or m.get("modified_by"):
                r.append(_row("Автор", f"{who or '-'}, змінив {m.get('modified_by', '-')}"))
            if m.get("created"):
                r.append(_row("Створено", m["created"][:10] + (f", змінено {m['modified'][:10]}" if m.get("modified") else "")))
            if m.get("app"):
                r.append(_row("Програма", m["app"]))
    elif k == "pdf" and "pages" in m:
        r.append(_row("Сторінок", f"{m['pages']}, об'єктів {m.get('objects', 0)}, версія {m.get('version', '?')}"))
        r.append(_row("Посилань", str(m.get("pdf_links", 0))))
        if "tail" in m:
            r.append(_row("Після %%EOF", "нічого ✅" if not m["tail"] else f"{human_size(m['tail'])} ⚠️"))
        if m.get("pdf_encrypted"):
            r.append(_row("Шифрування", "є ⚠️"))
    elif k == "html":
        r.append(_row("Скриптів", str(m.get("scripts", 0))))
        r.append(_row("iframe / форм", f"{m.get('iframes', 0)} / {m.get('forms', 0)}"))
        r.append(_row("Адрес", str(m.get("urls", 0))))
    elif k == "image":
        if m.get("width"):
            r.append(_row("Розмір", f"{m['width']}×{m['height']} px"))
        if "tail" in m:
            r.append(_row("Після кінця", "нічого ✅" if not m["tail"] else f"{human_size(m['tail'])} даних ⚠️"))
    return r


def _tech_extras(info: FileInfo) -> list[str]:
    m = info.meta or {}
    rows = []
    for key, label in (("md5", "MD5"), ("sha1", "SHA1")):
        if m.get(key):
            rows.append(f"{label:<7}{m[key]}")
    if "ent_max" in m:
        rows.append(f"Ентропія блоків 4 КБ: макс. {m['ent_max']}, блоків ≥7.5: {m.get('hot_pct', 0)}%")
    if "printable" in m:
        rows.append(f"Друковані символи {m['printable']}%, нулі {m.get('nulls', 0)}%")
    if m.get("magic"):
        rows.append(f"Сигнатура {m['magic']}")
    if m.get("sec_ent"):
        rows.append("Секції  " + "  ".join(f"{n}:{e}" for n, e in m["sec_ent"]))
    if m.get("sampled_mb"):
        rows.append(f"Файл великий, ентропію пораховано за перші {m['sampled_mb']} МБ")
    return rows


def format_report(info: FileInfo, total: int, verdict: str,
                  findings: list[Finding], story: str = "", vt: dict | None = None) -> str:
    """Особистий чат. Вердикт, картка файлу, структура, індикатори, техніка у блоці, що розгортається."""
    sha = info.sha256
    card = _card_rows(info)
    if vt_line := _vt_line(vt):
        card.append(vt_line)
    card.append(_row("Індикаторів", str(len(findings))))
    head = [
        f"<b>{esc(verdict)}</b>",
        f"<code>{bar(total)} {total}/100</code>",
        "",
        f"📄 <b>{esc(info.name)}</b>",
        "<pre>" + esc("\n".join(card)) + "</pre>",
    ]
    detail = _detail_rows(info)
    if detail:
        head += ["🧬 <b>Структура</b>", "<pre>" + esc("\n".join(detail)) + "</pre>"]
    head += [
        f"🔑 <b>SHA256</b>\n<code>{sha}</code>",
        f'🔎 <a href="https://www.virustotal.com/gui/file/{sha}">Знайти за хешем у VirusTotal</a>',
    ]
    blocks = ["\n".join(head)]
    if story:
        blocks.append(f"<blockquote>{esc(plain(story))}</blockquote>")

    if findings:
        top = sorted(findings, key=lambda f: -f.points)[:3]
        blocks.append("🎯 <b>Головне</b>\n" + "\n".join(
            f"{sev(f.points)} {esc(defang(plain(f.text)))}" for f in top))
        lines = ["📋 <b>Індикатори</b>"]
        for cat in ORDER:
            group = [f for f in findings if category_of(f.id) == cat]
            if group:
                chips = "  ".join(f"{f.id} +{f.points}" for f in group[:6])
                more = f"  ще {len(group) - 6}" if len(group) > 6 else ""
                lines.append(f"{ICONS.get(cat, '▫️')} {esc(cat)}\n<code>{esc(chips)}{more}</code>")
        blocks.append("\n".join(lines))
    else:
        blocks.append("✅ Підозрілих ознак не знайдено.\n"
                      "<i>Це не гарантія безпеки, а результат наших перевірок.</i>")
    blocks.append(_tech_block(findings, total, vt, info))

    advice = _advice(verdict)
    if advice:
        blocks.append(f"<blockquote>{esc(plain(advice))}</blockquote>")
    return fit_keep_tail(blocks)


def _tech_block(findings: list[Finding], total: int, vt: dict | None = None,
                info: FileInfo | None = None) -> str:
    """Для технарів. Хеші, ентропія, правила, бали, ATT&CK, у блоці, що розгортається."""
    rows = _tech_extras(info) if info else []
    if rows:
        rows.append("")
    for f in sorted(findings, key=lambda x: -x.points)[:TECH_LINES]:
        t = technique(f.id)
        rows.append(f"{f.id:<26} +{f.points:<3} {t[0] if t else ''}")
    if len(findings) > TECH_LINES:
        rows.append(f"ще {len(findings) - TECH_LINES}")
    if findings:
        raw = sum(f.points for f in findings)
        rows.append(f"Сума {raw}, стеля 100, підсумок {total}")
    tt = techniques(findings)
    if tt:
        rows.append("")
        rows.append("MITRE ATT&CK")
        rows += [f"{tid}  {name}" for tid, name in tt]
    if vt and not vt.get("unknown"):
        rows += ["", f"VirusTotal шкідливих {vt['malicious']}, підозрілих {vt['suspicious']}, всього {vt['total']}"]
    return "🔬 <b>Технічні деталі</b>\n<blockquote expandable>" + esc("\n".join(rows)) + "</blockquote>"


def fit_keep_tail(blocks: list[str], size: int = TG_LIMIT) -> str:
    """Як fit, але останні 2 блоки (техдеталі й порада) мають пріоритет над серединою."""
    if sum(len(b) + 1 for b in blocks) <= size:
        return "\n".join(blocks)
    tail, body = blocks[-2:], blocks[:-2]
    note = "<i>… частину знахідок приховано, дивіться технічні деталі</i>"
    room = size - sum(len(b) + 1 for b in tail) - len(note) - 2
    return "\n".join([fit(body, room), note] + tail)


def show_url(url: str, size: int = 70) -> str:
    """Посилання у безпечному вигляді: hxxp і [.]"""
    u = url.replace("http", "hxxp", 1) if url.lower().startswith("http") else url
    u = no_ping(u.replace(".", "[.]"))
    return u if len(u) <= size else u[:size - 1] + "…"


def format_short(name: str, a) -> str:
    """Короткий звіт для груп: вердикт, до 3 головних знахідок, порада."""
    top = sorted(a.findings, key=lambda f: -f.points)[:3]
    lines = [f"<b>{esc(a.verdict)}</b> · <code>{a.total}/100</code>",
             f"📄 {esc(no_ping(name))}"]
    lines += [f"• {esc(defang(no_ping(f.text)))}" for f in top]
    blocks = ["\n".join(lines)]
    advice = _advice(a.verdict)
    if advice:
        blocks.append(f"<blockquote>{esc(advice)}</blockquote>")
    return fit(blocks)


def url_rows(url: str) -> list[str]:
    """Параметри адреси для картки посилання. Домени у вигляді [.], щоб Telegram не робив їх клікабельними."""
    from ipaddress import ip_address
    from urllib.parse import parse_qsl, urlsplit
    try:
        from filetrust import intel
        from filetrust.analyzers.urlcheck import registered_domain
        u = urlsplit(url if "://" in url else "//" + url)
        host = (u.hostname or "").lower()
        if not host:
            return []
        db = intel.get()
        rows = [_row("Схема", "https 🔒" if u.scheme == "https" else f"{u.scheme or 'немає'} 🔓 ⚠️")]
        try:
            ip_address(host)
            return rows + [_row("Хост", "IP-адреса замість домену ⚠️")]
        except ValueError:
            pass
        reg = registered_domain(host)
        rank = db.rank.get(reg)
        top = f"  у топі Tranco #{rank} ✅" if rank else ("  немає в топі Tranco" if db.rank else "")
        rows.append(_row("Домен", reg.replace(".", "[.]") + top))
        subs = max(0, len(host.split(".")) - len(reg.split(".")))
        rows.append(_row("Піддоменів", f"{subs}" + (" ⚠️" if subs >= 3 else "")))
        tld = host.rsplit(".", 1)[-1]
        rows.append(_row("Зона", f".{tld}" + ("  ⚠️ часта у шахраїв" if tld in intel.RISKY else "")))
        if "xn--" in host:
            try:
                rows.append(_row("Punycode", host.encode("ascii").decode("idna").replace(".", "[.]") + " ⚠️"))
            except UnicodeError:
                rows.append(_row("Punycode", "є ⚠️"))
        elif not host.isascii():
            rows.append(_row("Юнікод", "в домені ⚠️"))
        rows.append(_row("Довжина", f"{len(url)}" + (" ⚠️" if len(url) > 120 else "")))
        q = len(parse_qsl(u.query))
        if q:
            rows.append(_row("Параметрів", str(q)))
        if u.port and u.port not in (80, 443):
            rows.append(_row("Порт", f"{u.port} ⚠️"))
        if db.phish_domains or db.phish_urls:
            rows.append(_row("База фішингу", "є 🔴" if db.phish(host, url) else "немає ✅"))
        return rows
    except Exception:                       # картка другорядна: збій не повинен ламати відповідь
        return []


def format_links(results: list, short: bool = False) -> str:
    """results: список (адреса, Assessment). У короткому режимі лише ризикові."""
    blocks = [] if short else [f"🔗 <b>Перевірка посилань: {len(results)}</b>"]
    shown = 0
    for n, (url, a) in enumerate(results, 1):
        if short and a.total < 30:
            continue
        shown += 1
        top = sorted(a.findings, key=lambda f: -f.points)[: 2 if short else 5]
        lines = [f"<b>{n}.</b> <code>{esc(show_url(url))}</code>",
                 f"<b>{esc(a.verdict)}</b> · <code>{bar(a.total)} {a.total}/100</code>"]
        if not short and (rows := url_rows(url)):
            lines.append("<pre>" + esc("\n".join(rows)) + "</pre>")
        lines += [f"{sev(f.points)} {esc(defang(plain(f.text)))}" for f in top]
        if not top:
            lines.append("Явних ознак підміни в адресі немає.")
        blocks.append("\n".join(lines))
    if short and not shown:
        return ""
    blocks.append("<blockquote>Не переходьте за такими посиланнями.</blockquote>" if short else
                  "<i>Сторінка не відкривалась, перевірено лише адресу. Це не гарантія безпеки.</i>")
    return fit_keep_last(blocks)


def fit_keep_last(blocks: list[str], size: int = TG_LIMIT) -> str:
    """Обрізає середину списку посилань, але лишає підсумковий рядок."""
    if sum(len(b) + 1 for b in blocks) <= size:
        return "\n".join(blocks)
    last = blocks[-1]
    kept = fit(blocks[:-1], size - len(last) - 40)
    return "\n".join([kept, "<i>… решту посилань приховано</i>", last])
