import random
import sys
import tempfile
import time
from collections import defaultdict
from pathlib import Path, PurePath

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "src"))
sys.path.insert(0, str(HERE))
sys.stdout.reconfigure(encoding="utf-8")

from filetrust.pipeline import analyze       
from filetrust.scoring.engine import score    
import samples                               

THRESHOLD = 30     
MIN_RECALL = 0.90   
MAX_FPR = 0.10

NAIVE_EXEC_EXT = {".exe", ".scr", ".bat", ".cmd", ".js", ".vbs", ".hta",
                  ".ps1", ".lnk", ".msi", ".jar", ".com"}
REAL_EXEC_KINDS = {"exe", "elf", "lnk"}


def run_all(items, tmp: Path):
    res = []
    for i, s in enumerate(items):
        p = tmp / f"s{i}.bin"
        p.write_bytes(s.data)
        t0 = time.perf_counter()
        info, findings = analyze(p, s.name)
        ms = (time.perf_counter() - t0) * 1000
        total, verdict = score(findings)
        res.append({
            "s": s, "kind": info.kind, "total": total, "ms": ms,
            "ids": [f.id for f in findings],
            "tool": total >= THRESHOLD,
            "ext": PurePath(s.name).suffix.lower() in NAIVE_EXEC_EXT,
            "magic": info.kind in REAL_EXEC_KINDS,
        })
    return res


def confusion(rows, key):
    tp = sum(1 for r in rows if r["s"].bad and r[key])
    fn = sum(1 for r in rows if r["s"].bad and not r[key])
    fp = sum(1 for r in rows if not r["s"].bad and r[key])
    tn = sum(1 for r in rows if not r["s"].bad and not r[key])
    return tp, fn, fp, tn


def rates(c):
    tp, fn, fp, tn = c
    rec = tp / (tp + fn) if tp + fn else 0.0
    fpr = fp / (fp + tn) if fp + tn else 0.0
    prec = tp / (tp + fp) if tp + fp else 0.0
    acc = (tp + tn) / sum(c) if sum(c) else 0.0
    return rec, fpr, prec, acc


def pct(x):
    return f"{x:.0%}"


def robustness(items, tmp: Path):
    rng = random.Random(99)
    runs = errors = 0
    times = []
    bad_cases = []
    for s in items[:: max(1, len(items) // 40)]:
        for tag, data in samples.mutate(s.data, rng):
            p = tmp / "mut.bin"
            p.write_bytes(data)
            runs += 1
            t0 = time.perf_counter()
            try:
                analyze(p, s.name)
            except Exception as e:   
                errors += 1
                bad_cases.append(f"{s.name} [{tag}]: {type(e).__name__}")
            times.append((time.perf_counter() - t0) * 1000)
    return runs, errors, times, bad_cases


def main():
    items = samples.build_samples()
    with tempfile.TemporaryDirectory() as t:
        tmp = Path(t)
        rows = run_all(items, tmp)
        runs, errors, rtimes, bad_cases = robustness(items, tmp)

    dev = [r for r in rows if r["s"].split == "dev"]
    held = [r for r in rows if r["s"].split == "heldout"]
    n_bad = sum(r["s"].bad for r in rows)
    out = ["# Результати оцінки filetrust", "",
           f"Зразків: {len(rows)} (шкідливих {n_bad}, чистих {len(rows) - n_bad}, "
           f"з них складних чистих {sum(r['s'].hard for r in rows)}). "
           f"dev: {len(dev)}, held-out: {len(held)}. Поріг: {THRESHOLD} балів.", "",
           "## Підсумок", "",
           "| Метод | Набір | Повнота | Хибні спрацювання | Точність | Загальна |",
           "|---|---|---|---|---|---|"]
    for label, key in [("**filetrust**", "tool"), ("Лише розширення", "ext"),
                       ("Лише libmagic (тип exe/elf/lnk)", "magic")]:
        for sname, subset in [("dev", dev), ("held-out", held), ("усі", rows)]:
            rec, fpr, prec, acc = rates(confusion(subset, key))
            out.append(f"| {label} | {sname} | {pct(rec)} | {pct(fpr)} | {pct(prec)} | {pct(acc)} |")

    out += ["", "Повнота: частка шкідливих, які позначено. Хибні спрацювання: частка чистих, "
            "які позначено помилково.", "", "## Повнота за категоріями усі зразки", "",
            "| Категорія | Кількість | filetrust | Лише розширення | Лише libmagic |",
            "|---|---|---|---|---|"]
    bycat = defaultdict(list)
    for r in rows:
        if r["s"].bad:
            bycat[r["s"].category].append(r)
    for cat, lst in sorted(bycat.items()):
        cells = [pct(sum(r[k] for r in lst) / len(lst)) for k in ("tool", "ext", "magic")]
        out.append(f"| {cat} | {len(lst)} | " + " | ".join(cells) + " |")

    hard = [r for r in rows if r["s"].hard]
    out += ["", f"## Складні чисті файли ({len(hard)})", "",
            f"Помилково позначено: {sum(r['tool'] for r in hard)} з {len(hard)}.", ""]

    misses = [r for r in rows if r["tool"] != r["s"].bad]
    out += ["## Помилки filetrust", ""]
    if misses:
        out += ["| Зразок | Очікували | Бал | Знахідки |", "|---|---|---|---|"]
        for r in misses:
            out.append(f"| {r['s'].name.replace(chr(0x202e), '<RTLO>')} | "
                       f"{'шкідливий' if r['s'].bad else 'чистий'} | {r['total']} | "
                       f"{', '.join(r['ids']) or '—'} |")
    else:
        out.append("Помилок на цьому наборі немає .")

    ms = sorted(r["ms"] for r in rows)
    rms = sorted(rtimes)
    out += ["", "## Швидкість і стійкість", "",
            f"- Час аналізу на файл: медіана {ms[len(ms)//2]:.1f} мс, максимум {ms[-1]:.1f} мс.",
            f"- Зіпсовані файли (порожні, обрізані, з випадковими байтами): {runs} запусків, "
            f"винятків {errors}; максимум {rms[-1]:.1f} мс."]
    for c in bad_cases[:10]:
        out.append(f"  - виняток: {c}")
    out += ["", "## Обмеження", "",
            "- Набір синтетичний.",
            "- Зразки інертні (без робочого шкідливого коду), тому вимірюється розпізнавання ознак, "
            "а не антивірусна здатність.",
            "- Розподіл dev / held-out зафіксовано правилом заздалегідь, ваги правил підбираються лише за dev, "
            "held-out слугує для перевірки."]

    text = "\n".join(out) + "\n"
    print(text)
    (HERE / "results.md").write_text(text, encoding="utf-8")

    rec, fpr, _, _ = rates(confusion(held, "tool"))
    if rec < MIN_RECALL or fpr > MAX_FPR:
        print(f"ПОРОГИ НЕ ДОТРИМАНО: recall={rec:.0%} (мін {MIN_RECALL:.0%}), "
              f"FPR={fpr:.0%} (макс {MAX_FPR:.0%})")
        sys.exit(1)


if __name__ == "__main__":
    main()
