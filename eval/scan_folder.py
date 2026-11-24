
import argparse
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "src"))
sys.stdout.reconfigure(encoding="utf-8")

from filetrust.pipeline import analyze        # noqa: E402
from filetrust.scoring.explain import assess  # noqa: E402

THRESHOLD = 30


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("folder")
    ap.add_argument("--bad", action="store_true", help="у папці файли, які мають бути позначені")
    ap.add_argument("--max-mb", type=int, default=20)
    args = ap.parse_args()

    files = [p for p in Path(args.folder).rglob("*") if p.is_file()
             and p.stat().st_size <= args.max_mb * 1024 * 1024]
    wrong, slow, errors = [], [], []
    for p in files:
        t = time.perf_counter()
        try:
            _, findings = analyze(p, p.name)
        except Exception as exc:
            errors.append((p, type(exc).__name__))
            continue
        dt = time.perf_counter() - t
        a = assess(findings)
        flagged = a.total >= THRESHOLD
        if flagged != args.bad:
            wrong.append((p, a.total, [f.id for f in a.findings]))
        if dt > 2:
            slow.append((p, round(dt, 1)))

    n = len(files)
    label = "пропущено шкідливих" if args.bad else "хибних спрацювань"
    print(f"Файлів: {n}. {label}: {len(wrong)} ({len(wrong) / n:.0%})" if n else "Файлів немає")
    for p, total, ids in wrong:
        print(f"  {p}  {total}  {', '.join(ids)}")
    if slow:
        print("Повільні (понад 2 с):", *slow)
    if errors:
        print("Помилки:", *errors)


if __name__ == "__main__":
    main()
