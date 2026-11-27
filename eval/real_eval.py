
import argparse
import sys
import time
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
from filetrust.pipeline import analyze        # noqa: E402
from filetrust.scoring.engine import score    # noqa: E402

THRESHOLDS = (20, 30, 40, 60)


def scan(folder, max_mb):
    rows = []
    for p in sorted(Path(folder).rglob("*")):
        if not p.is_file() or p.stat().st_size > max_mb * 1024 * 1024:
            continue
        t = time.perf_counter()
        try:
            _, fs = analyze(p, p.name)
        except Exception as e:
            rows.append((p, None, [f"CRASH:{type(e).__name__}"], 0))
            continue
        rows.append((p, score(fs)[0], [f.id for f in fs], time.perf_counter() - t))
    return rows


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("clean_pos", nargs="?")
    ap.add_argument("bad_pos", nargs="?")
    ap.add_argument("--clean"); ap.add_argument("--bad")
    ap.add_argument("--max-mb", type=int, default=20)
    ap.add_argument("--errors", type=int, default=15)
    a = ap.parse_args()
    clean_dir, bad_dir = a.clean or a.clean_pos, a.bad or a.bad_pos
    clean = scan(clean_dir, a.max_mb) if clean_dir else []
    bad = scan(bad_dir, a.max_mb) if bad_dir else []
    crashes = [r for r in clean + bad if r[1] is None]
    clean = [r for r in clean if r[1] is not None]
    bad = [r for r in bad if r[1] is not None]

    print(f"clean={len(clean)}  bad={len(bad)}  падінь={len(crashes)}")
    print(f"{'поріг':>5} {'TP':>4} {'FP':>4} {'FN':>4} {'TN':>4} {'точність':>9} {'повнота':>8}")
    for th in THRESHOLDS:
        tp = sum(r[1] >= th for r in bad); fn = len(bad) - tp
        fp = sum(r[1] >= th for r in clean); tn = len(clean) - fp
        prec = tp / (tp + fp) if tp + fp else float("nan")
        rec = tp / len(bad) if bad else float("nan")
        print(f"{th:>5} {tp:>4} {fp:>4} {fn:>4} {tn:>4} {prec:>9.1%} {rec:>8.1%}")
    th = 30
    print(f"\nХибні спрацювання (>= {th}):")
    for p, s, ids, _ in [r for r in clean if r[1] >= th][:a.errors]:
        print(f"  {s:>3} {p.name}  {','.join(ids)}")
    print(f"Пропущені (< {th}):")
    for p, s, ids, _ in [r for r in bad if r[1] < th][:a.errors]:
        print(f"  {s:>3} {p.name}  {','.join(ids) or '-'}")
    for title, rows in (("clean", clean), ("bad", bad)):
        c = Counter(i for r in rows for i in set(r[2]))
        print(f"Правила на {title}: {dict(c.most_common(12))}")
    slow = [(p.name, round(t, 1)) for p, _, _, t in clean + bad if t > 2]
    if slow: print("Повільні (>2 c):", slow)
    for p, _, ids, _ in crashes: print("ПАДІННЯ:", p, ids)


if __name__ == "__main__":
    main()
