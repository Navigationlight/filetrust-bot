
import io
import os
import sys
import urllib.request
import zipfile
from pathlib import Path

DEST = Path(os.getenv("INTEL_DIR", "data/intel"))
BASE = "https://raw.githubusercontent.com/mitchellkrogza/Phishing.Database/master/"
FEEDS = {"phishing-domains-ACTIVE.txt": BASE + "phishing-domains-ACTIVE.txt",
         "phishing-links-ACTIVE.txt": BASE + "phishing-links-ACTIVE.txt"}
TRANCO = "https://tranco-list.eu/top-1m.csv.zip"


def fetch(url: str) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": "filetrust-intel-updater"})
    with urllib.request.urlopen(req, timeout=120) as r:
        return r.read()


def main() -> int:
    DEST.mkdir(parents=True, exist_ok=True)
    bad = 0
    for name, url in FEEDS.items():
        try:
            data = fetch(url)
            (DEST / (name + ".tmp")).write_bytes(data)
            (DEST / (name + ".tmp")).replace(DEST / name)      
            print("ok", name, len(data) // 1024, "КБ")
        except Exception as e:
            bad += 1
            print("помилка", name, e)
    try:
        z = zipfile.ZipFile(io.BytesIO(fetch(TRANCO)))
        data = z.read(z.namelist()[0])
        (DEST / "top-1m.csv.tmp").write_bytes(data)
        (DEST / "top-1m.csv.tmp").replace(DEST / "top-1m.csv")
        print("ok top-1m.csv", len(data) // 1024, "КБ")
    except Exception as e:
        bad += 1
        print("помилка Tranco", e)
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
