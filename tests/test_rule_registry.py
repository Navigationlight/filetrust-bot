
import re
from pathlib import Path

from filetrust.scoring.explain import _CATEGORY

SRC = Path(__file__).resolve().parents[1] / "src" / "filetrust"


def test_every_emitted_rule_has_a_category():
    ids = set()
    for f in (SRC / "analyzers").glob("*.py"):
        ids |= set(re.findall(r'Finding\(\s*f?"([A-Z][A-Z0-9_]+)"', f.read_text(encoding="utf-8")))
    ids -= {"ARCHIVE_UNREADABLE"}
    missing = sorted(i for i in ids if i not in _CATEGORY and not i.startswith(("ARCHIVE_", "CHAIN_")))
    assert not missing, f"правила без категорії: {missing}"
