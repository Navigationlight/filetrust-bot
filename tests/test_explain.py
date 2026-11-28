from pathlib import Path

from filetrust.models import FileInfo, Finding
from filetrust.report import format_report
from filetrust.scoring.engine import score
from filetrust.scoring.explain import (
    CHAIN, CODE, CONT, MASK, PHISH, assess, category_of)


def test_categories_known_and_archive_prefix():
    assert category_of("DOUBLE_EXT") == MASK
    assert category_of("PDF_LAUNCH") == CODE
    assert category_of("HTML_PASSWORD_FORM") == PHISH
    assert category_of("ARCHIVE_ENCRYPTED") == CONT
    assert category_of("ARCHIVE_DOUBLE_EXT") == MASK
    assert category_of("CHAIN_X") == CHAIN


def test_no_chain_for_single_category():
    f = [Finding("OFFICE_MACRO", 40, ""), Finding("OFFICE_MACRO_AUTOEXEC", 15, "")]
    a = assess(f)
    assert a.total == score(f)[0]
    assert not any(x.id.startswith("CHAIN_") for x in a.findings)


def test_chain_mask_plus_code_adds_bonus():
    f = [Finding("TYPE_MISMATCH", 20, ""), Finding("HTML_SMUGGLING", 10, "")]
    a = assess(f)
    assert a.total == score(f)[0] + 15
    assert any(x.id == "CHAIN_MASK_CODE" for x in a.findings)
    assert "маскується" in a.story and "код" in a.story


def test_chain_encrypted_archive_with_exec():
    f = [Finding("ARCHIVE_ENCRYPTED", 40, ""), Finding("ARCHIVE_EXEC", 5, "")]
    assert any(x.id == "CHAIN_LOCKED_PAYLOAD" for x in assess(f).findings)


def test_total_capped_and_empty_ok():
    assert assess([Finding("A", 90, ""), Finding("DOUBLE_EXT", 90, ""),
                   Finding("EXEC_FILE", 90, "")]).total == 100
    a = assess([])
    assert a.total == 0 and a.story == "" and a.findings == []


def test_report_groups_by_category():
    info = FileInfo("a.pdf.exe", Path("x"), 1, "a" * 64, "application/x-dosexec", "exe")
    a = assess([Finding("DOUBLE_EXT", 60, "Подвійне розширення"),
                Finding("EXEC_FILE", 60, "Це виконуваний файл")])
    text = format_report(info, a.total, a.verdict, a.findings, a.story)
    assert "Маскування" in text and "Виконання коду" in text and "Комбінація" in text
    assert "Висновок." in text and "Що робити." in text
