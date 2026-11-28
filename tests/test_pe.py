
import os
import struct
from pathlib import Path

from filetrust.pipeline import analyze


def build_pe(sections, imports=(), entry_section=0, signed=False, pad=0):
  
    sections = [list(s) for s in sections]
    nsec = len(sections) + (1 if imports else 0)
    hdr_size = 0x400
    # імпорти кладемо в окрему секцію .idata
    rva = 0x1000
    out_secs, blobs = [], []
    raw = hdr_size
    imp_va = None
    for name, data, flags in sections:
        out_secs.append((name, rva, raw, len(data), flags)); blobs.append(data)
        raw += (len(data) + 0x1FF) & ~0x1FF; rva += 0x1000
    if imports:
        base = rva
        hint = b"".join(b"\0\0" + n.encode() + b"\0" for n in imports)
        names_off = [0] * len(imports); pos = 0
        for i, n in enumerate(imports):
            names_off[i] = pos; pos += 2 + len(n) + 1
        dll = b"kernel32.dll\0"
        ilt_off = 40 + len(hint) + len(dll)
        ilt = b"".join(struct.pack("<Q", base + 40 + o) for o in names_off) + b"\0" * 8
        desc = struct.pack("<IIIII", base + ilt_off, 0, 0, base + 40 + len(hint), base + ilt_off) + b"\0" * 20
        blob = desc + hint + dll + ilt
        out_secs.append((".idata", base, raw, len(blob), 0x40000040)); blobs.append(blob)
        imp_va = base; raw += (len(blob) + 0x1FF) & ~0x1FF
    n = len(out_secs)
    dd = [(0, 0)] * 16
    if imp_va:
        dd[1] = (imp_va, 40)
    if signed:
        dd[4] = (raw, 64)
    opt = struct.pack("<HBBIIIIIQIIHHHHHHIIIIHHQQQQII", 0x20B, 14, 0, 0x1000, 0x1000, 0, out_secs[entry_section][1], 0x1000,
                      0x140000000, 0x1000, 0x200, 6, 0, 0, 0, 6, 0, 0, 0x4000, hdr_size, 0, 3, 0, 0x100000, 0x1000, 0x100000, 0x1000, 0, 16)
    opt += b"".join(struct.pack("<II", *d) for d in dd)
    coff = struct.pack("<HHIIIHH", 0x8664, n, 0, 0, 0, len(opt), 0x22)
    head = b"MZ" + b"\0" * 58 + struct.pack("<I", 0x80)
    head = head.ljust(0x80, b"\0") + b"PE\0\0" + coff + opt
    for name, va, off, size, flags in out_secs:
        head += struct.pack("<8sIIIIIIHHI", name.encode(), 0x1000, va, (size + 0x1FF) & ~0x1FF, off, 0, 0, 0, 0, flags)
    body = head.ljust(hdr_size, b"\0")
    for blob in blobs:
        body += blob.ljust((len(blob) + 0x1FF) & ~0x1FF, b"\0")
    if signed:
        body += b"\0" * 64
    return body + b"\0" * pad


def ids(tmp_path, data, name="a.exe"):
    p = tmp_path / name
    p.write_bytes(data)
    return {f.id for f in analyze(p, name)[1]}


CODE = 0x60000020


def test_plain_pe_has_no_structural_alarms(tmp_path):
    r = ids(tmp_path, build_pe([(".text", os.urandom(0) + bytes(range(64)) * 40, CODE)],
                               imports=["ExitProcess", "GetStdHandle", "WriteFile", "ReadFile"], signed=True))
    assert "EXEC_FILE" in r
    assert not r & {"PE_PACKED", "PE_WX_SECTION", "PE_EP_ANOMALY", "PE_MALFORMED", "PE_NO_SIGNATURE", "PE_FEW_IMPORTS"}


def test_packed_section_by_entropy(tmp_path):
    assert "PE_PACKED" in ids(tmp_path, build_pe([(".text", os.urandom(4096), CODE)], imports=["ExitProcess"] * 5))


def test_packed_section_by_name(tmp_path):
    assert "PE_PACKED" in ids(tmp_path, build_pe([("UPX0", b"\0" * 2048, CODE), ("UPX1", b"\1" * 2048, CODE)]))


def test_writable_executable_section(tmp_path):
    assert "PE_WX_SECTION" in ids(tmp_path, build_pe([(".text", bytes(range(64)) * 40, 0xE0000020)]))


def test_injection_imports(tmp_path):
    r = ids(tmp_path, build_pe([(".text", bytes(range(64)) * 40, CODE)],
                               imports=["VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread", "ExitProcess"]))
    assert "PE_INJECTION_APIS" in r


def test_downloader_imports(tmp_path):
    r = ids(tmp_path, build_pe([(".text", bytes(range(64)) * 40, CODE)], imports=["URLDownloadToFileA", "WinExec"]))
    assert "PE_DOWNLOADER_APIS" in r


def test_unsigned_flag_and_signed_difference(tmp_path):
    base = [(".text", bytes(range(64)) * 40, CODE)]
    assert "PE_NO_SIGNATURE" in ids(tmp_path, build_pe(base))
    assert "PE_NO_SIGNATURE" not in ids(tmp_path, build_pe(base, signed=True), "b.exe")


def test_truncated_pe_is_flagged_not_crashing(tmp_path):
    data = build_pe([(".text", bytes(range(64)) * 40, CODE)])[:0x90]
    assert "PE_MALFORMED" in ids(tmp_path, data)


def test_garbage_after_mz_does_not_crash(tmp_path):
    ids(tmp_path, b"MZ" + os.urandom(3000))


def test_real_pip_launchers_have_no_serious_pe_alarms(tmp_path):
    found = list(Path("/").glob("opt/pipx/shared/lib/python*/site-packages/pip/_vendor/distlib/*.exe")) \
        + list(Path(__file__).parent.glob("*.exe"))
    for f in found:
        got = {x.id for x in analyze(f, f.name)[1]}
        assert not got & {"PE_PACKED", "PE_INJECTION_APIS", "PE_MALFORMED", "PE_EP_ANOMALY"}, (f.name, got)
