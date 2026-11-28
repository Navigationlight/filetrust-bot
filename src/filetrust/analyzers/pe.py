
import math
import struct

from filetrust.models import FileInfo, Finding

MAX_READ = 20 * 1024 * 1024
MAX_SECTIONS = 96
MAX_IMPORT_DLLS = 256
MAX_IMPORT_FUNCS = 8000

PACKER_SECTIONS = {b"upx0", b"upx1", b"upx2", b".aspack", b".adata", b".themida", b".vmp0", b".vmp1",
                   b".petite", b"mpress1", b"mpress2", b".nsp0", b".nsp1", b".enigma1", b".boom"}
IGNORE_ENTROPY = {b".rsrc", b".reloc"}          # ресурси й так стиснуті

INJECTION = {"VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread", "NtUnmapViewOfSection",
             "SetThreadContext", "QueueUserAPC", "NtWriteVirtualMemory", "ResumeThread", "NtCreateThreadEx"}
DOWNLOAD = {"URLDownloadToFileA", "URLDownloadToFileW", "InternetReadFile", "InternetOpenUrlA",
            "InternetOpenUrlW", "WinHttpReadData"}
RUN = {"WinExec", "ShellExecuteA", "ShellExecuteW", "ShellExecuteExA", "ShellExecuteExW",
       "CreateProcessA", "CreateProcessW"}
HOOK = {"SetWindowsHookExA", "SetWindowsHookExW"}
KEYS = {"GetAsyncKeyState", "GetKeyState", "GetKeyboardState"}


def entropy(chunk: bytes) -> float:
    if not chunk:
        return 0.0
    counts = [0] * 256
    for b in chunk:
        counts[b] += 1
    n = len(chunk)
    return -sum(c / n * math.log2(c / n) for c in counts if c)


class _PE:
    def __init__(self, data: bytes):
        self.d = data
        e = struct.unpack_from("<I", data, 0x3C)[0]
        if data[e:e + 4] != b"PE\0\0":
            raise ValueError("no PE signature")
        (self.machine, self.nsec, self.stamp, _, _, self.optsize, self.chars) = struct.unpack_from("<HHIIIHH", data, e + 4)
        o = e + 24
        self.magic = struct.unpack_from("<H", data, o)[0]
        if self.magic not in (0x10B, 0x20B):
            raise ValueError("bad optional header")
        self.entry = struct.unpack_from("<I", data, o + 16)[0]
        dd_off = o + (96 if self.magic == 0x10B else 112)
        ndd = min(struct.unpack_from("<I", data, dd_off - 4)[0], 16)
        self.dd = [struct.unpack_from("<II", data, dd_off + 8 * i) for i in range(ndd)]
        so = o + self.optsize
        if self.nsec > MAX_SECTIONS:
            raise ValueError("too many sections")
        self.sections = []
        for i in range(self.nsec):
            name, vsize, va, rsize, roff, *_ , flags = struct.unpack_from("<8sIIIIIIHHI", data, so + 40 * i)
            self.sections.append((name.rstrip(b"\0").lower(), vsize, va, rsize, roff, flags))

    def rva_to_off(self, rva: int) -> int | None:
        for _, vsize, va, rsize, roff, _ in self.sections:
            if va <= rva < va + max(vsize, rsize):
                return roff + (rva - va)
        return None

    def cstr(self, off: int, limit: int = 256) -> str:
        end = self.d.find(b"\0", off, off + limit)
        return self.d[off:end if end != -1 else off + limit].decode("latin-1")

    def imports(self) -> list[str]:
        if len(self.dd) < 2 or not self.dd[1][0]:
            return []
        off = self.rva_to_off(self.dd[1][0])
        names: list[str] = []
        if off is None:
            return names
        step = 8 if self.magic == 0x20B else 4
        for i in range(MAX_IMPORT_DLLS):
            try:
                ilt, _, _, name_rva, iat = struct.unpack_from("<IIIII", self.d, off + 20 * i)
            except struct.error:
                break
            if not name_rva:
                break
            t = self.rva_to_off(ilt or iat)
            while t is not None and len(names) < MAX_IMPORT_FUNCS:
                try:
                    v = int.from_bytes(self.d[t:t + step], "little")
                except ValueError:
                    break
                if v == 0 or v >> (step * 8 - 1):         # кінець або імпорт за ординалом
                    if v == 0:
                        break
                    t += step
                    names.append("")
                    continue
                n = self.rva_to_off(v)
                if n is None:
                    break
                names.append(self.cstr(n + 2))
                t += step
        return names


def check_pe(info: FileInfo) -> list[Finding]:
    data = info.path.read_bytes()[:MAX_READ]
    try:
        pe = _PE(data)
    except (ValueError, struct.error):
        return [Finding("PE_MALFORMED", 15, "Заголовок виконуваного файлу пошкоджений або підроблений")]
    out: list[Finding] = []
    try:
        out += _structure(pe, data)
        out += _imports(pe, len(data))
    except (struct.error, IndexError, ValueError):
        out.append(Finding("PE_MALFORMED", 15, "Структура виконуваного файлу пошкоджена"))
    return out


def _structure(pe: _PE, data: bytes) -> list[Finding]:
    out: list[Finding] = []
    packed = [n for n, *_ in pe.sections if n in PACKER_SECTIONS]
    hot = []
    for n, vsize, va, rsize, roff, flags in pe.sections:
        if n in IGNORE_ENTROPY or rsize < 1024:
            continue
        if entropy(data[roff:roff + min(rsize, 1_000_000)]) >= 7.2:
            hot.append(n.decode("latin-1"))
    if packed or hot:
        what = ", ".join(n.decode("latin-1") for n in packed) or ", ".join(hot)
        out.append(Finding("PE_PACKED", 30, f"Код схожий на упакований або зашифрований, секції {what}"))
    if any(f & 0x20000000 and f & 0x80000000 for *_, f in pe.sections):
        out.append(Finding("PE_WX_SECTION", 15, "Є секція, яку можна і виконувати, і змінювати"))
    if pe.entry:
        hit = next((i for i, (_, vs, va, rs, _, _) in enumerate(pe.sections)
                    if va <= pe.entry < va + max(vs, rs)), None)
        if hit is None:
            out.append(Finding("PE_EP_ANOMALY", 20, "Точка входу лежить поза секціями файлу"))
        elif hit == len(pe.sections) - 1 and len(pe.sections) > 1 and pe.sections[hit][0] not in (b".text", b"code"):
            out.append(Finding("PE_EP_ANOMALY", 10, "Виконання починається в останній секції"))
    end = max((s[4] + s[3] for s in pe.sections), default=0)
    sec = pe.dd[4] if len(pe.dd) > 4 else (0, 0)
    overlay = len(data) - end - (sec[1] if sec[0] else 0)
    if overlay > 1_000_000 and overlay > len(data) // 2:
        out.append(Finding("PE_OVERLAY", 10, "Після кінця програми дописано великий блок даних"))
    if not (sec[0] and sec[1]):
        out.append(Finding("PE_NO_SIGNATURE", 5, "Немає цифрового підпису видавця"))
    return out


def _imports(pe: _PE, size: int) -> list[Finding]:
    names = [n for n in pe.imports() if n]
    s = set(names)
    out: list[Finding] = []
    inj = s & INJECTION
    if len(inj) >= 3:
        out.append(Finding("PE_INJECTION_APIS", 30, "Імпортує набір функцій для впровадження коду в чужі процеси"))
    if s & DOWNLOAD and s & RUN:
        out.append(Finding("PE_DOWNLOADER_APIS", 20, "Вміє завантажувати з мережі та запускати програми"))
    if s & HOOK and s & KEYS:
        out.append(Finding("PE_KEYLOG_APIS", 20, "Імпортує функції, типові для перехоплення клавіатури"))
    if len(names) <= 3 and size > 10_000 and pe.sections:
        out.append(Finding("PE_FEW_IMPORTS", 10, "Майже немає імпортів, функції можуть підвантажуватись приховано"))
    return out
