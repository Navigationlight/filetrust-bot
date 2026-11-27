
import struct

from filetrust.analyzers.urlcheck import check_url
from filetrust.models import FileInfo, Finding

MAX_READ = 25 * 1024 * 1024
HIDDEN_SIGNS = (
    (b"MZ", "виконуваний файл Windows"), (b"\x7fELF", "виконуваний файл Linux"),
    (b"PK\x03\x04", "архів або документ Office"), (b"%PDF-", "PDF"),
    (b"Rar!", "архів RAR"), (b"7z\xbc\xaf", "архів 7z"), (b"\xd0\xcf\x11\xe0", "документ Office (старий)"),
    (b"<script", "скрипт"), (b"<html", "HTML-сторінка"), (b"#!", "скрипт"),
)

MAX_PIXELS = 40_000_000     # більше не декодуємо: захист від «бомб» у зображеннях
BENIGN_TRAILER = (b"ftyp", b"SEFH", b"MotionPhoto", b"Exif", b"XMP", b"ICC_PROFILE")


def _image_end(data: bytes) -> int | None:
    if data.startswith(b"\x89PNG"):
        i = data.rfind(b"IEND")
        return i + 8 if i != -1 else None      # IEND + CRC
    if data.startswith(b"\xff\xd8"):
        i = data.rfind(b"\xff\xd9")
        return i + 2 if i != -1 else None
    return None


def _is_pe(buf: bytes, i: int) -> bool:
    """MZ справжній, лише якщо за зсувом e_lfanew стоїть сигнатура PE."""
    if len(buf) < i + 0x40:
        return False
    off = int.from_bytes(buf[i + 0x3C:i + 0x40], "little")
    return off < 4096 and buf[i + off:i + off + 4] == b"PE\0\0"


def _find_sign(tail: bytes) -> str | None:
    head = tail.lstrip(b"\x00\r\n ")
    for sig, desc in HIDDEN_SIGNS:
        if head.startswith(sig):
            return desc
    window = tail[:4096]
    for sig, desc in HIDDEN_SIGNS[:7]:
        i = window.find(sig)
        if i == -1 or (sig == b"MZ" and not _is_pe(window, i)):
            continue                 # дві випадкові літери MZ ще не exe
        return desc
    return None


def _pixels(data: bytes) -> int | None:
    """Розмір картинки з заголовка (PNG, JPEG), без декодування."""
    if data.startswith(b"\x89PNG") and len(data) >= 24:
        w, h = struct.unpack(">II", data[16:24])
        return w * h
    if data.startswith(b"\xff\xd8"):
        i = 2
        while i + 9 < len(data):
            if data[i] != 0xFF:
                i += 1
                continue
            m = data[i + 1]
            if m == 0xFF:
                i += 1
            elif m in (0xD8, 0x01) or 0xD0 <= m <= 0xD7:
                i += 2
            elif m in (0xC0, 0xC1, 0xC2, 0xC3, 0xC5, 0xC6, 0xC7, 0xC9, 0xCA, 0xCB, 0xCD, 0xCE, 0xCF):
                h, w = struct.unpack(">HH", data[i + 5:i + 9])
                return w * h
            else:
                i += 2 + struct.unpack(">H", data[i + 2:i + 4])[0]
    return None


def check_image(info: FileInfo) -> list[Finding]:
    with info.path.open("rb") as f:
        data = f.read(MAX_READ)
    out: list[Finding] = []
    end = _image_end(data)
    if end is not None and len(data) - end > 16:
        tail = data[end:]
        sign = _find_sign(tail)
        if sign:
            out.append(Finding("IMAGE_HIDDEN_FILE", 70,
                               f"Після кінця зображення дописаний ще один файл: {sign}"))
        elif len(tail) > 4096 and not any(b in tail[:4096] for b in BENIGN_TRAILER):
            out.append(Finding("IMAGE_TRAILING_DATA", 15,
                               "Після кінця зображення є зайві дані"))
    out += _qr_findings(data)
    return out


def _qr_findings(data: bytes) -> list[Finding]:
    px = _pixels(data)
    if px is None or px > MAX_PIXELS:
        return []                    # невідомий формат або завелика картинка
    try:
        import cv2
        import numpy as np
    except ImportError:
        return []
    img = cv2.imdecode(np.frombuffer(data, np.uint8), cv2.IMREAD_COLOR)
    if img is None:
        return []
    text, _, _ = cv2.QRCodeDetector().detectAndDecode(img)
    if not text:
        return []
    found = check_url(text)
    if found:
        found.append(Finding("IMAGE_QR_LINK", 20, "QR-код на картинці веде на підозріле посилання"))
    return found
