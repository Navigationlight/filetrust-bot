
from filetrust.analyzers.urlcheck import check_url
from filetrust.models import FileInfo, Finding

MAX_READ = 25 * 1024 * 1024
HIDDEN_SIGNS = (
    (b"MZ", "виконуваний файл Windows"), (b"\x7fELF", "виконуваний файл Linux"),
    (b"PK\x03\x04", "архів або документ Office"), (b"%PDF-", "PDF"),
    (b"Rar!", "архів RAR"), (b"7z\xbc\xaf", "архів 7z"), (b"\xd0\xcf\x11\xe0", "документ Office (старий)"),
    (b"<script", "скрипт"), (b"<html", "HTML-сторінка"), (b"#!", "скрипт"),
)

BENIGN_TRAILER = (b"ftyp", b"SEFH", b"MotionPhoto", b"Exif", b"XMP", b"ICC_PROFILE")


def _image_end(data: bytes) -> int | None:
    if data.startswith(b"\x89PNG"):
        i = data.rfind(b"IEND")
        return i + 8 if i != -1 else None      # IEND + CRC
    if data.startswith(b"\xff\xd8"):
        i = data.rfind(b"\xff\xd9")
        return i + 2 if i != -1 else None
    return None


def check_image(info: FileInfo) -> list[Finding]:
    data = info.path.read_bytes()[:MAX_READ]
    out: list[Finding] = []
    end = _image_end(data)
    if end is not None and len(data) - end > 16:
        tail = data[end:]
        sign = next((d for s, d in HIDDEN_SIGNS if tail.lstrip(b"\x00\r\n ").startswith(s)), None)
        if sign is None:
            sign = next((d for s, d in HIDDEN_SIGNS[:7] if s in tail[:4096]), None)
        if sign:
            out.append(Finding("IMAGE_HIDDEN_FILE", 70,
                               f"Після кінця зображення дописаний ще один файл: {sign}"))
        elif len(tail) > 4096 and not any(b in tail[:4096] for b in BENIGN_TRAILER):
            out.append(Finding("IMAGE_TRAILING_DATA", 15,
                               "Після кінця зображення є зайві дані"))
    out += _qr_findings(data)
    return out


def _qr_findings(data: bytes) -> list[Finding]:
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
