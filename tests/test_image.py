import zlib, struct
from filetrust.pipeline import analyze


def _png():
    def ch(t, d): return struct.pack(">I", len(d)) + t + d + struct.pack(">I", zlib.crc32(t + d))
    return (b"\x89PNG\r\n\x1a\n" + ch(b"IHDR", struct.pack(">IIBBBBB", 1, 1, 8, 2, 0, 0, 0))
            + ch(b"IDAT", zlib.compress(b"\x00\xff\x00\x00")) + ch(b"IEND", b""))


def ids(p, n):
    return {f.id for f in analyze(p, n)[1]}


def test_clean_png_is_quiet(tmp_path):
    p = tmp_path / "a.png"; p.write_bytes(_png())
    assert not ids(p, "a.png") & {"IMAGE_HIDDEN_FILE", "IMAGE_TRAILING_DATA"}


def test_png_with_hidden_exe_is_flagged(tmp_path):
    p = tmp_path / "a.png"; p.write_bytes(_png() + b"MZ" + b"\x90" * 300)
    assert "IMAGE_HIDDEN_FILE" in ids(p, "a.png")


def test_png_with_hidden_zip_is_flagged(tmp_path):
    p = tmp_path / "a.png"; p.write_bytes(_png() + b"PK\x03\x04" + b"\0" * 100)
    assert "IMAGE_HIDDEN_FILE" in ids(p, "a.png")


def test_jpeg_motion_photo_trailer_is_not_flagged(tmp_path):
    p = tmp_path / "m.jpg"; p.write_bytes(b"\xff\xd8\xff\xe0" + b"A" * 100 + b"\xff\xd9" + b"\0\0\0\x18ftypmp42" + b"V" * 6000)
    assert "IMAGE_TRAILING_DATA" not in ids(p, "m.jpg")
