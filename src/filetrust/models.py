from dataclasses import dataclass
from pathlib import Path

@dataclass
class Finding:
    id: str      # DOUBLE_EXT
    points: int  # внесок у ризик
    text: str    # пояснення людською мовою

@dataclass
class FileInfo:
    name: str    # імʼя від користувача (тільки для аналізу, не для диска)
    path: Path
    size: int
    sha256: str
    mime: str    #  libmagic
    kind: str    #  pdf, zip, ooxml, exe
