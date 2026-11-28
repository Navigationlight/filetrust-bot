import asyncio
import json
import logging
import os
import sys
from pathlib import Path

from filetrust.config import TIMEOUT_SEC
from filetrust.models import FileInfo, Finding

log = logging.getLogger("filetrust")
SRC_DIR = str(Path(__file__).resolve().parents[1])


class AnalysisError(Exception):
    pass


async def analyze_isolated(path: Path, name: str, timeout: float = TIMEOUT_SEC):
    
    env = dict(os.environ)
    env["PYTHONPATH"] = os.pathsep.join(filter(None, [SRC_DIR, env.get("PYTHONPATH")]))
    proc = await asyncio.create_subprocess_exec(
        sys.executable, "-m", "filetrust.worker",
        stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE, env=env)
    payload = json.dumps({"path": str(path), "name": name}).encode("utf-8")
    try:
        out, err = await asyncio.wait_for(proc.communicate(payload), timeout)
    finally:
        if proc.returncode is None:
            proc.kill()
            await proc.wait()
    if err:
        log.warning("worker stderr: %s", err.decode("utf-8", "replace")[-800:])
    if proc.returncode != 0:
        raise AnalysisError(f"worker exit code {proc.returncode}")
    try:
        data = json.loads(out)
    except ValueError as exc:
        raise AnalysisError("worker returned invalid output") from exc
    if "error" in data:
        raise AnalysisError(data["error"])
    i = data["info"]
    info = FileInfo(name=i["name"], path=Path(i["path"]), size=i["size"],
                    sha256=i["sha256"], mime=i["mime"], kind=i["kind"],
                    meta=i.get("meta") or {})
    return info, [Finding(**f) for f in data["findings"]]
