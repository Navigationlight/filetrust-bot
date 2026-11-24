
import json
import sys
from dataclasses import asdict
from pathlib import Path

MEMORY_LIMIT = 2 * 1024 ** 3   # 2 ГБ адресного простору
CPU_LIMIT_SEC = 50


def _limits() -> None:
    try:                       # на Windows модуля resource немає, лишається таймаут
        import resource
        resource.setrlimit(resource.RLIMIT_AS, (MEMORY_LIMIT, MEMORY_LIMIT))
        resource.setrlimit(resource.RLIMIT_CPU, (CPU_LIMIT_SEC, CPU_LIMIT_SEC))
    except Exception:
        pass


def main() -> None:
    _limits()
    req = json.loads(sys.stdin.buffer.read().decode("utf-8"))
    try:
        from filetrust.pipeline import analyze
        info, findings = analyze(Path(req["path"]), req["name"])
        out = {"info": {**asdict(info), "path": str(info.path)},
               "findings": [asdict(f) for f in findings]}
    except BaseException as exc:    # включно з MemoryError
        out = {"error": type(exc).__name__}
    sys.stdout.write(json.dumps(out, ensure_ascii=True))


if __name__ == "__main__":
    main()
