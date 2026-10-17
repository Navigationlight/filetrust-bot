from filetrust.models import FileInfo, Finding

def format_report(info: FileInfo, total: int, verdict: str,
                  findings: list[Finding]) -> str:
    lines = [
        f"📄 {info.name}",
        f"Тип за вмістом: {info.kind} ({info.mime})",
        f"SHA256: {info.sha256[:12]}…{info.sha256[-6:]}",
        "",
        f"{verdict} ({total}/100)",
        "",
    ]
    if findings:
        lines.append("Знахідки:")
        for i, f in enumerate(findings, 1):
            lines.append(f"{i}. {f.text} (+{f.points})")
    else:
        lines.append("Підозрілих ознак не знайдено.")
        lines.append("Це не гарантія безпеки, а лише результат наших перевірок.")
    return "\n".join(lines)
