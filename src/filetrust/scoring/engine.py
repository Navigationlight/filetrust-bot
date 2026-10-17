from filetrust.models import Finding

def score(findings: list[Finding]) -> tuple[int, str]:
    total = min(100, sum(f.points for f in findings))
    if total >= 60:
        return total, "🔴 ВИСОКИЙ РИЗИК"
    if total >= 30:
        return total, "🟡 ПІДОЗРІЛО"
    return total, "🟢 НИЗЬКИЙ РИЗИК"
