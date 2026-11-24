from filetrust.models import Finding

# Бали окремих знахідок додаються, стеля 100.
# Пороги: від 30 підозріло, від 60 високий ризик. Поріг 30 той самий, що в eval/run_eval.py.
def score(findings: list[Finding]) -> tuple[int, str]:
    total = min(100, sum(f.points for f in findings))
    if total >= 60:
        return total, "🔴 ВИСОКИЙ РИЗИК"
    if total >= 30:
        return total, "🟡 ПІДОЗРІЛО"
    return total, "🟢 НИЗЬКИЙ РИЗИК"
