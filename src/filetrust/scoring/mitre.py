
"""Відповідність правил MITRE ATT&CK (Enterprise): ідентифікатор техніки та коротка назва."""
from filetrust.models import Finding

_M = {
    "RTLO": ("T1036.002", "Right-to-Left Override"),
    "DOUBLE_EXT": ("T1036.007", "Double File Extension"),
    "TYPE_MISMATCH": ("T1036.008", "Masquerade File Type"),
    "DISGUISED_EXEC": ("T1036.008", "Masquerade File Type"),
    "OFFICE_MACRO_HIDDEN_EXT": ("T1036.008", "Masquerade File Type"),
    "EXEC_FILE": ("T1204.002", "User Execution, Malicious File"),
    "ARCHIVE_EXEC": ("T1204.002", "User Execution, Malicious File"),
    "ARCHIVE_ENCRYPTED": ("T1027.013", "Encrypted or Encoded File"),
    "HTML_SMUGGLING": ("T1027.006", "HTML Smuggling"),
    "HTML_OBFUSCATED_JS": ("T1027", "Obfuscated Files or Information"),
    "PDF_OBFUSCATED": ("T1027", "Obfuscated Files or Information"),
    "HTML_PASSWORD_FORM": ("T1598.003", "Phishing for Information, Link"),
    "HTML_FORM_EXTERNAL": ("T1598.003", "Phishing for Information, Link"),
    "HTML_HIDDEN_IFRAME": ("T1189", "Drive-by Compromise"),
    "HTML_REDIRECT": ("T1189", "Drive-by Compromise"),
    "HTML_SUSPICIOUS_LINK": ("T1566.002", "Phishing, Spearphishing Link"),
    "OFFICE_MACRO": ("T1059.005", "Visual Basic"),
    "OFFICE_MACRO_AUTOEXEC": ("T1059.005", "Visual Basic"),
    "OFFICE_MACRO_SUSPICIOUS": ("T1059.005", "Visual Basic"),
    "OFFICE_MACRO_IOC": ("T1059.005", "Visual Basic"),
    "OFFICE_DDE": ("T1559.002", "Dynamic Data Exchange"),
    "OFFICE_REMOTE_CONTENT": ("T1221", "Template Injection"),
    "OFFICE_EMBEDDED_EXEC": ("T1204.002", "User Execution, Malicious File"),
    "OFFICE_SUSPICIOUS_LINK": ("T1566.002", "Phishing, Spearphishing Link"),
    "PDF_JAVASCRIPT": ("T1059.007", "JavaScript"),
    "PDF_AUTO_RUN": ("T1059.007", "JavaScript"),
    "PDF_LAUNCH": ("T1204.002", "User Execution, Malicious File"),
    "PDF_EMBEDDED_EXEC": ("T1204.002", "User Execution, Malicious File"),
    "PDF_EMBEDDED_FILE": ("T1027.009", "Embedded Payloads"),
    "PDF_RICHMEDIA": ("T1203", "Exploitation for Client Execution"),
    "PDF_SUSPICIOUS_LINK": ("T1566.002", "Phishing, Spearphishing Link"),
    "IMAGE_HIDDEN_FILE": ("T1027.009", "Embedded Payloads"),
    "IMAGE_QR_LINK": ("T1566.002", "Phishing, Spearphishing Link"),
    "PE_PACKED": ("T1027.002", "Software Packing"),
    "PE_WX_SECTION": ("T1027", "Obfuscated Files or Information"),
    "PE_EP_ANOMALY": ("T1027", "Obfuscated Files or Information"),
    "PE_OVERLAY": ("T1027.009", "Embedded Payloads"),
    "PE_FEW_IMPORTS": ("T1027.007", "Dynamic API Resolution"),
    "PE_INJECTION_APIS": ("T1055", "Process Injection"),
    "PE_DOWNLOADER_APIS": ("T1105", "Ingress Tool Transfer"),
    "PE_KEYLOG_APIS": ("T1056.001", "Keylogging"),
    "LINK_EXEC_DOWNLOAD": ("T1204.001", "User Execution, Malicious Link"),
}


def technique(fid: str) -> tuple[str, str] | None:
    if fid.startswith("ARCHIVE_") and fid not in _M:
        return None
    if fid.startswith("LINK_") and fid not in _M:
        return "T1566.002", "Phishing, Spearphishing Link"
    return _M.get(fid)


def techniques(findings: list[Finding]) -> list[tuple[str, str]]:
    """Унікальні техніки у порядку ідентифікатора."""
    return sorted({t for f in findings if (t := technique(f.id))})
