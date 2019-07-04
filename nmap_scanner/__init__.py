from .nmap_scanner import NmapScanner

_scanner = None


def invoke(event, context):
    global _scanner
    if _scanner is None:
        _scanner = NmapScanner()
    return _scanner.invoke(event, context)
