from .nmap_scanner import NmapScanner

_scanner = NmapScanner()


def invoke(event, context):
    return _scanner.invoke(event, context)
