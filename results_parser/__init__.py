from .results_parser import NmapResultsParser

_parser = None


def invoke(event, context):
    nonlocal _parser
    if _parser is None:
        _parser = NmapResultsParser()
    return _parser.invoke(event, context)
