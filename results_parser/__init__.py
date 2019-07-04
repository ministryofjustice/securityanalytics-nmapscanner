from .results_parser import NmapResultsParser

_parser = NmapResultsParser()


def invoke(event, context):
    return _parser.invoke(event, context)
