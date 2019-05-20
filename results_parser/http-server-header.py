def process_script(script, results_context):
    headers = []
    for elem in script.elem:
        headers.append(elem.cdata)
    return {"http-server-header": headers}
