def process_script(script, _):
    headers = []
    for elem in script.elem:
        headers.append(elem.cdata)
    return {"http-server-header": headers}
