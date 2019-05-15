def process_script(script, summaries, post_results, topic, results_key):
    headers = []
    for elem in script.elem:
        headers.append(elem.cdata)
    return {"http-server-header": headers}
