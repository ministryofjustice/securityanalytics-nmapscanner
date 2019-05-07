def process_script(script):
    results = {}
    for table in script.table:
        if table["key"] == "validity":
            results["validity"] = {}
            for elem in table.elem:
                results["validity"][elem["key"]] = elem.cdata
        if table["key"] == "issuer":
            results["issuer"] = {}
            for elem in table.elem:
                results["issuer"][elem["key"]] = elem.cdata
    print(f'ssl_cert results {results}')
    return {'ssl_cert': results}
