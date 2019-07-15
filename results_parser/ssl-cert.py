import datetime


def process_validity(results, table):
    # process validity data and compute the day difference between expiry and today
    results["validity"] = {}
    for elem in table.elem:
        results["validity"][elem["key"]] = elem.cdata
        if elem["key"] == "notAfter":
            ssl_exp_dt = datetime.datetime.strptime(elem.cdata, "%Y-%m-%dT%H:%M:%S")
            results["expiry_diff_at_scan"] = (ssl_exp_dt - datetime.datetime.now()).days


def process_extensions(results, table):
    # process extensions data for Subject Alternative name
    results["extensions"] = []
    for ext_table in table.table:
        alt_name = {}
        alt_rec = False
        for elem in ext_table.elem:
            if elem["key"] == "name" and "Subject Alternative Name" in elem.cdata:
                alt_rec = True
            alt_name[elem["key"]] = elem.cdata
        if alt_rec:
            results['extensions'].append(alt_name)


def process_script(script, results_context):
    results = {}
    for table in script.table:
        if table["key"] == "validity":
            process_validity(results, table)
        elif table["key"] == "extensions":
            process_extensions(results, table)
        elif table["key"] == "issuer" or table["key"] == "subject":
            results[table["key"]] = {}
            for elem in table.elem:
                results[table["key"]][elem["key"]] = elem.cdata

    results_context.post_results("ssl_cert", results)
    return {'ssl_cert': results}
