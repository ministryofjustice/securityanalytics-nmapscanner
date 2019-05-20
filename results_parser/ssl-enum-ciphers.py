import os

# ssl-enum-ciphers will translate these codes to these strings, converting them back in order to
# to use the numeric ordering for comparison
# https://svn.nmap.org/nmap-releases/nmap-6.00/scripts/ssl-enum-ciphers.nse
PROTOCOLS = set([
    "SSLv3",
    "TLSv1.0",
    "TLSv1.1",
    "TLSv1.2",
    "TLSv1.3"
])

task_name = os.environ["TASK_NAME"]


def summarise_proto(proto, summaries):
    if proto in PROTOCOLS:
        if "lowest_ssl_proto" not in summaries:
            summaries["lowest_ssl_proto"] = proto
        else:
            lowest = summaries["lowest_ssl_proto"]
            if proto < lowest:
                summaries["lowest_ssl_proto"] = proto
    else:
        if "unknown_ssl_proto" not in summaries:
            summaries["unknown_ssl_proto"] = True


def summarise_cipher(cipher, summaries):
    if "lowest_ssl_strength" not in summaries or cipher < summaries["lowest_ssl_strength"]:
        summaries["lowest_ssl_strength"] = cipher


def process_script(script, results_context):
    script_info = []
    summaries = {}
    for proto_table in script.table:
        proto = proto_table["key"]
        proto_key = {
            "ssl_protocol": proto
        }
        results_context.push_context(proto_key)
        summarise_proto(proto, summaries)
        proto_data = {}

        for sub_table in proto_table.table:
            if sub_table["key"] == "ciphers":
                proto_data["ciphers"] = cipher_info = []
                results_context.post_results("ssl_protos", proto_data)
                process_ciphers(cipher_info, sub_table, results_context)
        for elem in proto_table.elem:
            if elem["key"] == "cipher preference":
                proto_data["cipher_preference"] = elem.cdata
        script_info.append({**proto_key, **proto_data})
        results_context.pop_context()

    result = {"ssl_enum_ciphers": script_info}
    for elem in script.elem:
        if elem["key"] == "least strength":
            result["ssl_least_strength"] = elem.cdata
            summarise_cipher(elem.cdata, summaries)
    results_context.add_summaries(summaries)
    return result


def process_ciphers(cipher_info, table, results_context):
    for cipher_table in table.table:
        info = {}
        name = None
        for elem in cipher_table.elem:
            if elem["key"] == "name":
                name = elem.cdata
            else:
                info[elem["key"]] = elem.cdata
        cipher_key = {
            "name": name
        }
        cipher_info.append({**cipher_key, **info})
        results_context.push_context(cipher_key)
        results_context.post_results("ssl_ciphers", info)
        results_context.pop_context()
