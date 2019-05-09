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


def process_script(script, summaries):
    script_info = []
    for proto_table in script.table:
        proto = proto_table["key"]
        proto_info = {
            "protocol": proto
        }
        summarise_proto(proto, summaries)

        for sub_table in proto_table.table:
            if sub_table["key"] == "ciphers":
                proto_info["ciphers"] = cipher_info = []
                process_ciphers(cipher_info, sub_table)
        for elem in proto_table.elem:
            if elem["key"] == "cipher preference":
                proto_info["cipher_preference"] = elem.cdata
        script_info.append(proto_info)

    result = {"ssl_enum_ciphers": script_info}
    for elem in script.elem:
        if elem["key"] == "least strength":
            result["ssl_least_strength"] = elem.cdata
            summarise_cipher(elem.cdata, summaries)
    return result


def process_ciphers(cipher_info, table):
    for cipher_table in table.table:
        info = {}
        for elem in cipher_table.elem:
            info[elem["key"]] = elem.cdata
        cipher_info.append(info)
