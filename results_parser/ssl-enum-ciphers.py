# ssl-enum-ciphers will translate these codes to these strings, converting them back in order to
# to use the numeric ordering for comparison
# https://svn.nmap.org/nmap-releases/nmap-6.00/scripts/ssl-enum-ciphers.nse
PROTOCOLS = {
    "SSLv3": 0x0300,
    "TLSv1.0": 0x0301,
    "TLSv1.1": 0x0302,
    "TLSv1.2": 0x0303
}


def summarise_proto(proto, summaries):
    # default to low (unknown)
    proto_code = PROTOCOLS.get(proto, 0x0000)
    if "lowest_ssl_proto" not in summaries or proto_code < summaries["lowest_ssl_proto"]:
        summaries["lowest_ssl_proto"] = proto_code


def summarise_cipher(cipher, summaries):
    if "summary_lowest_ssl_strength" not in summaries or cipher < summaries["summary_lowest_ssl_strength"]:
        summaries["summary_lowest_ssl_strength"] = cipher


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
