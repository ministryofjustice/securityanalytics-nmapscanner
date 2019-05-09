import re

WHITE_SQUASHER = re.compile(r"\s+")
LINE_SPLITTER = re.compile(r"\n")


def summarise_severity(severity, summaries):
    if "highest_cve_severity" not in summaries or severity < summaries["highest_cve_severity"]:
        summaries["highest_cve_severity"] = severity


def process_script(script, summaries):
    results = []
    result = {"cve_vulners": results}
    for elem in script.elem:
        cve_info = []
        cpe_result = {"cpe_key": elem["key"], "cves": cve_info}
        cves_trimmed = [
            re.sub(WHITE_SQUASHER, " ", x).split(" ")
            for x
            in (
                cve.strip()
                for cve
                in LINE_SPLITTER.split(elem.cdata)
            )
            if x != ""
        ]
        for code, severity, _ in cves_trimmed:
            cve_info.append({
                "cve_code": code,
                "cve_severity": severity
            })
            summarise_severity(float(severity), summaries)
        if len(cve_info) > 0:
            results.append(cpe_result)
    return result



