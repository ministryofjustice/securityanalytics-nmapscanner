import re
import os

WHITE_SQUASHER = re.compile(r"\s+")
LINE_SPLITTER = re.compile(r"\n")

task_name = os.environ["TASK_NAME"]


def summarise_severity(severity, summaries):
    if "highest_cve_severity" not in summaries or severity > summaries["highest_cve_severity"]:
        summaries["highest_cve_severity"] = severity


def process_script(script, summaries, post_results, topic, results_key):
    results = []
    result = {"cve_vulners": results}
    for elem in script.elem:
        cve_info = []
        cpe_key = elem["key"]
        cpe_result = {"cpe_key": cpe_key, "cves": cve_info}
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
            severity = float(severity)
            cve_info.append({
                "cve_code": code,
                "cve_severity": severity
            })
            summarise_severity(severity, summaries)
            post_results(topic, f"{task_name}:cves:write", {
                **results_key,
                "cve_code": code,
                "cve_severity": severity,
                "cpe_key": cpe_key
            })
        if len(cve_info) > 0:
            results.append(cpe_result)
    return result


