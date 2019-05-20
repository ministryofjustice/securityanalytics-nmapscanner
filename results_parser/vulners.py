import re
import os

WHITE_SQUASHER = re.compile(r"\s+")
LINE_SPLITTER = re.compile(r"\n")

task_name = os.environ["TASK_NAME"]


def summarise_severity(severity, summaries):
    if "highest_cve_severity" not in summaries or severity > summaries["highest_cve_severity"]:
        summaries["highest_cve_severity"] = severity


def process_script(script, results_context):
    results = []
    result = {"cve_vulners": results}
    summaries = {}
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
            cve_key = {
                "cve_code": code
            }
            results_context.push_context(cve_key)
            cve_data = {
                "cve_severity": severity
            }
            summarise_severity(severity, summaries)
            results_context.post_results("cves", cve_data)
            results_context.pop_context()
            cve_info.append({**cve_key, **cve_data})
        if len(cve_info) > 0:
            results.append(cpe_result)

    results_context.add_summaries(summaries)
    return result
