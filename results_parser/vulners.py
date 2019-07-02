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

    # Old school parsing of elem based results.
    if hasattr(script, "elem"):
        _parse_elem_based_results(results, results_context, script, summaries)
    else:
        _parse_table_based_results(results, results_context, script, summaries)

    results_context.add_summaries(summaries)
    return result


def _parse_elem_based_results(results, results_context, script, summaries):
    for elem in script.elem:
        cve_info = []
        cpe_key = elem["key"]
        cpe_result = {"cpe_key": cpe_key, "cves": cve_info}
        # IN the elem is encoded data which is split into lines using a regex, and then split on spaces for columns
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


def _parse_table_based_results(results, results_context, script, summaries):
    for vuln in script.table:
        cve_info = []
        cpe_key = vuln["key"]
        cpe_result = {"cpe_key": cpe_key, "cves": cve_info}

        for table in vuln.table:
            vuln_info = {elem["key"]: elem.cdata for elem in table.elem}

            severity = float(vuln_info.pop("cvss"))
            code = vuln_info.pop("id")
            cve_key = {
                "cve_code": code
            }
            results_context.push_context(cve_key)
            cve_data = {
                "cve_severity": severity,
                # add any other fields too
                **vuln_info
            }
            summarise_severity(severity, summaries)
            results_context.post_results("cves", cve_data)
            results_context.pop_context()
            cve_info.append({**cve_key, **cve_data})
        if len(cve_info) > 0:
            results.append(cpe_result)
