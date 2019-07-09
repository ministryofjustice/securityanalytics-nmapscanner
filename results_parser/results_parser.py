from shared_task_code.base_results_parser import ResultsParser
import untangle
import importlib.util
from utils.time_utils import iso_date_string_from_timestamp
import os

MAPPED_OS_ATTRS = {f: f.replace("_", "") for f in ["type", "vendor", "os_family", "os_gen", "accuracy"]}


# TODO break this up into multiple parsers e.g. port parser, would make unit tests simpler too
class NmapResultsParser(ResultsParser):
    def __init__(self):
        super().__init__()

    async def parse_results(self, result_file_name, results_doc, meta_data):
        await super().parse_results(result_file_name, results_doc, meta_data)
        nmap_results = untangle.parse(results_doc).nmaprun

        # TODO if we standardise how start and end time are encoded by all the scanners, we can
        # move this code inside the ResultsParser class instead
        start_time, end_time = map(
            iso_date_string_from_timestamp,
            (nmap_results["start"], nmap_results.runstats.finished["time"]))

        for host in nmap_results.host:
            await self._process_host_results(host, result_file_name, start_time, end_time)

    async def _process_host_results(self, host, result_file_name, start_time, end_time):
        address = host.address["addr"]
        address_type = host.address["addrtype"]
        print(f"Looking at host: {(address, address_type)} scanned at {end_time}")

        scan_id = os.path.splitext(result_file_name)[0]
        non_temporal_key = {
            "address": address,
            "address_type": address_type
        }

        # TODO if we standardise how start and end time are encoded by all the scanners, we can
        # move all of the code in this method up to this point into the ResultsParser
        results_context = self.create_results_context(non_temporal_key, scan_id, start_time, end_time)

        host_names = []
        os_info = []
        ports = []
        results_details = {
            "host_names": host_names,
            "ports": ports,
            "os_info": os_info
        }

        if host["starttime"] and host["endtime"]:
            host_start_time, host_end_time = map(
                iso_date_string_from_timestamp,
                (host["starttime"], host["endtime"]))
            results_details["host_scan_start_time"] = host_start_time
            results_details["host_scan_end_time"] = host_end_time

        self.process_host_names(host_names, host)
        self._process_ports(ports, host, results_context)
        self.process_os(os_info, host, results_context)

        if hasattr(host, "status"):
            status = host.status
            results_details["status"] = status["state"]
            results_details["status_reason"] = status["reason"]

        if hasattr(host, "uptime"):
            uptime = host.uptime
            results_details["uptime"] = uptime["seconds"]
            results_details["last_boot"] = uptime["lastboot"]

        results_context.post_results("data", results_details, include_summaries=True)

        await results_context.publish_results()
        print(f"done host")

    def _process_ports(self, ports, host, results_context):
        if hasattr(host, "ports") and hasattr(host.ports, "port"):
            for port in host.ports.port:
                port_id, protocol = (port['portid'], port['protocol'])
                print(f"Looking at port: {(port_id, protocol)}")
                port_key = {
                    "port_id": port_id,
                    "protocol": protocol
                }
                results_context.push_context(port_key)
                port_data = {}
                if hasattr(port, "state"):
                    status = port.state
                    port_data["status"] = status["state"]
                    port_data["status_reason"] = status["reason"]
                self._process_port_service(port_data, port)
                results_context.post_results("ports", port_data)
                self._process_port_scripts(port_data, port, results_context)
                ports.append({**port_key, **port_data})
                results_context.pop_context()

    @staticmethod
    def _process_port_service(port_data, port):
        if hasattr(port, "service"):
            port_data.update({
                "service": port.service["name"],
                "product": port.service["product"],
                "version": port.service["version"],
                "extra_info": port.service["extrainfo"],
                "os_type": port.service["ostype"],
            })
            if hasattr(port.service, "cpe"):
                cpes = []
                for cpe in port.service.cpe:
                    cpes.append(cpe.cdata)
                if len(cpes) > 0:
                    port_data["cpes"] = cpes

    @staticmethod
    def _process_port_scripts(port_data, port, results_context):
        if hasattr(port, "script"):
            for script in port.script:
                name = script["id"]
                # try and dynamically load a module for each script
                script_processing_module_spec = importlib.util.find_spec(f"results_parser.{name}")
                if script_processing_module_spec:
                    print(f"Processing plugin for script {name}")
                    module = importlib.util.module_from_spec(script_processing_module_spec)
                    script_processing_module_spec.loader.exec_module(module)
                    script_info = module.process_script(script, results_context)
                    if script_info:
                        port_data.update(script_info)

    @staticmethod
    def process_host_names(host_names, host):
        if hasattr(host, "hostnames") and hasattr(host.hostnames, "hostname"):
            for host_name in host.hostnames.hostname:
                host_names.append({
                    "host_name": host_name["name"],
                    "host_name_type": host_name["type"]
                })

    @staticmethod
    def process_os_class(os_match, os_data):
        if hasattr(os_match, "osclass"):
            os_classes = []
            for os_class in os_match.osclass:
                class_info = {}
                for field, retrieve_name in MAPPED_OS_ATTRS.items():
                    class_info[f"os_class_{field}"] = os_class[retrieve_name]
                if hasattr(os_class, "cpe"):
                    cpe_info = []
                    for cpe in os_class.cpe:
                        cpe_info.append(cpe.cdata)
                    if len(cpe_info) > 0:
                        class_info["os_cpes"] = cpe_info

                os_classes.append(class_info)
            if len(os_classes) > 0:
                os_data["os_classes"] = os_classes

    def process_os(self, os_info, host, results_context):
        if hasattr(host, "os") and hasattr(host.os, "osmatch"):
            most_likely_os, most_accurate = (None, 0)
            for os_match in host.os.osmatch:
                name = os_match["name"]
                accuracy = int(os_match["accuracy"])

                os_key = {
                    "os_name": name
                }
                results_context.push_context(os_key)

                os_data = {
                    "os_accuracy": accuracy
                }

                if accuracy > most_accurate:
                    most_accurate = accuracy
                    most_likely_os = name
                self.process_os_class(os_match, os_data)
                os_info.append({**os_key, **os_data})

                results_context.post_results("os", os_data)

                if most_likely_os == name:
                    results_context.add_summary("most_likely_os", most_likely_os)
                    results_context.add_summary("most_likely_os_accuracy", most_accurate)

                results_context.pop_context()
