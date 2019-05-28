import os
import boto3
from utils.lambda_decorators import ssm_parameters, async_handler
from utils.json_serialisation import dumps
from utils.objectify_dict import objectify
import tarfile
import re
import io
import untangle
import datetime
import pytz
from urllib.parse import unquote_plus
import importlib.util
from hashlib import sha256


region = os.environ["REGION"]
stage = os.environ["STAGE"]
app_name = os.environ["APP_NAME"]
task_name = os.environ["TASK_NAME"]
ssm_prefix = f"/{app_name}/{stage}"
ssm_client = boto3.client("ssm", region_name=region)
s3_client = boto3.client("s3", region_name=region)
sns_client = boto3.client("sns", region_name=region)

SNS_TOPIC = f"{ssm_prefix}/tasks/{task_name}/results/arn"


# Tracks context for results e.g. the main data result has key fields of scan id, address and address type
# When looking at a port the port id and protocol are pushed onto that context
class ResultsContext:
    def __init__(self, topic, non_temporal_key_fields, scan_id, start, end):
        self.non_temporal_key = [non_temporal_key_fields]
        self.scan_id = scan_id
        self.start = start
        self.end = end
        self.topic = topic
        self.summaries = {}
        print(f"Created publication context {self.topic}, {self._key()}, {self.end}")

    def push_context(self, non_temporal_key_fields):
        self.non_temporal_key.append(non_temporal_key_fields)
        print(f"Created publication context {self.topic}, {self._key()}, {self.end}")

    def pop_context(self):
        self.non_temporal_key.pop()

    def add_summary(self, key, value):
        self.summaries[key] = value

    def add_summaries(self, summaries):
        for k, v in summaries.items():
            self.summaries[k] = v

    def _key(self):
        return "/".join(self._key_fields().values())

    def _key_fields(self):
        return {k: v for field in self.non_temporal_key for k, v in field.items()}

    def _hash_of(self, value):
        hasher = sha256()
        hasher.update(value.encode('utf-8'))
        hash_val = hasher.hexdigest()
        print(f"Mapped non-temporal key {value} to hash {hash_val}")
        return hash_val

    def post_results(self, doc_type, data, include_summaries=False):
        if include_summaries:
            for key, value in self.summaries.items():
                data[f"summary_{key}"] = value
        r = sns_client.publish(
            TopicArn=self.topic,
            Subject=f"{task_name}:{doc_type}",
            Message=dumps({
                **self._key_fields(),
                "scan_id": self.scan_id,
                "scan_start_time": self.start,
                "scan_end_time": self.end,
                **data}),
            MessageAttributes={
                "NonTemporalKey": {"StringValue": self._hash_of(self._key()), "DataType": "String"},
                "ScanEndTime": {"StringValue": self._hash_of(self.end), "DataType": "String"}
            }
        )
        print(f"Published message {r['MessageId']}")


def process_results(topic, bucket, key):
    # Get, read, and split the file into lines
    print(f"Reading new file: {(bucket, key)}")
    obj = s3_client.get_object(Bucket=bucket, Key=key)
    content = obj["Body"].read()
    tar = tarfile.open(mode="r:gz", fileobj=io.BytesIO(content), format=tarfile.PAX_FORMAT)
    result_file_name = re.sub(r"\.tar.gz$", "", key.split("/", -1)[-1])
    body = tar.extractfile(result_file_name)
    nmap_results = untangle.parse(body).nmaprun

    start_time, end_time = map(
        lambda f:
            datetime.datetime.fromtimestamp(int(f), pytz.utc).isoformat().replace('+00:00', 'Z'),
        (nmap_results["start"], nmap_results.runstats.finished["time"]))

    for host in nmap_results.host:
        process_host_results(topic, host, result_file_name, start_time, end_time)


def process_host_results(topic, host, result_file_name, start_time, end_time):
    address = host.address["addr"]
    address_type = host.address["addrtype"]
    print(f"Looking at host: {(address, address_type)} scanned at {end_time}")

    scan_id = os.path.splitext(result_file_name)[0]
    non_temporal_key = {
        "address": address,
        "address_type": address_type
    }

    results_context = ResultsContext(topic, non_temporal_key, scan_id, start_time, end_time)

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
            lambda f:
                datetime.datetime.fromtimestamp(int(host[f]), pytz.utc).isoformat().replace('+00:00', 'Z'),
            ("starttime", "endtime"))
        results_details["host_scan_start_time"] = host_start_time
        results_details["host_scan_end_time"] = host_end_time

    process_host_names(host_names, host)
    process_ports(ports, host, results_context)
    process_os(os_info, host, results_context)

    if hasattr(host, "status"):
        status = host.status
        results_details["status"] = status["state"]
        results_details["status_reason"] = status["reason"]

    if hasattr(host, "uptime"):
        uptime = host.uptime
        results_details["uptime"] = uptime["seconds"]
        results_details["last_boot"] = uptime["lastboot"]

    results_context.post_results("data", results_details, include_summaries=True)

    print(f"done host")


def process_ports(ports, host, results_context):
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
            process_port_service(port_data, port)
            results_context.post_results("ports", port_data)
            process_port_scripts(port_data, port, results_context)
            ports.append({**port_key, **port_data})
            results_context.pop_context()


def process_port_service(port_data, port):
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


def process_port_scripts(port_data, port, results_context):
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


def process_host_names(host_names, host):
    if hasattr(host, "hostnames") and hasattr(host.hostnames, "hostname"):
        for host_name in host.hostnames.hostname:
            host_names.append({
                "host_name": host_name["name"],
                "host_name_type": host_name["type"]
            })


MAPPED_OS_ATTRS = {f: f.replace("_", "") for f in ["type", "vendor", "os_family", "os_gen", "accuracy"]}


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


def process_os(os_info, host, results_context):
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
            process_os_class(os_match, os_data)
            os_info.append({**os_key, **os_data})

            if most_likely_os:
                results_context.add_summary("most_likely_os", most_likely_os)
                results_context.add_summary("most_likely_os_accuracy", most_accurate)

            results_context.post_results("os", os_data)
            results_context.pop_context()


@ssm_parameters(
    ssm_client,
    SNS_TOPIC
)
@async_handler
async def parse_results(event, _):
    topic = event['ssm_params'][SNS_TOPIC]
    for record in event["Records"]:
        s3_object = objectify(record["s3"])
        bucket = s3_object.bucket.name
        key = unquote_plus(s3_object.object.key)
        process_results(topic, bucket, key)
