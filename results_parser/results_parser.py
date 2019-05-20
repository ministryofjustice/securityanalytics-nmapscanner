from lambda_decorators import async_handler
import os
import boto3
from utils.lambda_decorators import ssm_parameters
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


region = os.environ["REGION"]
stage = os.environ["STAGE"]
app_name = os.environ["APP_NAME"]
task_name = os.environ["TASK_NAME"]
ssm_prefix = f"/{app_name}/{stage}"
ssm_client = boto3.client("ssm", region_name=region)
s3_client = boto3.client("s3", region_name=region)
sns_client = boto3.client("sns", region_name=region)

SNS_TOPIC = f"{ssm_prefix}/tasks/{task_name}/results/arn"


def post_results(topic, doc_type, document, non_temporal_key, time):
    r = sns_client.publish(
        TopicArn=topic,
        Subject=doc_type,
        Message=dumps(document),
        MessageAttributes={"NonTemporalKey": non_temporal_key, "ScanEndTime": time}
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
    host_names = []
    os_info = []
    ports = []
    results_key = {
        "scan_id": scan_id,
        "scan_start_time": start_time,
        "scan_end_time": end_time,
        "address": address,
        "address_type": address_type
    }
    results_details = {
        "host_names": host_names,
        "ports": ports,
        "os_info": os_info
    }

    results = {**results_key, **results_details}

    if host["starttime"] and host["endtime"]:
        host_start_time, host_end_time = map(
            lambda f:
                datetime.datetime.fromtimestamp(int(host[f]), pytz.utc).isoformat().replace('+00:00', 'Z'),
            ("starttime", "endtime"))
        results["host_scan_start_time"] = host_start_time
        results["host_scan_end_time"] = host_end_time

    process_host_names(host_names, host)

    summaries = {}

    process_ports(ports, host, summaries, results_key, topic)

    process_os(os_info, host, summaries, results_key, topic)

    if hasattr(host, "status"):
        status = host.status
        results["status"] = status["state"]
        results["status_reason"] = status["reason"]

    if hasattr(host, "uptime"):
        uptime = host.uptime
        results["uptime"] = uptime["seconds"]
        results["last_boot"] = uptime["lastboot"]

    add_summaries(results, summaries)

    post_results(topic, f"{task_name}:data:write", results, scan_id, end_time)

    print(f"done host")


def add_summaries(results, summaries):
    for key, value in summaries.items():
        results[f"summary_{key}"] = value


def process_ports(ports, host, summaries, results_key, topic):
    if hasattr(host, "ports") and hasattr(host.ports, "port"):
        for port in host.ports.port:
            port_id, protocol = (port['portid'], port['protocol'])
            print(f"Looking at port: {(port_id, protocol)}")
            port_info = {
                "port_id": port_id,
                "protocol": protocol
            }
            # publish this before adding the script info
            port_result_key = {**results_key, **port_info}
            if hasattr(port, "state"):
                status = port.state
                port_info["status"] = status["state"]
                port_info["status_reason"] = status["reason"]
            process_port_service(port_info, port)
            non_temporal_key = f"{results_key['scan_id']}/{port_id}/{protocol}"
            post_results(topic, f"{task_name}:ports:write", {**results_key, **port_info}, non_temporal_key, results_key["scan_end_time"])
            process_port_scripts(port_info, port, summaries, topic, port_result_key)
            ports.append(port_info)


def process_port_service(port_info, port):
    if hasattr(port, "service"):
        port_info.update({
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
                port_info["cpes"] = cpes


def process_port_scripts(port_info, port, summaries, topic, results_key):
    if hasattr(port, "script"):
        for script in port.script:
            name = script["id"]
            # try and dynamically load a module for each script
            script_processing_module_spec = importlib.util.find_spec(f"results_parser.{name}")
            if script_processing_module_spec:
                print(f"Processing plugin for script {name}")
                module = importlib.util.module_from_spec(script_processing_module_spec)
                script_processing_module_spec.loader.exec_module(module)
                script_info = module.process_script(script, summaries, post_results, topic, results_key)
                if script_info:
                    port_info.update(script_info)


def process_host_names(host_names, host):
    if hasattr(host, "hostnames") and hasattr(host.hostnames, "hostname"):
        for host_name in host.hostnames.hostname:
            host_names.append({
                "host_name": host_name["name"],
                "host_name_type": host_name["type"]
            })


MAPPED_OS_ATTRS = {f: f.replace("_", "") for f in ["type", "vendor", "os_family", "os_gen", "accuracy"]}


def process_os(os_info, host, summaries, results_key, topic):
    if hasattr(host, "os") and hasattr(host.os, "osmatch"):
        most_likely_os, most_accurate = (None, 0)
        for os_match in host.os.osmatch:
            name = os_match["name"]
            accuracy = int(os_match["accuracy"])
            os_details = {
                "os_name": name,
                "os_accuracy": accuracy
            }
            if accuracy > most_accurate:
                most_accurate = accuracy
                most_likely_os = name
            if hasattr(os_match, "osclass"):
                os_classes = []
                for os_class in os_match.osclass:
                    class_info = {}
                    for field, retreive_name in MAPPED_OS_ATTRS.items():
                        class_info[f"os_class_{field}"] = os_class[retreive_name]
                    if hasattr(os_class, "cpe"):
                        cpe_info = []
                        for cpe in os_class.cpe:
                            cpe_info.append(cpe.cdata)
                        if len(cpe_info) > 0:
                            class_info["os_cpes"] = cpe_info

                    os_classes.append(class_info)
                if len(os_classes) > 0:
                    os_details["os_classes"] = os_classes
            os_info.append(os_details)
            if most_likely_os:
                summaries["most_likely_os"] = most_likely_os
                summaries["most_likely_os_accuracy"] = most_accurate
                non_temporal_key = f"{results_key['scan_id']}/{name}"
            post_results(topic, f"{task_name}:os:write", {**results_key, **os_details}, non_temporal_key, results_key["scan_end_time"])


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
