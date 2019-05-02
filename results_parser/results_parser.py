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


def post_results(topic, doc_type, document):
    r = sns_client.publish(
        TopicArn=topic, Subject=doc_type, Message=dumps(document)
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

    for host in nmap_results.host:
        process_host_results(topic, host, result_file_name)


def process_host_results(topic, host, result_file_name):
    address = host.address["addr"]
    address_type = host.address["addrtype"]
    start_time, end_time = map(
        lambda f:
            datetime.datetime.fromtimestamp(int(host[f]), pytz.utc).isoformat().replace('+00:00', 'Z'),
        ("starttime", "endtime"))
    print(f"Looking at host: {(address, address_type)} scanned at {end_time}")

    host_names = []
    os_info = []
    ports = []
    results = {
        "scan_id": os.path.splitext(result_file_name)[0],
        "start_time": start_time,
        "end_time": end_time,
        "address": address,
        "address_type": address_type,
        "host_names": host_names,
        "ports": ports,
        "os_info": os_info
    }

    process_host_names(host_names, host)

    process_ports(ports, host)

    process_os(os_info, host)

    if hasattr(host, "status"):
        status = host.status
        results["status"] = status["state"]
        results["status_reason"] = status["reason"]

    if hasattr(host, "uptime"):
        uptime = host.uptime
        results["uptime"] = uptime["seconds"]
        results["last_boot"] = uptime["lastboot"]

    post_results(topic, f"{task_name}:data:write", results)

    print(f"done host")


def process_ports(ports, host):
    for port in host.ports.port:
        port_id, protocol = (port['portid'], port['protocol'])
        print(f"Looking at port: {(port_id, protocol)}")
        port_info = {
            "port_id": port_id,
            "protocol": protocol
        }
        if hasattr(port, "state"):
            status = port.state
            port_info["status"] = status["state"]
            port_info["status_reason"] = status["reason"]
        process_port_service(port_info, port)
        process_port_scripts(port_info, port)
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


def process_port_scripts(port_info, port):
    if hasattr(port, "script"):
        for script in port.script:
            name = script["id"]
            # try and dynamically load a module for each script
            script_processing_module_spec = importlib.util.find_spec(f"results_parser.{name}")
            if script_processing_module_spec:
                print(f"Processing plugin for script {name}")
                module = importlib.util.module_from_spec(script_processing_module_spec)
                script_processing_module_spec.loader.exec_module(module)
                script_info = module.process_script(script)
                if script_info:
                    port_info.update(script_info)


def process_host_names(host_names, host):
    for host_name in host.hostnames.hostname:
        host_names.append({
            "host_name": host_name["name"],
            "host_name_type": host_name["type"]
        })


MAPPED_OS_ATTRS = {f: f.replace("_", "") for f in ["type", "vendor", "os_family", "os_gen", "accuracy"]}


def process_os(os_info, host):
    for os_match in host.os.osmatch:
        os_details = {
            "os_name": os_match["name"],
            "os_accuracy": os_match["accuracy"]
        }
        if hasattr(os_match, "osclass"):
            os_classes = []
            for os_class in os_match.osclass:
                class_info = {}
                for field, retreive_name in MAPPED_OS_ATTRS.items():
                    class_info[f"os_class_{field}"] = os_class[retreive_name]
                    if hasattr(os_class, "cpe"):
                        class_info["os_cpe"] = os_class.cpe.cdata
                os_classes.append(class_info)
            if len(os_classes) > 0:
                os_details["os_classes"] = os_classes
        os_info.append(os_details)


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
