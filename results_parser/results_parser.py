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
    body = tar.extractfile(re.sub(r"\.tar.gz$", "", key.split("/", -1)[-1]))
    nmap_results = untangle.parse(body).nmaprun

    for host in nmap_results.host:
        process_host_results(topic, host)


def process_host_results(topic, host):
    address = host.address["addr"]
    address_type = host.address["addrtype"]
    parsed_time = datetime.datetime.fromtimestamp(int(host["endtime"]), pytz.utc)
    scan_time = parsed_time.isoformat().replace('+00:00', 'Z')
    print(f"Looking at host: {(address, address_type)} scanned at {scan_time}")
    post_results(topic, "host", {"time": scan_time, "address": address, "address_type": address_type})

    process_host_names(address, address_type, host, scan_time, topic)

    process_ports(address, address_type, host, scan_time, topic)

    print(f"done host")


def process_ports(address, address_type, host, scan_time, topic):
    for port in host.ports.port:
        print(f"Looking at port: {(port['portid'], port['protocol'])}")
        post_results(topic, "port", {
            "time": scan_time,
            "address": address,
            "address_type": address_type,
            "protocol": port["protocol"],
            "state": port.state["state"],
            "service": port.service["name"],
            "product": port.service["product"],
            "version": port.service["version"],
            "extra_info": port.service["extrainfo"],
            "os_type": port.service["ostype"],
            "port_id": port["portid"]
        })


def process_host_names(address, address_type,host, scan_time, topic):
    for host_name in host.hostnames.hostname:
        post_results(topic, "host_name", {
            "time": scan_time,
            "address": address,
            "address_type": address_type,
            "host_name": host_name["name"],
            "host_name_type": host_name["type"]
        })


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
