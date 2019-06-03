import os
import aioboto3
import boto3
from utils.lambda_decorators import ssm_parameters, async_handler
from utils.json_serialisation import dumps
from netaddr import IPNetwork
from netaddr.core import AddrFormatError
import re
from json import loads

region = os.environ["REGION"]
stage = os.environ["STAGE"]
app_name = os.environ["APP_NAME"]
task_name = os.environ["TASK_NAME"]
ssm_prefix = f"/{app_name}/{stage}"
ecs_client = boto3.client("ecs", region_name=region)
ssm_client = aioboto3.client("ssm", region_name=region)

PRIVATE_SUBNETS = f"{ssm_prefix}/vpc/using_private_subnets"
SUBNETS = f"{ssm_prefix}/vpc/subnets/instance"
CLUSTER = f"{ssm_prefix}/ecs/cluster"
RESULTS = f"{ssm_prefix}/tasks/{task_name}/s3/results/id"
SECURITY_GROUP = f"{ssm_prefix}/tasks/{task_name}/security_group/id"
IMAGE_ID = f"{ssm_prefix}/tasks/{task_name}/image/id"

# <name> from https://tools.ietf.org/html/rfc952#page-5
ALLOWED_NAME = re.compile(r"(?!-)[a-z0-9-]{1,63}(?<!-)$", re.IGNORECASE)

# <name> from https://tools.ietf.org/html/rfc952#page-5
UNDERSCORE_ALLOWED_NAME = re.compile(r"[_]?(?!-)[a-z0-9-]{1,63}(?<!-)$", re.IGNORECASE)

# from https://tools.ietf.org/html/rfc3696#section-2
ALL_NUMERIC = re.compile(r"[0-9]+$")


# Lifted from https://stackoverflow.com/a/33214423
# Modified to extract compilation of regexes
def is_valid_hostname(hostname):
    if hostname[-1] == ".":
        # strip exactly one dot from the right, if present
        hostname = hostname[:-1]
    if len(hostname) > 253:
        return False

    labels = hostname.split(".")

    # the TLD must be not all-numeric
    if ALL_NUMERIC.match(labels[-1]):
        return False

    # hostname should consist of at least two parts:
    if len(labels) < 2:
        return False

    # RFC2782 allows for an underscore as the first character for each part of the domain name
    host_check = all(UNDERSCORE_ALLOWED_NAME.match(label) for label in labels[:-2])
    domain_check = all(ALLOWED_NAME.match(label) for label in labels[-2:])
    return (host_check & domain_check)


# Since we pass the target string directly into the script that is run inside the ecs instance
# anyone with access to the task queue could cause our instance to execute arbitrary code.
# TODO support nmap ranges e.g. 2-6.13-55.33.2-99
def sanitise_nmap_target(target_str):
    targets = target_str.split(" ")
    sanitised = []
    # Try to parse as network descriptions (includes individual hosts)
    for target in targets:
        try:
            # not used but will throw if it is an invalid input
            IPNetwork(target)
            sanitised.append(target)
        except AddrFormatError:
            # prefix to make into a url and parse then extract only the netloc,
            #  will prevent e.g. use of semicolon in query params getting through
            if is_valid_hostname(target):
                sanitised.append(target)
            else:
                raise ValueError(
                    f"Target {target} was an invalid specification.")

    return " ".join(sanitised)


def submit_ecs_task(event, host, message_id):
    ssm_params = event["ssm_params"]
    private_subnet = "true" == ssm_params[PRIVATE_SUBNETS]
    network_configuration = {
        "awsvpcConfiguration": {
            "subnets": ssm_params[SUBNETS].split(","),
            "securityGroups": [ssm_params[SECURITY_GROUP]],
            "assignPublicIp": "DISABLED" if private_subnet else "ENABLED"
        }
    }
    ecs_params = {
        "cluster": ssm_params[CLUSTER],
        "networkConfiguration": network_configuration,
        "taskDefinition": ssm_params[IMAGE_ID],
        "launchType": "FARGATE",
        "overrides": {
            "containerOverrides": [{
                "name": task_name,
                "environment": [
                    # TODO The only bit of this file that isn't going to be the same for other
                    # task queue executors, is this bit that maps the request body to some env vars
                    # Extract the common code into a layer exported by the task-execution project
                    {
                        "name": "NMAP_TARGET_STRING",
                                "value": sanitise_nmap_target(host.strip())
                    },
                    {
                        "name": "MESSAGE_ID",
                                "value": message_id
                    },
                    {
                        "name": "RESULTS_BUCKET",
                                "value": ssm_params[RESULTS]
                    }]
            }]
        }
    }
    print(f"Submitting task: {dumps(ecs_params)}")
    task_response = ecs_client.run_task(**ecs_params)
    print(f"Submitted scanning task: {dumps(task_response)}")

    failures = task_response["failures"]
    if len(failures) != 0:
        raise RuntimeError(
            f"ECS task failed to start {dumps(failures)}")


@ssm_parameters(
    ssm_client,
    PRIVATE_SUBNETS,
    SUBNETS,
    CLUSTER,
    RESULTS,
    SECURITY_GROUP,
    IMAGE_ID
)
@async_handler
async def submit_scan_task(event, _):

    print(f"Processing event {dumps(event)}")
    for record in event["Records"]:
        print(f"Scan requested: {dumps(record['body'])}")
        if record['body'][0] == '{':
            # triggered from cloudwatch which requires format in JSON:
            body = loads(record['body'])
            if 'CloudWatchEventHosts' in body:
                id = 0
                for nmap_targets in body['CloudWatchEventHosts']:
                    id += 1
                    submit_ecs_task(event, nmap_targets, f'{record["messageId"]}-{id}')
        else:
            # triggered via AWS by pushing host(s) to the queue manually:
            submit_ecs_task(event, record["body"], record["messageId"])
