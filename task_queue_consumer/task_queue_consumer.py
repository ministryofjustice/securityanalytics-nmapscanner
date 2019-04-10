from lambda_decorators import async_handler
import os
import boto3
from utils import json_serialisation

region = os.environ["REGION"]
stage = os.environ["STAGE"]
ecs_client = boto3.client('ecs', region_name=region)
ssm_client = boto3.client('ssm', region_name=region)


@async_handler
async def submit_scan_task(event, context):
    private_subnet = 'true' == os.environ["PRIVATE_SUBNETS"]
    network_configuration = {
        'awsvpcConfiguration': {
            'subnets': os.environ["SUBNETS"].split(","),
            'securityGroups': [os.environ["SECURITY_GROUP"]],
            'assignPublicIp': 'DISABLED' if private_subnet else 'ENABLED'
        }
    }
    for event in event['Records']:
        print(f"Scan requested: {json_serialisation.dumps(event['body'])}")
        params = {
            "cluster": os.environ["CLUSTER"],
            "networkConfiguration": network_configuration,
            "taskDefinition": os.environ["TASK"],
            "launchType": "FARGATE",
            "overrides": {
                "containerOverrides": [{
                    "name": os.environ["TASK_NAME"],
                    "environment": [
                        {
                            "name": "HOST_TO_SCAN",
                            "value": event["body"].strip()
                        },
                        {
                            "name": "RESULTS_BUCKET",
                            "value": os.environ["BUCKET"]
                        }]
                }]
            }
        }
        print(f"Submitting task: {json_serialisation.dumps(params)}")
        task_response = ecs_client.run_task(**params)
        print(f"Submitted scanning task: {json_serialisation.dumps(task_response)}")

    return 0
