import pytest
import aioboto3
import os

# resource "aws_ssm_parameter" "task_queue" {
#   name        = "/${var.app_name}/${terraform.workspace}/tasks/${var.task_name}/task_queue/arn"
#   description = "The job queue ARN"
#   type        = "String"
#   value       = aws_sqs_queue.trigger_queue.arn
#   overwrite   = "true"
#
#   tags = {
#     app_name  = var.app_name
#     workspace = terraform.workspace
#   }
# }
#
# resource "aws_ssm_parameter" "task_queue_url" {
#   name        = "/${var.app_name}/${terraform.workspace}/tasks/${var.task_name}/task_queue/url"
#   description = "The job queue URL"
#   type        = "String"
#   value       = aws_sqs_queue.trigger_queue.id
#   overwrite   = "true"
#
#   tags = {
#     app_name  = var.app_name
#     workspace = terraform.workspace
#   }
# }
#
# resource "aws_ssm_parameter" "results_notifier" {
#   name        = "/${var.app_name}/${terraform.workspace}/tasks/${var.task_name}/results/arn"
#   description = "The results broadcaster"
#   type        = "String"
#   value       = aws_sns_topic.task_results.arn
#   overwrite   = "true"
#
#   tags = {
#     app_name  = var.app_name
#     workspace = terraform.workspace
#   }
# }


@pytest.mark.asyncio
@pytest.mark.integration
async def test_integration():
    region = os.environ["REGION"]
    stage = os.environ["STAGE"]
    app_name = os.environ["APP_NAME"]
    task_name = os.environ["TASK_NAME"]
    ssm_prefix = f"/{app_name}/{stage}"

    sqs_input_queue = f"{ssm_prefix}/tasks/{task_name}/task_queue/url"
    sns_output_notifier = f"{ssm_prefix}/tasks/{task_name}/results/arn"

    ssm_client = aioboto3.client("ssm", region_name=region)
    sqs_client = aioboto3.client("sqs", region_name=region)
    sns_client = aioboto3.client("sns", region_name=region)
    try:
        params = await ssm_client.get_parameters(Names=[
            sqs_input_queue,
            sns_output_notifier
        ])
        params = {p['Name']: p['Value'] for p in params["Parameters"]}

        sqs_input_queue_url = params[sqs_input_queue]
        sns_output_notifier_arn = params[sns_output_notifier]

        # await sns_client.subscribe(
        #     TopicArn=sns_output_notifier_arn,
        #     Protocol=
        # )

        print(sqs_input_queue_url, sns_output_notifier_arn)
    finally:
        await ssm_client.close()
        await sns_client.close()
        await sqs_client.close()
