data "aws_iam_policy_document" "notify_topic_policy" {
  statement {
    actions = [
      "sqs:SendMessage",
    ]

    condition {
      test = "ArnEquals"
      variable = "aws:SourceArn"

      values = [
        data.aws_ssm_parameter.scan_initiation_topic.value,
      ]
    }

    effect = "Allow"

    principals {
      type = "AWS"
      identifiers = [
        "*"]
    }

    resources = [
      var.scan_trigger_queue_arn,
    ]
  }
}

resource "aws_sqs_queue_policy" "queue_policy" {
  count = local.is_not_integration_test
  queue_url = var.scan_trigger_queue_url
  policy = data.aws_iam_policy_document.notify_topic_policy.json
}

locals {
  is_not_integration_test = terraform.workspace == var.ssm_source_stage ? var.subscribe_to_scheduler ? 1 : 0 : 0
}

resource "aws_sns_topic_subscription" "user_updates_sqs_target" {
  count = local.is_not_integration_test
  topic_arn = data.aws_ssm_parameter.scan_initiation_topic.value
  protocol = "sqs"
  endpoint = var.scan_trigger_queue_arn
  raw_message_delivery = true
}

