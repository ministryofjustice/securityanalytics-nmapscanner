resource "aws_lambda_permission" "api_gateway_invoke" {
  statement_id  = "AllowExecutionFromAPIGateway"
  action        = "lambda:InvokeFunction"
  function_name = "${aws_lambda_function.sample.function_name}"
  principal     = "apigateway.amazonaws.com"
  source_arn    = "arn:aws:execute-api:${var.aws_region}:${var.account_id}:${aws_api_gateway_rest_api.api_gateway.id}/*/GET/nmap/sample"
}

resource "aws_api_gateway_deployment" "stage" {
  depends_on = [
    "aws_api_gateway_integration_response.nmap_sample",
    "aws_api_gateway_integration.nmap_sample",
  ]

  rest_api_id = "${aws_api_gateway_rest_api.api_gateway.id}"
  stage_name  = "${terraform.workspace}"
}

resource "aws_lambda_function" "sample" {
  depends_on = ["data.external.nmap_zip"]

  function_name = "${terraform.workspace}-${var.app_name}-${var.task_name}-sample"
  handler       = "sample_lambda.sample.sample"
  role          = "${aws_iam_role.sample_role.arn}"
  runtime       = "python3.7"
  filename      = "${local.nmap_zip}"

  layers = [
    "${data.aws_ssm_parameter.utils_layer.value}",
  ]

  environment {
    variables = {
      REGION    = "${var.aws_region}"
      STAGE     = "${terraform.workspace}"
      APP_NAME  = "${var.app_name}"
      TASK_NAME = "${var.task_name}"
    }
  }

  tags = {
    source_hash = "${data.external.nmap_zip.result.hash}"
    workspace   = "${terraform.workspace}"
    app_name    = "${var.app_name}"
  }
}

# TODO should use the shared api, but that is currently set to private and so making new public one
# here just for tests
resource "aws_api_gateway_rest_api" "api_gateway" {
  name = "${terraform.workspace}-${var.app_name}-${var.task_name}-api"
}

resource "aws_api_gateway_resource" "nmap" {
  parent_id   = "${aws_api_gateway_rest_api.api_gateway.root_resource_id}"
  path_part   = "nmap"
  rest_api_id = "${aws_api_gateway_rest_api.api_gateway.id}"
}

resource "aws_api_gateway_resource" "nmap_sample" {
  parent_id   = "${aws_api_gateway_resource.nmap.id}"
  path_part   = "sample"
  rest_api_id = "${aws_api_gateway_rest_api.api_gateway.id}"
}

resource "aws_api_gateway_method" "nmap_sample" {
  rest_api_id   = "${aws_api_gateway_rest_api.api_gateway.id}"
  resource_id   = "${aws_api_gateway_resource.nmap_sample.id}"
  http_method   = "GET"
  authorization = "NONE"
}

resource "aws_api_gateway_integration" "nmap_sample" {
  rest_api_id             = "${aws_api_gateway_rest_api.api_gateway.id}"
  resource_id             = "${aws_api_gateway_resource.nmap_sample.id}"
  http_method             = "${aws_api_gateway_method.nmap_sample.http_method}"
  integration_http_method = "POST"
  type                    = "AWS_PROXY"
  uri                     = "${aws_lambda_function.sample.invoke_arn}"
}

resource "aws_api_gateway_method_response" "nmap_sample_200" {
  rest_api_id = "${aws_api_gateway_rest_api.api_gateway.id}"
  resource_id = "${aws_api_gateway_resource.nmap_sample.id}"
  http_method = "${aws_api_gateway_method.nmap_sample.http_method}"
  status_code = "200"
}

resource "aws_api_gateway_integration_response" "nmap_sample" {
  depends_on = [
    "aws_api_gateway_integration.nmap_sample",
  ]

  rest_api_id = "${aws_api_gateway_rest_api.api_gateway.id}"
  resource_id = "${aws_api_gateway_resource.nmap_sample.id}"
  http_method = "${aws_api_gateway_method.nmap_sample.http_method}"
  status_code = "${aws_api_gateway_method_response.nmap_sample_200.status_code}"
}

data "aws_iam_policy_document" "sample_trust" {
  statement {
    actions = ["sts:AssumeRole"]
    effect  = "Allow"

    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
  }
}

data "aws_iam_policy_document" "sample_access" {
  statement {
    effect = "Allow"

    actions = [
      "lambda:InvokeFunction",
    ]

    # TODO reduce this scope
    resources = ["*"]
  }

  statement {
    effect = "Allow"

    actions = [
      "logs:CreateLogGroup",
      "logs:CreateLogStream",
      "logs:PutLogEvents",
    ]

    # TODO reduce this scope
    resources = ["*"]
  }
}

resource "aws_iam_role" "sample_role" {
  name               = "${terraform.workspace}-${var.app_name}-${var.task_name}-sample"
  assume_role_policy = "${data.aws_iam_policy_document.sample_trust.json}"

  tags {
    task_name = "${var.task_name}"
    app_name  = "${var.app_name}"
    workspace = "${terraform.workspace}"
  }
}

resource "aws_iam_policy" "task_policy" {
  name   = "${terraform.workspace}-${var.app_name}-${var.task_name}-sample"
  policy = "${data.aws_iam_policy_document.sample_access.json}"
}

resource "aws_iam_role_policy_attachment" "task_policy" {
  role       = "${aws_iam_role.sample_role.name}"
  policy_arn = "${aws_iam_policy.task_policy.arn}"
}
