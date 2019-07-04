
# TODO should use the shared api, but that is currently set to private and so making new public one
# here just for tests
resource "aws_api_gateway_rest_api" "api_gateway" {
  name = "${terraform.workspace}-${var.app_name}-${var.task_name}-api"
}

resource "aws_api_gateway_deployment" "stage" {
  depends_on = [
    aws_api_gateway_integration_response.nmap_sample,
    aws_api_gateway_integration.nmap_sample,
  ]

  rest_api_id = aws_api_gateway_rest_api.api_gateway.id
  stage_name  = terraform.workspace
}

locals {
  endpoints = {
    sample = {
      GET = "${aws_api_gateway_deployment.stage.invoke_url}/nmap/sample/"
    }
  }
}

resource "local_file" "endpoints" {
  filename = "../.generated/endpoints.json"
  content  = jsonencode(local.endpoints)
}

