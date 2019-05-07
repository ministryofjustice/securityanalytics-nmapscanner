locals {
  endpoints = {
    sample = {
      GET = "${aws_api_gateway_deployment.stage.invoke_url}/nmap/sample/"
    }
  }
}

resource "local_file" "endpoints" {
  filename = "../.generated/endpoints.json"
  content = "${jsonencode(local.endpoints)}"
}