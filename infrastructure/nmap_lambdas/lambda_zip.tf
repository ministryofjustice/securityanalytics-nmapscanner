locals {
  nmap_zip = "../.generated/sec-an-nmap.zip"
}

data "external" "nmap_zip" {
  program = [
    "python",
    "../shared_code/python/package_lambda.py",
    "-x",
    "${local.nmap_zip}",
    "${path.module}/packaging.config.json",
    "../Pipfile.lock",
  ]
}
