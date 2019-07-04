#############################################
# Backend setup
#############################################

terraform {
  backend "s3" {
    # This is configured using the -backend-config parameter with 'terraform init'
    bucket         = ""
    dynamodb_table = "sec-an-terraform-locks"
    key            = "nmap/terraform.tfstate"
    region         = "eu-west-2" # london
  }
}

#############################################
# Variables used across the whole application
#############################################

variable "aws_region" {
  default = "eu-west-2" # london
}

# Set this variable with your app.auto.tfvars file or enter it manually when prompted
variable "app_name" {
}

variable "task_name" {
  default = "nmap"
}

variable "account_id" {
}

variable "ssm_source_stage" {
  default = "DEFAULT"
}

variable "known_deployment_stages" {
  type    = list(string)
  default = ["dev", "qa", "prod"]
}

variable "scan_hosts" {
  type    = list(string)
  default = ["scanme.nmap.org"]
}

variable "use_xray" {
  type        = string
  description = "Whether to instrument lambdas"
  default     = false
}

provider "aws" {
  version = "~> 2.13"
  region  = var.aws_region

  # N.B. To support all authentication use cases, we expect the local environment variables to provide auth details.
  allowed_account_ids = [var.account_id]
}

#############################################
# Resources
#############################################

locals {
  # When a build is done as a user locally, or when building a stage e.g. dev/qa/prod we use
  # the workspace name e.g. progers or dev
  # When the circle ci build is run we override the var.ssm_source_stage to explicitly tell it
  # to use the resources in dev. Change
  ssm_source_stage = var.ssm_source_stage == "DEFAULT" ? terraform.workspace : var.ssm_source_stage

  transient_workspace = false == contains(var.known_deployment_stages, terraform.workspace)
}

module "docker_image" {
  source             = "./docker_image"
  app_name           = var.app_name
  task_name          = var.task_name
  results_bucket_arn = module.nmap_task.results_bucket_arn
  results_bucket_id  = module.nmap_task.results_bucket_id
  ssm_source_stage   = local.ssm_source_stage
}

locals {
  nmap_zip = "../.generated/sec-an-nmap.zip"
}

data "external" "nmap_zip" {
  program = [
    "python",
    "../shared_code/python/package_lambda.py",
    "-x",
    local.nmap_zip,
    "${path.module}/packaging.config.json",
    "../Pipfile.lock",
  ]
}

module "nmap_task" {
  source = "../../securityanalytics-taskexecution/infrastructure/ecs_task"

  account_id          = var.account_id
  aws_region          = var.aws_region
  app_name            = var.app_name
  task_name           = var.task_name
  use_xray            = var.use_xray
  transient_workspace = local.transient_workspace
  ssm_source_stage    = local.ssm_source_stage

  # TODO add separate settings for results and scan lambdas
  cpu    = "1024"
  memory = "2048"

  # ECS
  docker_file          = module.docker_image.docker_file
  docker_combined_hash = "${module.docker_image.docker_hash}:${module.docker_image.sources_hash}"
  param_parse_lambda   = "nmap_scanner.invoke"

  # Results
  lambda_zip           = local.nmap_zip
  lambda_hash          = data.external.nmap_zip.result.hash
  results_parse_lambda = "results_parser.invoke"

  # General
  subscribe_input_to_scan_initiator = true
  subscribe_es_to_output            = true
}

//module "elastic_resources" {
//  source           = "./elastic_resources"
//  aws_region       = var.aws_region
//  app_name         = var.app_name
//  task_name        = var.task_name
//  ssm_source_stage = local.ssm_source_stage
//}

module "sample_api" {
  source = "./sample_api"

  account_id          = var.account_id
  aws_region          = var.aws_region
  app_name            = var.app_name
  task_name           = var.task_name
  use_xray            = var.use_xray
  transient_workspace = local.transient_workspace
  ssm_source_stage    = local.ssm_source_stage
  lambda_zip          = local.nmap_zip
}

