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

module "elastic_resources" {
  source           = "./elastic_resources"
  aws_region       = var.aws_region
  app_name         = var.app_name
  task_name        = var.task_name
  ssm_source_stage = local.ssm_source_stage
}

module "nmap_task" {
  # two slashes are intentional: https://www.terraform.io/docs/modules/sources.html#modules-in-package-sub-directories
  source = "github.com/ministryofjustice/securityanalytics-taskexecution//infrastructure/ecs_task"

  # It is sometimes useful for the developers of the project to use a local version of the task
  # execution project. This enables them to develop the task execution project and the nmap scanner
  # (or other future tasks), at the same time, without requiring the task execution changes to be
  # pushed to master. Unfortunately you can not interpolate variables to generate source locations, so
  # devs will have to comment in/out this line as and when they need
  # source = "../../securityanalytics-taskexecution/infrastructure/ecs_task"

  app_name                      = var.app_name
  aws_region                    = var.aws_region
  use_xray                      = var.use_xray
  cpu                           = "1024"
  memory                        = "2048"
  docker_dir                    = replace(dirname(module.docker_image.docker_file), "\\", "/")
  task_name                     = var.task_name
  sources_hash                  = module.docker_image.sources_hash
  docker_hash                   = module.docker_image.docker_hash
  subscribe_elastic_to_notifier = true
  account_id                    = var.account_id
  ssm_source_stage              = local.ssm_source_stage
  transient_workspace           = local.transient_workspace
  results_parser_arn            = module.nmap_lambda.results_parser_arn
}

module "subscribe_scheduler" {
  source                 = "./scan_initiation_subscription"
  app_name               = var.app_name
  ssm_source_stage       = local.ssm_source_stage
  subscribe_to_scheduler = true
  scan_trigger_queue_arn = module.nmap_task.task_queue
  scan_trigger_queue_url = module.nmap_task.task_queue_url
}

module "nmap_lambda" {
  source                   = "./nmap_lambdas"
  app_name                 = var.app_name
  task_name                = var.task_name
  results_bucket           = module.nmap_task.results_bucket_id
  results_bucket_arn       = module.nmap_task.results_bucket_arn
  aws_region               = var.aws_region
  account_id               = var.account_id
  use_xray                 = var.use_xray
  queue_arn                = module.nmap_task.task_queue
  ssm_source_stage         = local.ssm_source_stage
  task_queue_consumer_role = module.nmap_task.task_queue_consumer
  results_parser_role      = module.nmap_task.results_parser
  results_parser_dlq       = module.nmap_task.results_dead_letter_queue
}

