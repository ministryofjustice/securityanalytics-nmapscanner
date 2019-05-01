#############################################
# Backend setup
#############################################

terraform {
  backend "s3" {
    bucket         = "sec-an-terraform-state"
    dynamodb_table = "sec-an-terraform-locks"
    key            = "nmap/terraform.tfstate"
    region         = "eu-west-2"              # london
    profile        = "sec-an"
  }
}

#############################################
# Variables used across the whole application
#############################################

variable "aws_region" {
  default = "eu-west-2" # london
}

variable "app_name" {
  default = "sec-an"
}

variable "task_name" {
  default = "nmap"
}

variable "account_id" {}

variable "ssm_source_stage" {
  default = "DEFAULT"
}

variable "known_deployment_stages" {
  type    = "list"
  default = ["dev", "qa", "prod"]
}

variable "scan_hosts" {
  type    = "list"
  default = ["scanme.nmap.org"]
}

provider "aws" {
  region              = "${var.aws_region}"
  profile             = "${var.app_name}"
  allowed_account_ids = ["${var.account_id}"]
}

#############################################
# Resources
#############################################

locals {
  # When a build is done as a user locally, or when building a stage e.g. dev/qa/prod we use
  # the workspace name e.g. progers or dev
  # When the circle ci build is run we override the var.ssm_source_stage to explicitly tell it
  # to use the resources in dev. Change
  ssm_source_stage = "${var.ssm_source_stage == "DEFAULT" ? terraform.workspace : var.ssm_source_stage}"
}

module "docker_image" {
  source             = "docker_image"
  app_name           = "${var.app_name}"
  task_name          = "${var.task_name}"
  results_bucket_arn = "${module.nmap_task.results_bucket_arn}"
  results_bucket_id  = "${module.nmap_task.results_bucket_id}"
  ssm_source_stage   = "${local.ssm_source_stage}"
}

module "nmap_task" {
  source = "github.com/ministryofjustice/securityanalytics-taskexecution/infrastructure/ecs_task"

  // It is sometimes useful for the developers of the project to use a local version of the task
  // execution project. This enables them to develop the task execution project and the nmap scanner
  // (or other future tasks), at the same time, without requiring the task execution changes to be
  // pushed to master. Unfortunately you can not interpolate variables to generate source locations, so
  // devs will have to comment in/out this line as and when they need
  // source = "../../securityanalytics-taskexecution/infrastructure/ecs_task"

  app_name                      = "${var.app_name}"
  aws_region                    = "${var.aws_region}"
  cpu                           = "1024"
  memory                        = "2048"
  docker_dir                    = "${dirname(module.docker_image.docker_file)}"
  task_name                     = "${var.task_name}"
  sources_hash                  = "${module.docker_image.sources_hash}"
  docker_hash                   = "${module.docker_image.docker_hash}"
  subscribe_elastic_to_notifier = true
  account_id                    = "${var.account_id}"
  ssm_source_stage              = "${local.ssm_source_stage}"
  transient_workspace           = "${!contains(var.known_deployment_stages, terraform.workspace)}"
}

module "nmap_task_scheduler" {
  source = "github.com/ministryofjustice/securityanalytics-taskexecution/infrastructure/scheduler"

  // It is sometimes useful for the developers of the project to use a local version of the task
  // execution project. This enables them to develop the task execution project and the nmap scanner
  // (or other future tasks), at the same time, without requiring the task execution changes to be
  // pushed to master. Unfortunately you can not interpolate variables to generate source locations, so
  // devs will have to comment in/out this line as and when they need
  // source = "../../securityanalytics-taskexecution/infrastructure/scheduler"

  app_name            = "${var.app_name}"
  task_name           = "${var.task_name}"
  scan_hosts          = "${var.scan_hosts}"
  queue_url           = "${module.nmap_task.task_queue_url}"
  queue_arn           = "${module.nmap_task.task_queue}"
  transient_workspace = "${!contains(var.known_deployment_stages, terraform.workspace)}"
}

resource "aws_sqs_queue_policy" "nmap_cwe_sqs_rule" {
  queue_url = "${module.nmap_task.task_queue_url}"

  policy = <<POLICY
  {
  "Version": "2012-10-17",
  "Id": "sqspolicy",
  "Statement": [
    {
      "Sid": "TrustCWEToSendEventsToMyQueue",
      "Effect": "Allow",
      "Principal": {
        "Service": "events.amazonaws.com"
      },
      "Action": "SQS:SendMessage",
      "Resource": "${module.nmap_task.task_queue}"


    }
  ]
}
POLICY
}
