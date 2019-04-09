#############################################
# Backend setup
#############################################

terraform {
  backend "s3" {
    bucket         = "sec-an-terraform-state"
    dynamodb_table = "sec-an-terraform-locks"
    key            = "nmap/terraform.tfstate"
    region         = "eu-west-2"                   # london
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

provider "aws" {
  region              = "${var.aws_region}"
  profile             = "${var.app_name}"
  allowed_account_ids = ["${var.account_id}"]
}

#############################################
# Resources
#############################################

data "aws_ssm_parameter" "results_bucket_arn" {
  name = "/${var.app_name}/${terraform.workspace}/s3/results/arn"
}

module "docker_image" {
  source = "docker_image"
  app_name = "${var.app_name}"
  task_name = "${var.task_name}"
  results_bucket_arn = "${data.aws_ssm_parameter.results_bucket_arn.value}"
}

module "nmap_task" {
  source   = "github.com/ministryofjustice/securityanalytics-taskexecution//infrastructure/ecs_task"
  app_name = "${var.app_name}"
  aws_region = "${var.aws_region}"
  cpu = "1024"
  memory = "2048"
  docker_dir = "${dirname(module.docker_image.docker_file)}"
  results_bucket_arn = "${data.aws_ssm_parameter.results_bucket_arn.value}"
  task_name = "${var.task_name}"
  sources_hash = "${module.docker_image.sources_hash}"
  docker_hash = "${module.docker_image.docker_hash}"
}
