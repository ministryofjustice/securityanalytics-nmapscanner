data "aws_ssm_parameter" "utils_layer" {
  name = "/${var.app_name}/${var.ssm_source_stage}/lambda/layers/utils/arn"
}

data "aws_ssm_parameter" "api_gateway" {
  name = "/${var.app_name}/${var.ssm_source_stage}/api/private/name"
}

data "aws_ssm_parameter" "dead_letter_bucket_name" {
  name = "/${var.app_name}/${var.ssm_source_stage}/s3/dead_letters/name"
}

data "aws_ssm_parameter" "dead_letter_bucket_arn" {
  name = "/${var.app_name}/${var.ssm_source_stage}/s3/dead_letters/arn"
}