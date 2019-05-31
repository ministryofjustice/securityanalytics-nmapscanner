data "aws_ssm_parameter" "scan_initiation_topic" {
  name = "/${var.app_name}/${var.ssm_source_stage}/scheduler/scan_initiator_topic/arn"
}