variable "app_name" {
  type = "string"
}

variable "ssm_source_stage" {
  type = "string"
}

variable "subscribe_to_scheduler" {
  type    = "string"
  default = true
}

variable "scan_trigger_queue_arn" {
  type = "string"
}

variable "scan_trigger_queue_url" {
  type = "string"
}
