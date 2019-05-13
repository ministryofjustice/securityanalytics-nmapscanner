module "severe_cve_search" {
  // two slashes are intentional: https://www.terraform.io/docs/modules/sources.html#modules-in-package-sub-directories
  // source = "github.com/ministryofjustice/securityanalytics-analyticsplatform//infrastructure/kibana_saved_object"

  // It is sometimes useful for the developers of the project to use a local version of the task
  // execution project. This enables them to develop the task execution project and the nmap scanner
  // (or other future tasks), at the same time, without requiring the task execution changes to be
  // pushed to master. Unfortunately you can not interpolate variables to generate source locations, so
  // devs will have to comment in/out this line as and when they need
  source = "../../../securityanalytics-analyticsplatform/infrastructure/kibana_saved_object"
  app_name                      = "${var.app_name}"
  aws_region                    = "${var.aws_region}"
  ssm_source_stage              = "${var.ssm_source_stage}"
  task_name = "${var.task_name}"
  object_template = "${path.module}/searches/serious_vulnerabilities.json"
  object_substitutions {
    severity = 7
    index = "${module.nmap_index.index_id}"
  }
  object_type = "search"
}