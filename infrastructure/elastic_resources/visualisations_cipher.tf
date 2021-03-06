module "severe_cipher_total" {
  # two slashes are intentional: https://www.terraform.io/docs/modules/sources.html#modules-in-package-sub-directories
  source = "github.com/ministryofjustice/securityanalytics-analyticsplatform//infrastructure/kibana_saved_object"

  # It is sometimes useful for the developers of the project to use a local version of the task
  # execution project. This enables them to develop the task execution project and the nmap scanner
  # (or other future tasks), at the same time, without requiring the task execution changes to be
  # pushed to master. Unfortunately you can not interpolate variables to generate source locations, so
  # devs will have to comment in/out this line as and when they need
  # source = "../../../securityanalytics-analyticsplatform/infrastructure/kibana_saved_object"
  app_name = var.app_name

  aws_region       = var.aws_region
  ssm_source_stage = var.ssm_source_stage
  object_template  = "${path.module}/visualisations/ssl_cipher/ssl_cipher_total.vis.json"

  object_substitutions = {
    search_id = module.weak_ssl_cipher_search.object_id
  }

  object_type  = "visualization"
  object_title = "Total hosts with weak SSL ciphers"
  es_domain    = data.aws_ssm_parameter.es_domain.value
}

module "severe_cipher_distro" {
  # two slashes are intentional: https://www.terraform.io/docs/modules/sources.html#modules-in-package-sub-directories
  source = "github.com/ministryofjustice/securityanalytics-analyticsplatform//infrastructure/kibana_saved_object"

  # It is sometimes useful for the developers of the project to use a local version of the task
  # execution project. This enables them to develop the task execution project and the nmap scanner
  # (or other future tasks), at the same time, without requiring the task execution changes to be
  # pushed to master. Unfortunately you can not interpolate variables to generate source locations, so
  # devs will have to comment in/out this line as and when they need
  # source = "../../../securityanalytics-analyticsplatform/infrastructure/kibana_saved_object"
  app_name = var.app_name

  aws_region       = var.aws_region
  ssm_source_stage = var.ssm_source_stage
  object_template  = "${path.module}/visualisations/ssl_cipher/ssl_cipher_distro.vis.json"

  object_substitutions = {
    search_id = module.weak_ssl_cipher_search.object_id
  }

  object_type  = "visualization"
  object_title = "Distribution of weakest SSL ciphers"
  es_domain    = data.aws_ssm_parameter.es_domain.value
}

module "severe_cipher_table" {
  # two slashes are intentional: https://www.terraform.io/docs/modules/sources.html#modules-in-package-sub-directories
  source = "github.com/ministryofjustice/securityanalytics-analyticsplatform//infrastructure/kibana_saved_object"

  # It is sometimes useful for the developers of the project to use a local version of the task
  # execution project. This enables them to develop the task execution project and the nmap scanner
  # (or other future tasks), at the same time, without requiring the task execution changes to be
  # pushed to master. Unfortunately you can not interpolate variables to generate source locations, so
  # devs will have to comment in/out this line as and when they need
  # source = "../../../securityanalytics-analyticsplatform/infrastructure/kibana_saved_object"
  app_name = var.app_name

  aws_region       = var.aws_region
  ssm_source_stage = var.ssm_source_stage
  object_template  = "${path.module}/visualisations/ssl_cipher/ssl_cipher_table.vis.json"

  object_substitutions = {
    search_id = module.weak_ssl_cipher_search.object_id
  }

  object_type  = "visualization"
  object_title = "Table of hosts with weak SSL ciphers"
  es_domain    = data.aws_ssm_parameter.es_domain.value
}

