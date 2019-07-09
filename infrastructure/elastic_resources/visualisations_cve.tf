module "severe_cve_total" {
  // two slashes are intentional: https://www.terraform.io/docs/modules/sources.html#modules-in-package-sub-directories
  source = "github.com/ministryofjustice/securityanalytics-analyticsplatform//infrastructure/kibana_saved_object"

  // It is sometimes useful for the developers of the project to use a local version of the task
  // execution project. This enables them to develop the task execution project and the nmap scanner
  // (or other future tasks), at the same time, without requiring the task execution changes to be
  // pushed to master. Unfortunately you can not interpolate variables to generate source locations, so
  // devs will have to comment in/out this line as and when they need
  //  source = "../../../securityanalytics-analyticsplatform/infrastructure/kibana_saved_object"
  app_name = var.app_name

  aws_region       = var.aws_region
  ssm_source_stage = var.ssm_source_stage
  object_template  = "${path.module}/visualisations/cve/serious_vulnerabilities_total.vis.json"

  object_substitutions = {
    severity  = 7
    search_id = module.severe_cve_search.object_id
  }

  object_type  = "visualization"
  object_title = "Total hosts with severe CVEs"
  es_domain    = data.aws_ssm_parameter.es_domain.value
}

module "severe_cve_distro" {
  // two slashes are intentional: https://www.terraform.io/docs/modules/sources.html#modules-in-package-sub-directories
  source = "github.com/ministryofjustice/securityanalytics-analyticsplatform//infrastructure/kibana_saved_object"

  // It is sometimes useful for the developers of the project to use a local version of the task
  // execution project. This enables them to develop the task execution project and the nmap scanner
  // (or other future tasks), at the same time, without requiring the task execution changes to be
  // pushed to master. Unfortunately you can not interpolate variables to generate source locations, so
  // devs will have to comment in/out this line as and when they need
  //  source = "../../../securityanalytics-analyticsplatform/infrastructure/kibana_saved_object"
  app_name = var.app_name

  aws_region       = var.aws_region
  ssm_source_stage = var.ssm_source_stage
  object_template  = "${path.module}/visualisations/cve/serious_vulnerabilities_distro.vis.json"

  object_substitutions = {
    search_id = module.severe_cve_search.object_id
  }

  object_type  = "visualization"
  object_title = "Distribution of most severe CVEs"
  es_domain    = data.aws_ssm_parameter.es_domain.value
}

module "severe_cve_table" {
  // two slashes are intentional: https://www.terraform.io/docs/modules/sources.html#modules-in-package-sub-directories
  source = "github.com/ministryofjustice/securityanalytics-analyticsplatform//infrastructure/kibana_saved_object"

  // It is sometimes useful for the developers of the project to use a local version of the task
  // execution project. This enables them to develop the task execution project and the nmap scanner
  // (or other future tasks), at the same time, without requiring the task execution changes to be
  // pushed to master. Unfortunately you can not interpolate variables to generate source locations, so
  // devs will have to comment in/out this line as and when they need
  //  source = "../../../securityanalytics-analyticsplatform/infrastructure/kibana_saved_object"
  app_name = var.app_name

  aws_region       = var.aws_region
  ssm_source_stage = var.ssm_source_stage
  object_template  = "${path.module}/visualisations/cve/serious_vulnerabilities_table.vis.json"
  es_domain        = data.aws_ssm_parameter.es_domain.value
  object_substitutions = {
    search_id = module.severe_cve_search.object_id
  }

  object_type  = "visualization"
  object_title = "Table of hosts with severe CVEs"

}


module "severe_cve_ai_filter" {
  // two slashes are intentional: https://www.terraform.io/docs/modules/sources.html#modules-in-package-sub-directories
  source = "github.com/ministryofjustice/securityanalytics-analyticsplatform//infrastructure/kibana_saved_object"

  // It is sometimes useful for the developers of the project to use a local version of the task
  // execution project. This enables them to develop the task execution project and the nmap scanner
  // (or other future tasks), at the same time, without requiring the task execution changes to be
  // pushed to master. Unfortunately you can not interpolate variables to generate source locations, so
  // devs will have to comment in/out this line as and when they need
  //  source = "../../../securityanalytics-analyticsplatform/infrastructure/kibana_saved_object"
  app_name = var.app_name

  aws_region       = var.aws_region
  ssm_source_stage = var.ssm_source_stage
  object_template  = "${path.module}/visualisations/cve/ai_serious_vulnerabilities_filter.vis.json"

  object_substitutions = {
    index = module.index_pattern_snapshot.object_id
  }

  object_type  = "visualization"
  object_title = "CVE severity Filter"
  es_domain    = data.aws_ssm_parameter.es_domain.value
}


module "severe_cve_ai_table" {
  // two slashes are intentional: https://www.terraform.io/docs/modules/sources.html#modules-in-package-sub-directories
  source = "github.com/ministryofjustice/securityanalytics-analyticsplatform//infrastructure/kibana_saved_object"

  // It is sometimes useful for the developers of the project to use a local version of the task
  // execution project. This enables them to develop the task execution project and the nmap scanner
  // (or other future tasks), at the same time, without requiring the task execution changes to be
  // pushed to master. Unfortunately you can not interpolate variables to generate source locations, so
  // devs will have to comment in/out this line as and when they need
  //  source = "../../../securityanalytics-analyticsplatform/infrastructure/kibana_saved_object"
  app_name = var.app_name

  aws_region       = var.aws_region
  ssm_source_stage = var.ssm_source_stage
  object_template  = "${path.module}/visualisations/cve/ai_serious_vulnerabilities_table.vis.json"
  es_domain        = data.aws_ssm_parameter.es_domain.value
  object_substitutions = {
    index = module.index_pattern_snapshot.object_id
  }

  object_type  = "visualization"
  object_title = "Table of hosts with severe CVEs"

}
