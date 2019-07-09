module "severe_proto_total" {
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
  object_template  = "${path.module}/visualisations/ssl_proto/ssl_proto_total.vis.json"

  object_substitutions = {
    search_id = module.weak_ssl_proto_search.object_id
  }

  object_type  = "visualization"
  object_title = "Total hosts with weak SSL protos"
  es_domain    = data.aws_ssm_parameter.es_domain.value
}

module "severe_proto_distro" {
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
  object_template  = "${path.module}/visualisations/ssl_proto/ssl_proto_distro.vis.json"

  object_substitutions = {
    search_id = module.weak_ssl_proto_search.object_id
  }

  object_type  = "visualization"
  object_title = "Distribution of weakest SSL protos"
  es_domain    = data.aws_ssm_parameter.es_domain.value
}

module "severe_proto_table" {
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
  object_template  = "${path.module}/visualisations/ssl_proto/ssl_proto_table.vis.json"

  object_substitutions = {
    search_id = module.weak_ssl_proto_search.object_id
  }

  object_type  = "visualization"
  object_title = "Table of hosts with weak SSL protos"
  es_domain    = data.aws_ssm_parameter.es_domain.value
}


module "ssl_proto_ai_filter" {
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
  object_template  = "${path.module}/visualisations/ssl_proto/ssl_proto_ai_filter.vis.json"

  object_substitutions = {
    index = module.index_pattern_snapshot.object_id
  }

  object_type  = "visualization"
  object_title = "SSL Protocol Filter"
  es_domain    = data.aws_ssm_parameter.es_domain.value
}


module "ssl_proto_ai_table" {
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
  object_template  = "${path.module}/visualisations/ssl_proto/ssl_proto_ai_table.vis.json"

  object_substitutions = {
    index = module.index_pattern_snapshot.object_id
  }

  object_type  = "visualization"
  object_title = "Table of hosts with weak SSL protos"
  es_domain    = data.aws_ssm_parameter.es_domain.value
}

