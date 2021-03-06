module "moj_dashboard" {
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
  object_template  = "${path.module}/dashboards/moj.dash.json"

  object_substitutions = {
    cve_total     = module.severe_cve_total.object_id
    cve_distro    = module.severe_cve_distro.object_id
    cve_table     = module.severe_cve_table.object_id
    proto_total   = module.severe_proto_total.object_id
    proto_distro  = module.severe_proto_distro.object_id
    proto_table   = module.severe_proto_table.object_id
    cipher_total  = module.severe_cipher_total.object_id
    cipher_distro = module.severe_cipher_distro.object_id
    cipher_table  = module.severe_cipher_table.object_id
  }

  object_type  = "dashboard"
  object_title = "MoJ Security Analaysis Dashboard 1"
  es_domain    = data.aws_ssm_parameter.es_domain.value
}

module "moj_dashboard_2" {
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
  object_template  = "${path.module}/dashboards/moj2.dash.json"

  object_substitutions = {
    common_ciphers = module.common_ciphers.object_id
    common_vulns   = module.common_vulns.object_id
    likely_os      = module.likely_os.object_id
    services       = module.services.object_id
    proto_all      = module.proto_all.object_id
    vulns_severity = module.vulns_severity.object_id
    host_status    = module.host_status.object_id
    host_scanned   = module.host_scanned.object_id
  }

  object_type  = "dashboard"
  object_title = "MoJ Security Analaysis Dashboard 2"
  es_domain    = data.aws_ssm_parameter.es_domain.value
}

module "moj_dashboard_3" {
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
  object_template  = "${path.module}/dashboards/moj3.dash.json"

  object_substitutions = {
    ssl_expiry_distro = module.ssl_expiry_distro.object_id
    ssl_expiry_table  = module.ssl_expiry_table.object_id
    open_ports_distro = module.open_ports_distro.object_id
    open_ports_table  = module.open_ports_table.object_id
  }

  object_type  = "dashboard"
  object_title = "SSL Expiry"
  es_domain    = data.aws_ssm_parameter.es_domain.value
}


module "moj_dash_ai_open_ports" {
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
  object_template  = "${path.module}/dashboards/ai_open_ports.dash.json"

  object_substitutions = {
    open_ports_ai_table = module.open_ports_ai_table.object_id
    open_ports_cloud    = module.open_ports_cloud.object_id
    open_ports_filter   = module.open_ports_filter.object_id
  }

  object_type  = "dashboard"
  object_title = "Actionable Items: Open ports"
  es_domain    = data.aws_ssm_parameter.es_domain.value
}


module "moj_dash_ai_ssl_protocols" {
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
  object_template  = "${path.module}/dashboards/ai_ssl_proto_support.dash.json"

  object_substitutions = {
    ssl_proto_ai_table  = module.ssl_proto_ai_table.object_id
    ssl_proto_ai_filter = module.ssl_proto_ai_filter.object_id
  }

  object_type  = "dashboard"
  object_title = "Actionable items: SSL protocol support"
  es_domain    = data.aws_ssm_parameter.es_domain.value
}

module "moj_dash_ai_cve_severity" {
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
  object_template  = "${path.module}/dashboards/ai_cve_severity.dash.json"

  object_substitutions = {
    severe_cve_ai_filter = module.severe_cve_ai_filter.object_id
    severe_cve_ai_table  = module.severe_cve_ai_table.object_id
  }

  object_type  = "dashboard"
  object_title = "Actionable items: CVE Severity"
  es_domain    = data.aws_ssm_parameter.es_domain.value
}


module "moj_dash_ai_ssl_expiry" {
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
  object_template  = "${path.module}/dashboards/ai_ssl_expiry.dash.json"

  object_substitutions = {
    ai_expiry_dates_filter = module.ai_expiry_dates_filter.object_id
    ai_expiry_dates_table  = module.ai_expiry_dates_table.object_id
  }

  object_type  = "dashboard"
  object_title = "Actionable items: SSL expiry"
  es_domain    = data.aws_ssm_parameter.es_domain.value
}
