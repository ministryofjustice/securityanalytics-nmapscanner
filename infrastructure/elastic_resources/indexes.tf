module "nmap_index" {
  // two slashes are intentional: https://www.terraform.io/docs/modules/sources.html#modules-in-package-sub-directories
  source = "github.com/ministryofjustice/securityanalytics-analyticsplatform//infrastructure/elastic_index"

  // It is sometimes useful for the developers of the project to use a local version of the task
  // execution project. This enables them to develop the task execution project and the nmap scanner
  // (or other future tasks), at the same time, without requiring the task execution changes to be
  // pushed to master. Unfortunately you can not interpolate variables to generate source locations, so
  // devs will have to comment in/out this line as and when they need
  //  source = "../../../securityanalytics-analyticsplatform/infrastructure/elastic_index"
  app_name = "${var.app_name}"

  aws_region       = "${var.aws_region}"
  ssm_source_stage = "${var.ssm_source_stage}"
  index_file       = "${path.module}/indexes/nmap-data.index.json"
  index_name       = "data"
  task_name        = "${var.task_name}"
}

module "index_pattern" {
  // two slashes are intentional: https://www.terraform.io/docs/modules/sources.html#modules-in-package-sub-directories
  source = "github.com/ministryofjustice/securityanalytics-analyticsplatform//infrastructure/kibana_saved_object"

  // It is sometimes useful for the developers of the project to use a local version of the task
  // execution project. This enables them to develop the task execution project and the nmap scanner
  // (or other future tasks), at the same time, without requiring the task execution changes to be
  // pushed to master. Unfortunately you can not interpolate variables to generate source locations, so
  // devs will have to comment in/out this line as and when they need
  //  source = "../../../securityanalytics-analyticsplatform/infrastructure/kibana_saved_object"
  app_name = "${var.app_name}"

  aws_region           = "${var.aws_region}"
  ssm_source_stage     = "${var.ssm_source_stage}"
  task_name            = "${var.task_name}"
  object_template      = "${path.module}/indexes/nmap-data.pattern.json"
  object_substitutions = {}

  object_type  = "index-pattern"
  object_title = "${var.task_name}:data:read*"
}

module "nmap_index_os" {
  // two slashes are intentional: https://www.terraform.io/docs/modules/sources.html#modules-in-package-sub-directories
  source = "github.com/ministryofjustice/securityanalytics-analyticsplatform//infrastructure/elastic_index"

  // It is sometimes useful for the developers of the project to use a local version of the task
  // execution project. This enables them to develop the task execution project and the nmap scanner
  // (or other future tasks), at the same time, without requiring the task execution changes to be
  // pushed to master. Unfortunately you can not interpolate variables to generate source locations, so
  // devs will have to comment in/out this line as and when they need
  //  source = "../../../securityanalytics-analyticsplatform/infrastructure/elastic_index"
  app_name = "${var.app_name}"

  aws_region       = "${var.aws_region}"
  ssm_source_stage = "${var.ssm_source_stage}"
  index_file       = "${path.module}/indexes/nmap-os.index.json"
  index_name       = "os"
  task_name        = "${var.task_name}"
}

module "index_pattern_os" {
  // two slashes are intentional: https://www.terraform.io/docs/modules/sources.html#modules-in-package-sub-directories
  source = "github.com/ministryofjustice/securityanalytics-analyticsplatform//infrastructure/kibana_saved_object"

  // It is sometimes useful for the developers of the project to use a local version of the task
  // execution project. This enables them to develop the task execution project and the nmap scanner
  // (or other future tasks), at the same time, without requiring the task execution changes to be
  // pushed to master. Unfortunately you can not interpolate variables to generate source locations, so
  // devs will have to comment in/out this line as and when they need
  //  source = "../../../securityanalytics-analyticsplatform/infrastructure/kibana_saved_object"
  app_name = "${var.app_name}"

  aws_region           = "${var.aws_region}"
  ssm_source_stage     = "${var.ssm_source_stage}"
  task_name            = "${var.task_name}"
  object_template      = "${path.module}/indexes/nmap-os.pattern.json"
  object_substitutions = {}

  object_type  = "index-pattern"
  object_title = "${var.task_name}:os:read*"
}

module "nmap_index_ports" {
  // two slashes are intentional: https://www.terraform.io/docs/modules/sources.html#modules-in-package-sub-directories
  source = "github.com/ministryofjustice/securityanalytics-analyticsplatform//infrastructure/elastic_index"

  // It is sometimes useful for the developers of the project to use a local version of the task
  // execution project. This enables them to develop the task execution project and the nmap scanner
  // (or other future tasks), at the same time, without requiring the task execution changes to be
  // pushed to master. Unfortunately you can not interpolate variables to generate source locations, so
  // devs will have to comment in/out this line as and when they need
  //  source = "../../../securityanalytics-analyticsplatform/infrastructure/elastic_index"
  app_name = "${var.app_name}"

  aws_region       = "${var.aws_region}"
  ssm_source_stage = "${var.ssm_source_stage}"
  index_file       = "${path.module}/indexes/nmap-ports.index.json"
  index_name       = "ports"
  task_name        = "${var.task_name}"
}

module "index_pattern_ports" {
  // two slashes are intentional: https://www.terraform.io/docs/modules/sources.html#modules-in-package-sub-directories
  source = "github.com/ministryofjustice/securityanalytics-analyticsplatform//infrastructure/kibana_saved_object"

  // It is sometimes useful for the developers of the project to use a local version of the task
  // execution project. This enables them to develop the task execution project and the nmap scanner
  // (or other future tasks), at the same time, without requiring the task execution changes to be
  // pushed to master. Unfortunately you can not interpolate variables to generate source locations, so
  // devs will have to comment in/out this line as and when they need
  //  source = "../../../securityanalytics-analyticsplatform/infrastructure/kibana_saved_object"
  app_name = "${var.app_name}"

  aws_region           = "${var.aws_region}"
  ssm_source_stage     = "${var.ssm_source_stage}"
  task_name            = "${var.task_name}"
  object_template      = "${path.module}/indexes/nmap-ports.pattern.json"
  object_substitutions = {}

  object_type  = "index-pattern"
  object_title = "${var.task_name}:ports:read*"
}

module "nmap_index_cves" {
  // two slashes are intentional: https://www.terraform.io/docs/modules/sources.html#modules-in-package-sub-directories
  source = "github.com/ministryofjustice/securityanalytics-analyticsplatform//infrastructure/elastic_index"

  // It is sometimes useful for the developers of the project to use a local version of the task
  // execution project. This enables them to develop the task execution project and the nmap scanner
  // (or other future tasks), at the same time, without requiring the task execution changes to be
  // pushed to master. Unfortunately you can not interpolate variables to generate source locations, so
  // devs will have to comment in/out this line as and when they need
  //  source = "../../../securityanalytics-analyticsplatform/infrastructure/elastic_index"
  app_name = "${var.app_name}"

  aws_region       = "${var.aws_region}"
  ssm_source_stage = "${var.ssm_source_stage}"
  index_file       = "${path.module}/indexes/nmap-cves.index.json"
  index_name       = "cves"
  task_name        = "${var.task_name}"
}

module "index_pattern_cves" {
  // two slashes are intentional: https://www.terraform.io/docs/modules/sources.html#modules-in-package-sub-directories
  source = "github.com/ministryofjustice/securityanalytics-analyticsplatform//infrastructure/kibana_saved_object"

  // It is sometimes useful for the developers of the project to use a local version of the task
  // execution project. This enables them to develop the task execution project and the nmap scanner
  // (or other future tasks), at the same time, without requiring the task execution changes to be
  // pushed to master. Unfortunately you can not interpolate variables to generate source locations, so
  // devs will have to comment in/out this line as and when they need
  //  source = "../../../securityanalytics-analyticsplatform/infrastructure/kibana_saved_object"
  app_name = "${var.app_name}"

  aws_region           = "${var.aws_region}"
  ssm_source_stage     = "${var.ssm_source_stage}"
  task_name            = "${var.task_name}"
  object_template      = "${path.module}/indexes/nmap-cves.pattern.json"
  object_substitutions = {}

  object_type  = "index-pattern"
  object_title = "${var.task_name}:cves:read*"
}

module "nmap_index_ssl_protos" {
  // two slashes are intentional: https://www.terraform.io/docs/modules/sources.html#modules-in-package-sub-directories
  source = "github.com/ministryofjustice/securityanalytics-analyticsplatform//infrastructure/elastic_index"

  // It is sometimes useful for the developers of the project to use a local version of the task
  // execution project. This enables them to develop the task execution project and the nmap scanner
  // (or other future tasks), at the same time, without requiring the task execution changes to be
  // pushed to master. Unfortunately you can not interpolate variables to generate source locations, so
  // devs will have to comment in/out this line as and when they need
  //  source = "../../../securityanalytics-analyticsplatform/infrastructure/elastic_index"
  app_name = "${var.app_name}"

  aws_region       = "${var.aws_region}"
  ssm_source_stage = "${var.ssm_source_stage}"
  index_file       = "${path.module}/indexes/nmap-ssl_protos.index.json"
  index_name       = "ssl_protos"
  task_name        = "${var.task_name}"
}

module "index_pattern_ssl_protos" {
  // two slashes are intentional: https://www.terraform.io/docs/modules/sources.html#modules-in-package-sub-directories
  source = "github.com/ministryofjustice/securityanalytics-analyticsplatform//infrastructure/kibana_saved_object"

  // It is sometimes useful for the developers of the project to use a local version of the task
  // execution project. This enables them to develop the task execution project and the nmap scanner
  // (or other future tasks), at the same time, without requiring the task execution changes to be
  // pushed to master. Unfortunately you can not interpolate variables to generate source locations, so
  // devs will have to comment in/out this line as and when they need
  //  source = "../../../securityanalytics-analyticsplatform/infrastructure/kibana_saved_object"
  app_name = "${var.app_name}"

  aws_region           = "${var.aws_region}"
  ssm_source_stage     = "${var.ssm_source_stage}"
  task_name            = "${var.task_name}"
  object_template      = "${path.module}/indexes/nmap-ssl_protos.pattern.json"
  object_substitutions = {}

  object_type  = "index-pattern"
  object_title = "${var.task_name}:ssl_protos:read*"
}

module "nmap_index_ssl_ciphers" {
  // two slashes are intentional: https://www.terraform.io/docs/modules/sources.html#modules-in-package-sub-directories
  source = "github.com/ministryofjustice/securityanalytics-analyticsplatform//infrastructure/elastic_index"

  // It is sometimes useful for the developers of the project to use a local version of the task
  // execution project. This enables them to develop the task execution project and the nmap scanner
  // (or other future tasks), at the same time, without requiring the task execution changes to be
  // pushed to master. Unfortunately you can not interpolate variables to generate source locations, so
  // devs will have to comment in/out this line as and when they need
  //  source = "../../../securityanalytics-analyticsplatform/infrastructure/elastic_index"
  app_name = "${var.app_name}"

  aws_region       = "${var.aws_region}"
  ssm_source_stage = "${var.ssm_source_stage}"
  index_file       = "${path.module}/indexes/nmap-ssl_ciphers.index.json"
  index_name       = "ssl_ciphers"
  task_name        = "${var.task_name}"
}

module "index_pattern_ssl_ciphers" {
  // two slashes are intentional: https://www.terraform.io/docs/modules/sources.html#modules-in-package-sub-directories
  source = "github.com/ministryofjustice/securityanalytics-analyticsplatform//infrastructure/kibana_saved_object"

  // It is sometimes useful for the developers of the project to use a local version of the task
  // execution project. This enables them to develop the task execution project and the nmap scanner
  // (or other future tasks), at the same time, without requiring the task execution changes to be
  // pushed to master. Unfortunately you can not interpolate variables to generate source locations, so
  // devs will have to comment in/out this line as and when they need
  //  source = "../../../securityanalytics-analyticsplatform/infrastructure/kibana_saved_object"
  app_name = "${var.app_name}"

  aws_region           = "${var.aws_region}"
  ssm_source_stage     = "${var.ssm_source_stage}"
  task_name            = "${var.task_name}"
  object_template      = "${path.module}/indexes/nmap-ssl_ciphers.pattern.json"
  object_substitutions = {}

  object_type  = "index-pattern"
  object_title = "${var.task_name}:ssl_ciphers:read*"
}
