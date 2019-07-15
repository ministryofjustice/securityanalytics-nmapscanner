# TODO I wish we could use these along with modules with a count argument, but terraform doesn't
# support that yet
locals {
  flavours   = ["history", "snapshot"]
  data_types = ["data", "os", "ports", "cves", "ssl_ciphers", "ssl_protos"]
  # Commnented out because setproduct function is only in terraform 12
  # index_patterns = "${setproduct(local.data_types, local.flavours)}"
}

module "index" {
  # two slashes are intentional: https://www.terraform.io/docs/modules/sources.html#modules-in-package-sub-directories
  source = "github.com/ministryofjustice/securityanalytics-analyticsplatform//infrastructure/elastic_index"

  # It is sometimes useful for the developers of the project to use a local version of the task
  # execution project. This enables them to develop the task execution project and the nmap scanner
  # (or other future tasks), at the same time, without requiring the task execution changes to be
  # pushed to master. Unfortunately you can not interpolate variables to generate source locations, so
  # devs will have to comment in/out this line as and when they need
  # source = "../../../securityanalytics-analyticsplatform/infrastructure/elastic_index"
  app_name = var.app_name

  aws_region       = var.aws_region
  ssm_source_stage = var.ssm_source_stage
  index_file       = "${path.module}/indexes/nmap-data.index.json"
  index_name       = "data"
  task_name        = var.task_name
  es_domain        = data.aws_ssm_parameter.es_domain.value
}

module "index_pattern_history" {
  # two slashes are intentional: https://www.terraform.io/docs/modules/sources.html#modules-in-package-sub-directories
  source = "github.com/ministryofjustice/securityanalytics-analyticsplatform//infrastructure/kibana_saved_object"

  # It is sometimes useful for the developers of the project to use a local version of the task
  # execution project. This enables them to develop the task execution project and the nmap scanner
  # (or other future tasks), at the same time, without requiring the task execution changes to be
  # pushed to master. Unfortunately you can not interpolate variables to generate source locations, so
  # devs will have to comment in/out this line as and when they need
  # source = "../../../securityanalytics-analyticsplatform/infrastructure/kibana_saved_object"
  app_name = var.app_name

  aws_region           = var.aws_region
  ssm_source_stage     = var.ssm_source_stage
  object_template      = "${path.module}/indexes/nmap-data.pattern.json"
  object_substitutions = {}

  object_type  = "index-pattern"
  object_title = "${var.task_name}:data_history:read*"
  es_domain    = data.aws_ssm_parameter.es_domain.value
}

module "index_pattern_snapshot" {
  # two slashes are intentional: https://www.terraform.io/docs/modules/sources.html#modules-in-package-sub-directories
  source = "github.com/ministryofjustice/securityanalytics-analyticsplatform//infrastructure/kibana_saved_object"

  # It is sometimes useful for the developers of the project to use a local version of the task
  # execution project. This enables them to develop the task execution project and the nmap scanner
  # (or other future tasks), at the same time, without requiring the task execution changes to be
  # pushed to master. Unfortunately you can not interpolate variables to generate source locations, so
  # devs will have to comment in/out this line as and when they need
  # source = "../../../securityanalytics-analyticsplatform/infrastructure/kibana_saved_object"
  app_name = var.app_name

  aws_region           = var.aws_region
  ssm_source_stage     = var.ssm_source_stage
  object_template      = "${path.module}/indexes/nmap-data.pattern.json"
  object_substitutions = {}

  object_type  = "index-pattern"
  object_title = "${var.task_name}:data_snapshot:read*"
  es_domain    = data.aws_ssm_parameter.es_domain.value
}

module "nmap_index_os" {
  # two slashes are intentional: https://www.terraform.io/docs/modules/sources.html#modules-in-package-sub-directories
  source = "github.com/ministryofjustice/securityanalytics-analyticsplatform//infrastructure/elastic_index"

  # It is sometimes useful for the developers of the project to use a local version of the task
  # execution project. This enables them to develop the task execution project and the nmap scanner
  # (or other future tasks), at the same time, without requiring the task execution changes to be
  # pushed to master. Unfortunately you can not interpolate variables to generate source locations, so
  # devs will have to comment in/out this line as and when they need
  # source = "../../../securityanalytics-analyticsplatform/infrastructure/elastic_index"
  app_name = var.app_name

  aws_region       = var.aws_region
  ssm_source_stage = var.ssm_source_stage
  index_file       = "${path.module}/indexes/nmap-os.index.json"
  index_name       = "os"
  task_name        = var.task_name
  es_domain        = data.aws_ssm_parameter.es_domain.value
}

module "index_pattern_os_history" {
  # two slashes are intentional: https://www.terraform.io/docs/modules/sources.html#modules-in-package-sub-directories
  source = "github.com/ministryofjustice/securityanalytics-analyticsplatform//infrastructure/kibana_saved_object"

  # It is sometimes useful for the developers of the project to use a local version of the task
  # execution project. This enables them to develop the task execution project and the nmap scanner
  # (or other future tasks), at the same time, without requiring the task execution changes to be
  # pushed to master. Unfortunately you can not interpolate variables to generate source locations, so
  # devs will have to comment in/out this line as and when they need
  # source = "../../../securityanalytics-analyticsplatform/infrastructure/kibana_saved_object"
  app_name = var.app_name

  aws_region           = var.aws_region
  ssm_source_stage     = var.ssm_source_stage
  object_template      = "${path.module}/indexes/nmap-os.pattern.json"
  object_substitutions = {}

  object_type  = "index-pattern"
  object_title = "${var.task_name}:os_history:read*"
  es_domain    = data.aws_ssm_parameter.es_domain.value
}

module "index_pattern_os_snapshot" {
  # two slashes are intentional: https://www.terraform.io/docs/modules/sources.html#modules-in-package-sub-directories
  source = "github.com/ministryofjustice/securityanalytics-analyticsplatform//infrastructure/kibana_saved_object"

  # It is sometimes useful for the developers of the project to use a local version of the task
  # execution project. This enables them to develop the task execution project and the nmap scanner
  # (or other future tasks), at the same time, without requiring the task execution changes to be
  # pushed to master. Unfortunately you can not interpolate variables to generate source locations, so
  # devs will have to comment in/out this line as and when they need
  # source = "../../../securityanalytics-analyticsplatform/infrastructure/kibana_saved_object"
  app_name = var.app_name

  aws_region           = var.aws_region
  ssm_source_stage     = var.ssm_source_stage
  object_template      = "${path.module}/indexes/nmap-os.pattern.json"
  object_substitutions = {}

  object_type  = "index-pattern"
  object_title = "${var.task_name}:os_snapshot:read*"
  es_domain    = data.aws_ssm_parameter.es_domain.value
}

module "nmap_index_ports" {
  # two slashes are intentional: https://www.terraform.io/docs/modules/sources.html#modules-in-package-sub-directories
  source = "github.com/ministryofjustice/securityanalytics-analyticsplatform//infrastructure/elastic_index"

  # It is sometimes useful for the developers of the project to use a local version of the task
  # execution project. This enables them to develop the task execution project and the nmap scanner
  # (or other future tasks), at the same time, without requiring the task execution changes to be
  # pushed to master. Unfortunately you can not interpolate variables to generate source locations, so
  # devs will have to comment in/out this line as and when they need
  # source = "../../../securityanalytics-analyticsplatform/infrastructure/elastic_index"
  app_name = var.app_name

  aws_region       = var.aws_region
  ssm_source_stage = var.ssm_source_stage
  index_file       = "${path.module}/indexes/nmap-ports.index.json"
  index_name       = "ports"
  task_name        = var.task_name
  es_domain        = data.aws_ssm_parameter.es_domain.value
}

module "index_pattern_ports_history" {
  # two slashes are intentional: https://www.terraform.io/docs/modules/sources.html#modules-in-package-sub-directories
  source = "github.com/ministryofjustice/securityanalytics-analyticsplatform//infrastructure/kibana_saved_object"

  # It is sometimes useful for the developers of the project to use a local version of the task
  # execution project. This enables them to develop the task execution project and the nmap scanner
  # (or other future tasks), at the same time, without requiring the task execution changes to be
  # pushed to master. Unfortunately you can not interpolate variables to generate source locations, so
  # devs will have to comment in/out this line as and when they need
  # source = "../../../securityanalytics-analyticsplatform/infrastructure/kibana_saved_object"
  app_name = var.app_name

  aws_region           = var.aws_region
  ssm_source_stage     = var.ssm_source_stage
  object_template      = "${path.module}/indexes/nmap-ports.pattern.json"
  object_substitutions = {}

  object_type  = "index-pattern"
  object_title = "${var.task_name}:ports_history:read*"
  es_domain    = data.aws_ssm_parameter.es_domain.value
}

module "index_pattern_ports_snapshot" {
  # two slashes are intentional: https://www.terraform.io/docs/modules/sources.html#modules-in-package-sub-directories
  source = "github.com/ministryofjustice/securityanalytics-analyticsplatform//infrastructure/kibana_saved_object"

  # It is sometimes useful for the developers of the project to use a local version of the task
  # execution project. This enables them to develop the task execution project and the nmap scanner
  # (or other future tasks), at the same time, without requiring the task execution changes to be
  # pushed to master. Unfortunately you can not interpolate variables to generate source locations, so
  # devs will have to comment in/out this line as and when they need
  # source = "../../../securityanalytics-analyticsplatform/infrastructure/kibana_saved_object"
  app_name = var.app_name

  aws_region           = var.aws_region
  ssm_source_stage     = var.ssm_source_stage
  object_template      = "${path.module}/indexes/nmap-ports.pattern.json"
  object_substitutions = {}

  object_type  = "index-pattern"
  object_title = "${var.task_name}:ports_snapshot:read*"
  es_domain    = data.aws_ssm_parameter.es_domain.value
}

module "nmap_index_cves" {
  # two slashes are intentional: https://www.terraform.io/docs/modules/sources.html#modules-in-package-sub-directories
  source = "github.com/ministryofjustice/securityanalytics-analyticsplatform//infrastructure/elastic_index"

  # It is sometimes useful for the developers of the project to use a local version of the task
  # execution project. This enables them to develop the task execution project and the nmap scanner
  # (or other future tasks), at the same time, without requiring the task execution changes to be
  # pushed to master. Unfortunately you can not interpolate variables to generate source locations, so
  # devs will have to comment in/out this line as and when they need
  # source = "../../../securityanalytics-analyticsplatform/infrastructure/elastic_index"
  app_name = var.app_name

  aws_region       = var.aws_region
  ssm_source_stage = var.ssm_source_stage
  index_file       = "${path.module}/indexes/nmap-cves.index.json"
  index_name       = "cves"
  task_name        = var.task_name
  es_domain        = data.aws_ssm_parameter.es_domain.value
}

module "index_pattern_cves_history" {
  # two slashes are intentional: https://www.terraform.io/docs/modules/sources.html#modules-in-package-sub-directories
  source = "github.com/ministryofjustice/securityanalytics-analyticsplatform//infrastructure/kibana_saved_object"

  # It is sometimes useful for the developers of the project to use a local version of the task
  # execution project. This enables them to develop the task execution project and the nmap scanner
  # (or other future tasks), at the same time, without requiring the task execution changes to be
  # pushed to master. Unfortunately you can not interpolate variables to generate source locations, so
  # devs will have to comment in/out this line as and when they need
  # source = "../../../securityanalytics-analyticsplatform/infrastructure/kibana_saved_object"
  app_name = var.app_name

  aws_region           = var.aws_region
  ssm_source_stage     = var.ssm_source_stage
  object_template      = "${path.module}/indexes/nmap-cves.pattern.json"
  object_substitutions = {}

  object_type  = "index-pattern"
  object_title = "${var.task_name}:cves_history:read*"
  es_domain    = data.aws_ssm_parameter.es_domain.value
}

module "index_pattern_cves_snapshot" {
  # two slashes are intentional: https://www.terraform.io/docs/modules/sources.html#modules-in-package-sub-directories
  source = "github.com/ministryofjustice/securityanalytics-analyticsplatform//infrastructure/kibana_saved_object"

  # It is sometimes useful for the developers of the project to use a local version of the task
  # execution project. This enables them to develop the task execution project and the nmap scanner
  # (or other future tasks), at the same time, without requiring the task execution changes to be
  # pushed to master. Unfortunately you can not interpolate variables to generate source locations, so
  # devs will have to comment in/out this line as and when they need
  # source = "../../../securityanalytics-analyticsplatform/infrastructure/kibana_saved_object"
  app_name = var.app_name

  aws_region           = var.aws_region
  ssm_source_stage     = var.ssm_source_stage
  object_template      = "${path.module}/indexes/nmap-cves.pattern.json"
  object_substitutions = {}

  object_type  = "index-pattern"
  object_title = "${var.task_name}:cves_snapshot:read*"
  es_domain    = data.aws_ssm_parameter.es_domain.value
}

module "nmap_index_ssl_protos" {
  # two slashes are intentional: https://www.terraform.io/docs/modules/sources.html#modules-in-package-sub-directories
  source = "github.com/ministryofjustice/securityanalytics-analyticsplatform//infrastructure/elastic_index"

  # It is sometimes useful for the developers of the project to use a local version of the task
  # execution project. This enables them to develop the task execution project and the nmap scanner
  # (or other future tasks), at the same time, without requiring the task execution changes to be
  # pushed to master. Unfortunately you can not interpolate variables to generate source locations, so
  # devs will have to comment in/out this line as and when they need
  # source = "../../../securityanalytics-analyticsplatform/infrastructure/elastic_index"
  app_name = var.app_name

  aws_region       = var.aws_region
  ssm_source_stage = var.ssm_source_stage
  index_file       = "${path.module}/indexes/nmap-ssl_protos.index.json"
  index_name       = "ssl_protos"
  task_name        = var.task_name
  es_domain        = data.aws_ssm_parameter.es_domain.value
}

module "index_pattern_ssl_protos_history" {
  # two slashes are intentional: https://www.terraform.io/docs/modules/sources.html#modules-in-package-sub-directories
  source = "github.com/ministryofjustice/securityanalytics-analyticsplatform//infrastructure/kibana_saved_object"

  # It is sometimes useful for the developers of the project to use a local version of the task
  # execution project. This enables them to develop the task execution project and the nmap scanner
  # (or other future tasks), at the same time, without requiring the task execution changes to be
  # pushed to master. Unfortunately you can not interpolate variables to generate source locations, so
  # devs will have to comment in/out this line as and when they need
  # source = "../../../securityanalytics-analyticsplatform/infrastructure/kibana_saved_object"
  app_name = var.app_name

  aws_region           = var.aws_region
  ssm_source_stage     = var.ssm_source_stage
  object_template      = "${path.module}/indexes/nmap-ssl_protos.pattern.json"
  object_substitutions = {}

  object_type  = "index-pattern"
  object_title = "${var.task_name}:ssl_protos_history:read*"
  es_domain    = data.aws_ssm_parameter.es_domain.value
}

module "index_pattern_ssl_protos_snapshot" {
  # two slashes are intentional: https://www.terraform.io/docs/modules/sources.html#modules-in-package-sub-directories
  source = "github.com/ministryofjustice/securityanalytics-analyticsplatform//infrastructure/kibana_saved_object"

  # It is sometimes useful for the developers of the project to use a local version of the task
  # execution project. This enables them to develop the task execution project and the nmap scanner
  # (or other future tasks), at the same time, without requiring the task execution changes to be
  # pushed to master. Unfortunately you can not interpolate variables to generate source locations, so
  # devs will have to comment in/out this line as and when they need
  # source = "../../../securityanalytics-analyticsplatform/infrastructure/kibana_saved_object"
  app_name = var.app_name

  aws_region           = var.aws_region
  ssm_source_stage     = var.ssm_source_stage
  object_template      = "${path.module}/indexes/nmap-ssl_protos.pattern.json"
  object_substitutions = {}

  object_type  = "index-pattern"
  object_title = "${var.task_name}:ssl_protos_snapshot:read*"
  es_domain    = data.aws_ssm_parameter.es_domain.value
}

module "nmap_index_ssl_ciphers" {
  # two slashes are intentional: https://www.terraform.io/docs/modules/sources.html#modules-in-package-sub-directories
  source = "github.com/ministryofjustice/securityanalytics-analyticsplatform//infrastructure/elastic_index"

  # It is sometimes useful for the developers of the project to use a local version of the task
  # execution project. This enables them to develop the task execution project and the nmap scanner
  # (or other future tasks), at the same time, without requiring the task execution changes to be
  # pushed to master. Unfortunately you can not interpolate variables to generate source locations, so
  # devs will have to comment in/out this line as and when they need
  # source = "../../../securityanalytics-analyticsplatform/infrastructure/elastic_index"
  app_name = var.app_name

  aws_region       = var.aws_region
  ssm_source_stage = var.ssm_source_stage
  index_file       = "${path.module}/indexes/nmap-ssl_ciphers.index.json"
  index_name       = "ssl_ciphers"
  task_name        = var.task_name
  es_domain        = data.aws_ssm_parameter.es_domain.value
}

module "index_pattern_ssl_ciphers_history" {
  # two slashes are intentional: https://www.terraform.io/docs/modules/sources.html#modules-in-package-sub-directories
  source = "github.com/ministryofjustice/securityanalytics-analyticsplatform//infrastructure/kibana_saved_object"

  # It is sometimes useful for the developers of the project to use a local version of the task
  # execution project. This enables them to develop the task execution project and the nmap scanner
  # (or other future tasks), at the same time, without requiring the task execution changes to be
  # pushed to master. Unfortunately you can not interpolate variables to generate source locations, so
  # devs will have to comment in/out this line as and when they need
  # source = "../../../securityanalytics-analyticsplatform/infrastructure/kibana_saved_object"
  app_name = var.app_name

  aws_region           = var.aws_region
  ssm_source_stage     = var.ssm_source_stage
  object_template      = "${path.module}/indexes/nmap-ssl_ciphers.pattern.json"
  object_substitutions = {}

  object_type  = "index-pattern"
  object_title = "${var.task_name}:ssl_ciphers_history:read*"
  es_domain    = data.aws_ssm_parameter.es_domain.value
}

module "index_pattern_ssl_ciphers_snapshot" {
  # two slashes are intentional: https://www.terraform.io/docs/modules/sources.html#modules-in-package-sub-directories
  source = "github.com/ministryofjustice/securityanalytics-analyticsplatform//infrastructure/kibana_saved_object"

  # It is sometimes useful for the developers of the project to use a local version of the task
  # execution project. This enables them to develop the task execution project and the nmap scanner
  # (or other future tasks), at the same time, without requiring the task execution changes to be
  # pushed to master. Unfortunately you can not interpolate variables to generate source locations, so
  # devs will have to comment in/out this line as and when they need
  # source = "../../../securityanalytics-analyticsplatform/infrastructure/kibana_saved_object"
  app_name = var.app_name

  aws_region           = var.aws_region
  ssm_source_stage     = var.ssm_source_stage
  object_template      = "${path.module}/indexes/nmap-ssl_ciphers.pattern.json"
  object_substitutions = {}

  object_type  = "index-pattern"
  object_title = "${var.task_name}:ssl_ciphers_snapshot:read*"
  es_domain    = data.aws_ssm_parameter.es_domain.value
}

module "nmap_index_ssl_cert" {
  # two slashes are intentional: https://www.terraform.io/docs/modules/sources.html#modules-in-package-sub-directories
  source = "github.com/ministryofjustice/securityanalytics-analyticsplatform//infrastructure/elastic_index"

  # It is sometimes useful for the developers of the project to use a local version of the task
  # execution project. This enables them to develop the task execution project and the nmap scanner
  # (or other future tasks), at the same time, without requiring the task execution changes to be
  # pushed to master. Unfortunately you can not interpolate variables to generate source locations, so
  # devs will have to comment in/out this line as and when they need
  # source = "../../../securityanalytics-analyticsplatform/infrastructure/elastic_index"
  app_name = var.app_name

  aws_region       = var.aws_region
  ssm_source_stage = var.ssm_source_stage
  index_file       = "${path.module}/indexes/nmap-ssl_cert.index.json"
  index_name       = "ssl_cert"
  task_name        = var.task_name
  es_domain        = data.aws_ssm_parameter.es_domain.value
}

module "index_pattern_ssl_cert_history" {
  # two slashes are intentional: https://www.terraform.io/docs/modules/sources.html#modules-in-package-sub-directories
  source = "github.com/ministryofjustice/securityanalytics-analyticsplatform//infrastructure/kibana_saved_object"

  # It is sometimes useful for the developers of the project to use a local version of the task
  # execution project. This enables them to develop the task execution project and the nmap scanner
  # (or other future tasks), at the same time, without requiring the task execution changes to be
  # pushed to master. Unfortunately you can not interpolate variables to generate source locations, so
  # devs will have to comment in/out this line as and when they need
  # source = "../../../securityanalytics-analyticsplatform/infrastructure/kibana_saved_object"
  app_name = var.app_name

  aws_region           = var.aws_region
  ssm_source_stage     = var.ssm_source_stage
  object_template      = "${path.module}/indexes/nmap-ssl_cert.pattern.json"
  object_substitutions = {}

  object_type  = "index-pattern"
  object_title = "${var.task_name}:ssl_cert_history:read*"
  es_domain    = data.aws_ssm_parameter.es_domain.value
}

module "index_pattern_ssl_cert_snapshot" {
  # two slashes are intentional: https://www.terraform.io/docs/modules/sources.html#modules-in-package-sub-directories
  source = "github.com/ministryofjustice/securityanalytics-analyticsplatform//infrastructure/kibana_saved_object"

  # It is sometimes useful for the developers of the project to use a local version of the task
  # execution project. This enables them to develop the task execution project and the nmap scanner
  # (or other future tasks), at the same time, without requiring the task execution changes to be
  # pushed to master. Unfortunately you can not interpolate variables to generate source locations, so
  # devs will have to comment in/out this line as and when they need
  # source = "../../../securityanalytics-analyticsplatform/infrastructure/kibana_saved_object"
  app_name = var.app_name

  aws_region           = var.aws_region
  ssm_source_stage     = var.ssm_source_stage
  object_template      = "${path.module}/indexes/nmap-ssl_cert.pattern.json"
  object_substitutions = {}

  object_type  = "index-pattern"
  object_title = "${var.task_name}:ssl_cert_snapshot:read*"
  es_domain    = data.aws_ssm_parameter.es_domain.value
}
