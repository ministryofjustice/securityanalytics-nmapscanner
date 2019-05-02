data "local_file" "index_definition" {
  filename = "${path.module}/nmap-data.index.json"
}

data "external" "current_index" {
  program = [
    "python",
    "${path.module}/get-current-write-index.py",
    "${var.aws_region}",
    "${var.app_name}",
    "${var.task_name}",
    "${data.aws_ssm_parameter.es_domain.value}",
  ]
}

locals {
  index_hash     = "${md5(data.local_file.index_definition.content)}"
  old_index_hash = "${data.external.current_index.result.index}"
}

resource "null_resource" "setup_new_index" {
  triggers {
    index_hash = "${local.index_hash}"
    foo        = "${timestamp()}"
  }

  provisioner "local-exec" {
    # Doesn't just write the new one, it also updates the aliases and starts re-indexing
    command = "python ${path.module}/write-new-index.py ${var.aws_region} ${var.app_name} ${var.task_name} ${local.index_hash} ${data.local_file.index_definition.filename} ${data.aws_ssm_parameter.es_domain.value} ${local.old_index_hash}"
  }
}
