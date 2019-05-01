data "local_file" "index_definition" {
  filename = "elastic_resources/nmap-data.index.json"
}

data "external" "current_index" {
  program = [
    "python",
    "${path.module}/get-current-write-index.py",
    "${var.aws_region}",
    "${var.task_name}",
    "${terraform.workspace}",
    "${data.aws_ssm_parameter.es_domain.value}"
  ]
}

locals {
  index_hash = "${md5(data.local_file.index_definition.content)}"
  old_index_hash = "${data.external.current_index.result.index}"
}

resource "null_resource" "setup_new_index" {
  triggers {
    index_hash = "${local.index_hash}"
    foo = "${timestamp()}"
  }

  provisioner "local-exec" {
    command = "python ${path.module}/write-new-index.py ${local.index_hash} ${path.module}/${data.local_file.index_definition.filename} ${local.old_index_hash}"
  }
}
//
//resource "null_resource" "update_write_alias" {
//  depends_on = ["null_resource.setup_new_index"]
//  triggers {
//    index_hash = "${local.index_hash}"
//  }
//
//  provisioner "local-exec" {
//    command = "python ${path.module}/update-write-index.py ${local.old_index_hash} ${local.index_hash}"
//  }
//}
//
//resource "null_resource" "add_read_alias" {
//  depends_on = ["null_resource.setup_new_index"]
//  triggers {
//    index_hash = "${local.index_hash}"
//  }
//
//  provisioner "local-exec" {
//    command = "python ${path.module}/add-read-index.py ${local.index_hash}"
//  }
//}
//
//resource "null_resource" "start_reindex" {
//  depends_on = ["null_resource.setup_new_index", "null_resource.update_write_alias"]
//  triggers {
//    index_hash = "${local.index_hash}"
//  }
//
//  provisioner "local-exec" {
//    command = "python ${path.module}/re-index.py ${local.old_index_hash} ${local.index_hash}"
//  }
//}