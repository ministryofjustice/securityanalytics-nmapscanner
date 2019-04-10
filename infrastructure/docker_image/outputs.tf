output "sources_hash" {
  value = "${md5(data.template_file.task_script.rendered)}"
}

output "docker_file" {
  value = "${local.docker_file}"
}

output "docker_hash" {
  value = "${md5(data.template_file.docker_file.rendered)}"
}
