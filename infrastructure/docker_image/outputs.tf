data "local_file" "task_script" {
  depends_on = ["local_file.task_script", "data.local_file.docker_file"]
  filename = "../.generated/task_script.sh"
}

data "local_file" "docker_file" {
  depends_on = ["local_file.docker_file"]
  filename = "../.generated/Dockerfile"
}

# read this from the output file to ensure it is created first.
# The two data sources above are required to ensure that the files are written out before returning the output
output "sources_hash" {
  value = "${md5(data.local_file.task_script.content)}"
}

# needed to ensure the template is written out first
output "docker_file" {
  value = "${data.local_file.docker_file.filename}"
}

output "docker_hash" {
  value = "${md5(data.local_file.docker_file.content)}"
}