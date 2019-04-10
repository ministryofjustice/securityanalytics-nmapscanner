data "template_file" "docker_file" {
  template = "${file("docker_image/Dockerfile.template")}"

  vars {
    results_bucket_arn = "${var.results_bucket_arn}"
  }
}

locals {
  docker_file = "../.generated/Dockerfile"
}

resource "local_file" "docker_file" {
  filename = "${local.docker_file}"
  content  = "${data.template_file.docker_file.rendered}"
}

data "template_file" "task_script" {
  template = "${file("docker_image/task_script.sh.template")}"

  vars {
    bucket_name = "${var.results_bucket_id}"
  }
}

resource "local_file" "task_script" {
  filename = "../.generated/task_script.sh"
  content  = "${data.template_file.task_script.rendered}"
}
