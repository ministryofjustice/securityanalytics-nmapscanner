data "aws_ssm_parameter" "results_bucket_id" {
  name = "/${var.app_name}/${terraform.workspace}/s3/results/id"
}


data "template_file" "docker_file" {
  template = "${file("docker_image/Dockerfile.template")}"
  vars {
    results_bucket_arn = "${var.results_bucket_arn}"
  }
}

resource "local_file" "docker_file" {
  filename = "../.generated/Dockerfile"
  content = "${data.template_file.docker_file.rendered}"
}

data "template_file" "task_script" {
  template = "${file("docker_image/task_script.sh.template")}"
  vars {
    task_name = "${var.task_name}"
    bucket_name = "${data.aws_ssm_parameter.results_bucket_id.value}"
  }
}

resource "local_file" "task_script" {
  filename = "../.generated/task_script.sh"
  content = "${data.template_file.docker_file.rendered}"
}