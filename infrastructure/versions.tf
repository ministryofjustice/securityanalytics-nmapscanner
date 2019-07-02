terraform {
  required_version = ">= 0.12"
}

provider "null" {
  version = "~> 2.1"
}

provider "template" {
  version = "~> 2.1"
}

provider "external" {
  version = "~> 1.1"
}

provider "local" {
  version = "~> 1.2"
}