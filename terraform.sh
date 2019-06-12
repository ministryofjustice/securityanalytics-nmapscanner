#!/bin/sh

cd infrastructure
echo "** Running terraform.sh in $PWD (app_name=$1, workspace=$2) **"
if [[ "$OSTYPE" == "darwin"* ]]; then
    # MacOS sets the maximum file limit to 256 - there are some parts of the build script that run in parallel
    # or touch lots of files at the same time - boosting this to 4096 allows this to happen and stops the build failing
    ulimit -n 4096
fi
terraform init -backend-config "bucket=$1-terraform-state"
terraform workspace new $2 || terraform workspace select $2
terraform get --update
terraform apply -auto-approve -input=true -var app_name=$1
wait
# pause in case the user is watching output
sleep 5
