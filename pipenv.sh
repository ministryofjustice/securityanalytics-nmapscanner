cd infrastructure
terraform init -backend-config "bucket=$1-terraform-state"
terraform workspace new $2 || terraform workspace select $2
terraform apply -auto-approve -input=true

sleep 5