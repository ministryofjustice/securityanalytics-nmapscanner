#!/usr/bin/sh

. ./.venv/bin/activate
export AWS_REGION=eu-west-2
export PYTHONPATH=`pwd`
export PYTHONPATH=$PYTHONPATH:shared_code
export USERNAME=builder
