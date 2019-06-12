#!/bin/sh

if [ $# -ne 2 ]; then
    echo "Syntax: setup.sh <app_name> <tf_workspace>"
    sleep 30
    exit
fi
echo "** Running setup.sh in $PWD (app_name=$1, workspace=$2) **"
# update with the latest shared code first:
git submodule init
git submodule update --remote
git submodule sync

export PIPENV_VENV_IN_PROJECT=true
pipenv install --dev

# since the terraform step uses python code, it requires we run in an activated venv
pipenv run $(pwd)/terraform.sh $1 $2

wait
