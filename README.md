[![CircleCI](https://circleci.com/gh/ministryofjustice/securityanalytics-nmapscanner.svg?style=svg)](https://circleci.com/gh/ministryofjustice/securityanalytics-nmapscanner)

# Sample project

At present this project is being used as a sample project. It contains a simple lambda which will be unit and 

# Testing

These instructions are for Powershell, you'll need a few paths set up and to go into the pipenv environment to run the tests:

```
$Env:PYTHONPATH="C:\dev\MoJ-repo\securityanalytics-nmapscanner;C:\dev\MoJ-repo\securityanalytics-nmapscanner/shared_code/python"
$Env:PIPENV_VENV_IN_PROJECT="true"
$Env:AWS_REGION="eu-west-2"
pipenv install --dev
pipenv shell
pytest tests -s
```

This runs all of the tests. Note that you can use `-m` to reduce the scope e.g. `-m unit` to run unit tests and `-m integration`.