import os
import sys
import boto3
from requests_aws4auth import AWS4Auth
import requests
import json

region, task_name, stage, url = sys.argv[1:]

credentials = (
    boto3.Session()
    if "AWS_ACCESS_KEY_ID" in os.environ.keys() else
    boto3.Session(profile_name="sec-an")
).get_credentials()

aws_auth = AWS4Auth(credentials.access_key, credentials.secret_key, region, "es", session_token=credentials.token)

alias = f"{task_name}:data:write"

r = requests.get(f"https://{url}/_alias/{alias}", auth=aws_auth)

aliases = list(json.loads(r.text).keys())

if len(aliases) != 1:
    raise ValueError(f"More than one index found for alias {alias}")

print(f"{{\"index\":{json.dumps(aliases[0])}}}")
