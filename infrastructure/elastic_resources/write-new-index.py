import os
import sys
import boto3
from requests_aws4auth import AWS4Auth
import requests
import json

if len(sys.argv[1:]) not in range(6, 8):
    raise ValueError(f"write-new-index.py region app_name task_name index_hash index_file url old_index")

region, app_name, task_name, index_hash, index_file_name, url = sys.argv[1:7]
old_index = sys.argv[7] if len(sys.argv) == 8 else None

credentials = (
    boto3.Session()
    if "AWS_ACCESS_KEY_ID" in os.environ.keys() else
    boto3.Session(profile_name=app_name)
).get_credentials()

aws_auth = AWS4Auth(
    credentials.access_key,
    credentials.secret_key,
    region,
    "es",
    session_token=credentials.token
)

write_alias = f"{task_name}:data:write"
read_alias = f"{task_name}:data:read"
new_index = f"{task_name}:data:{index_hash}"


def add_new_index(index_file):
    if old_index != new_index:
        index_doc = json.load(index_file)
        r = requests.put(f"https://{url}/{new_index}", auth=aws_auth, json=index_doc)

        if not r.ok:
            raise ValueError(f"Failure response ({r.status_code}): {r.text}")

        print(f"Added new index {new_index}")
    else:
        print(f"Index {new_index} already existed, ignoring")


def update_aliases():
    actions = []
    alias_doc = {
        "actions": actions
    }
    if old_index and old_index != new_index:
        actions.append({"remove": {"index": old_index, "alias": write_alias}})

    actions.append({"add": {"index": new_index, "alias": write_alias}})
    actions.append({"add": {"index": new_index, "alias": read_alias}})

    r = requests.post(f"https://{url}/_aliases", auth=aws_auth, json=alias_doc)

    if not r.ok:
        raise ValueError(f"Failure response ({r.status_code}): {r.text}")

    print(f"Updated write alias {write_alias} to point to {new_index}")
    print(f"Added read alias {read_alias} to point to {new_index}")


def start_re_index():
    if old_index:
        re_index_doc = {
          "source": {
            "index": old_index
          },
          "dest": {
            "index": new_index
          }
        }
        r = requests.post(f"https://{url}/_reindex", auth=aws_auth, json=re_index_doc)

        if not r.ok:
            raise ValueError(f"Failure response ({r.status_code}): {r.text}")

        print(f"Started re-indexing from {old_index} to {new_index}")


with open(index_file_name, 'r') as index_file:
    add_new_index(index_file)
    update_aliases()
    start_re_index()


