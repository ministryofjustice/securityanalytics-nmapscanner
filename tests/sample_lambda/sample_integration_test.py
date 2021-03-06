import pytest
import os
import boto3
import requests
import json
from requests_aws4auth import AWS4Auth


# TODO move this to shared layer
def get_auth():
    session = boto3.Session() \
        if 'AWS_ACCESS_KEY_ID' in os.environ \
        else boto3.Session(profile_name='sec-an')
    credentials = session.get_credentials()
    return AWS4Auth(
        credentials.access_key,
        credentials.secret_key,
        region,
        "execute-api",
        session_token=credentials.token)


region = os.environ['AWS_REGION']


# TODO make this into a reusable util
def get_url(endpoint, method):
    return json.load(open('.generated/endpoints.json'))[endpoint][method]


@pytest.mark.integration
def test_integration():
    url = get_url('sample', 'GET')
    response = requests.get(url, auth=get_auth())
    print(f"response: {response.text}")
    assert 200 == response.status_code
    assert "hello lambda world" in response.text
