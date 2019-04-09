import pytest
import os
import boto3
import requests
import json
from requests_aws4auth import AWS4Auth

region = os.environ['AWS_REGION']
credentials = boto3.Session(profile_name='sec-an').get_credentials()
aws_auth = AWS4Auth(
    credentials.access_key,
    credentials.secret_key,
    region,
    "execute-api",
    session_token=credentials.token)


# TODO make this into a reusable util
def get_url(endpoint, method):
    return json.load(open('.generated/endpoints.json'))[endpoint][method]


@pytest.mark.integration
def test_integration():
    url = get_url('sample', 'GET')
    response = requests.get(url, auth=aws_auth)
    assert response.status_code == 200
    assert "hello lambda world" in response.text
