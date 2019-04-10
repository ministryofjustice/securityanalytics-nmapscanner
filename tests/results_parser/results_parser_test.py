from unittest import mock
import pytest
import os
import itertools
from test_utils.test_utils import resetting_mocks, serialise_mocks
from utils.json_serialisation import dumps
from botocore.response import StreamingBody


TEST_ENV = {
    "REGION": "eu-west-wood",
    "STAGE": "door",
    "APP_NAME": "me-once",
    "TASK_NAME": "me-twice",
}

with mock.patch.dict(os.environ, TEST_ENV), \
     mock.patch("boto3.client") as boto_client, \
     mock.patch("utils.json_serialisation.stringify_all"):
    # ensure each client is a different mock
    boto_client.side_effect = (mock.MagicMock() for _ in itertools.count())
    from results_parser import results_parser


@mock.patch.dict(os.environ, TEST_ENV)
def ssm_return_vals():
    stage = os.environ["STAGE"]
    app_name = os.environ["APP_NAME"]
    task_name = os.environ["TASK_NAME"]
    ssm_prefix = f"/{app_name}/{stage}"
    return {
        "Parameters": [
            {"Name": f"{ssm_prefix}/tasks/{task_name}/results/arn", "Value": "test_topic"}
        ]
    }


def expected_pub(doc_type, doc):
    return {
        "TopicArn": "test_topic",
        "Subject": doc_type,
        "Message": dumps(doc)
    }


@pytest.mark.unit
@serialise_mocks()
@resetting_mocks(
    results_parser.sns_client, 
    results_parser.s3_client, 
    results_parser.ssm_client
)
def test_parses_():
    results_parser.ssm_client.get_parameters.return_value = ssm_return_vals()

    # load sample results file and make mock return it
    sample_file_name = "./tests/results_parser/scanme.nmap.org-2019-04-17T12_55_56Z-nmap.xml.tar.gz"
    with open(sample_file_name, "rb") as sample_data:
        results_parser.s3_client.get_object.return_value = {
            "Body": StreamingBody(sample_data, os.stat(sample_file_name).st_size)
        }

        results_parser.parse_results({
            "Records": [
                {"s3": {
                    "bucket": {"name": "test_bucket"},
                    # Please note that the / characters in the key are replaced with %2F, the key is
                    # urlencoded
                    "object": {"key": "nmap%2Fscanme.nmap.org-2019-04-17T12%3A55%3A56Z-nmap.xml.tar.gz"}
                }}
            ]
        }, mock.MagicMock())

    expected = [
        mock.call(**exp) for exp in
        [
            expected_pub("host", {
                "time": "2019-04-17T12:56:27Z", "address": "45.33.32.156", "address_type": "ipv4"}),
            expected_pub("host_name", {
                "time": "2019-04-17T12:56:27Z",
                "address": "45.33.32.156",
                "address_type": "ipv4",
                "host_name": "scanme.nmap.org",
                "host_name_type": "user"
            }),
            expected_pub("host_name", {
                "time": "2019-04-17T12:56:27Z",
                "address": "45.33.32.156",
                "address_type": "ipv4",
                "host_name": "scanme.nmap.org",
                "host_name_type": "PTR"
            }),
            expected_pub("port", {
                "time": "2019-04-17T12:56:27Z",
                "address": "45.33.32.156",
                "address_type": "ipv4",
                "protocol": "tcp",
                "state": "open",
                "service": "ssh",
                "product": "OpenSSH",
                "version": "6.6.1p1 Ubuntu 2ubuntu2.11",
                "extra_info": "Ubuntu Linux; protocol 2.0",
                "os_type": "Linux",
                "port_id": "22"
            }),
            expected_pub("port", {
                "time": "2019-04-17T12:56:27Z",
                "address": "45.33.32.156",
                "address_type": "ipv4",
                "protocol": "tcp",
                "state": "open",
                "service": "http",
                "product": "Apache httpd",
                "version": "2.4.7",
                "extra_info": "(Ubuntu)",
                "os_type": None,
                "port_id": "80"
            }),
            expected_pub("port", {
                "time": "2019-04-17T12:56:27Z",
                "address": "45.33.32.156",
                "address_type": "ipv4",
                "protocol": "tcp",
                "state": "open",
                "service": "nping-echo",
                "product": "Nping echo",
                "version": None,
                "extra_info": None,
                "os_type": None,
                "port_id": "9929"
            }),
            expected_pub("port", {
                "time": "2019-04-17T12:56:27Z",
                "address": "45.33.32.156",
                "address_type": "ipv4",
                "protocol": "tcp",
                "state": "open",
                "service": "tcpwrapped",
                "product": None,
                "version": None,
                "extra_info": None,
                "os_type": None,
                "port_id": "31337"
            })
        ]
    ]

    assert expected == results_parser.sns_client.publish.call_args_list
