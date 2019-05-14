from unittest import mock
import pytest
import os
import json
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
TEST_DIR = "./tests/results_parser/"

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
def test_parses_hosts_and_ports():
    results_parser.ssm_client.get_parameters.return_value = ssm_return_vals()

    # load sample results file and make mock return it
    sample_file_name = f"{TEST_DIR}scanme.nmap.org-2019-04-17T12_55_56Z-nmap.xml.tar.gz"
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
                    "object": {"key": "scanme.nmap.org-2019-04-17T12%3A55%3A56Z-nmap.xml.tar.gz"}
                }}
            ]
        }, mock.MagicMock())

    results_parser.sns_client.publish.assert_called_once_with(
        **expected_pub("me-twice:data:write", {
            "scan_id": "scanme.nmap.org-2019-04-17T12:55:56Z-nmap",
            "scan_start_time": "2019-04-17T12:55:57Z",
            "scan_end_time": "2019-04-17T12:56:27Z",
            "address": "45.33.32.156",
            "address_type": "ipv4",
            "host_names": [
                {
                    "host_name": "scanme.nmap.org",
                    "host_name_type": "user"
                },
                {
                    "host_name": "scanme.nmap.org",
                    "host_name_type": "PTR"
                }
            ],
            "ports": [
                {
                    "port_id": "22",
                    "protocol": "tcp",
                    "status": "open",
                    "status_reason": "syn-ack",
                    "service": "ssh",
                    "product": "OpenSSH",
                    "version": "6.6.1p1 Ubuntu 2ubuntu2.11",
                    "extra_info": "Ubuntu Linux; protocol 2.0",
                    "os_type": "Linux",
                    "cpes": ["cpe:/a:openbsd:openssh:6.6.1p1", "cpe:/o:linux:linux_kernel"]
                },
                {
                    "port_id": "80",
                    "protocol": "tcp",
                    "status": "open",
                    "status_reason": "syn-ack",
                    "service": "http",
                    "product": "Apache httpd",
                    "version": "2.4.7",
                    "extra_info": "(Ubuntu)",
                    "os_type": None,
                    "cpes": ["cpe:/a:apache:http_server:2.4.7"],
                    "http-server-header": [
                        "Apache/2.4.7 (Ubuntu)"
                    ]
                },
                {
                    "port_id": "9929",
                    "protocol": "tcp",
                    "status": "open",
                    "status_reason": "syn-ack",
                    "service": "nping-echo",
                    "product": "Nping echo",
                    "version": None,
                    "extra_info": None,
                    "os_type": None
                },
                {

                    "port_id": "31337",
                    "protocol": "tcp",
                    "status": "open",
                    "status_reason": "syn-ack",
                    "service": "tcpwrapped",
                    "product": None,
                    "version": None,
                    "extra_info": None,
                    "os_type": None
                }
            ],
            "os_info": [
                {
                    "os_name": "Linux 4.4",
                    "os_accuracy": "97",
                    "os_classes": [
                        {
                            "os_class_type": "general purpose",
                            "os_class_vendor": "Linux",
                            "os_class_os_family": "Linux",
                            "os_class_os_gen": "4.X",
                            "os_class_accuracy": "97",
                            "os_cpes": [
                                "cpe:/o:linux:linux_kernel:4.4"
                            ]
                        }
                    ]
                },
                {
                    "os_name": "Linux 3.11 - 4.1",
                    "os_accuracy": "93",
                    "os_classes": [
                        {
                            "os_class_type": "general purpose",
                            "os_class_vendor": "Linux",
                            "os_class_os_family": "Linux",
                            "os_class_os_gen": "3.X",
                            "os_class_accuracy": "93",
                            "os_cpes": [
                                "cpe:/o:linux:linux_kernel:3"
                            ]
                        },
                        {
                            "os_class_type": "general purpose",
                            "os_class_vendor": "Linux",
                            "os_class_os_family": "Linux",
                            "os_class_os_gen": "4.X",
                            "os_class_accuracy": "93",
                            "os_cpes": [
                                "cpe:/o:linux:linux_kernel:4"
                            ]
                        }
                    ]
                }
            ],
            "host_scan_start_time": "2019-04-17T12:55:57Z",
            "host_scan_end_time": "2019-04-17T12:56:27Z",
            "status": "up",
            "status_reason": "echo-reply",
            "uptime": "686432",
            "last_boot": "Tue Apr  9 14:15:55 2019",
            "summary_most_likely_os": "Linux 4.4",
            "summary_most_likely_os_accuracy": 97
        })
    )


@pytest.mark.unit
@serialise_mocks()
@resetting_mocks(
    results_parser.sns_client,
    results_parser.s3_client,
    results_parser.ssm_client
)
def test_parses_tls_info():
    results_parser.ssm_client.get_parameters.return_value = ssm_return_vals()

    # load sample results file and make mock return it
    sample_file_name = f"{TEST_DIR}34868089-d02d-4414-b9c9-b0d5247d2a32-2019-04-26T16_36_15Z-nmap.xml.tar.gz"
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
                    "object": {"key": "34868089-d02d-4414-b9c9-b0d5247d2a32-2019-04-26T16%3A36%3A15Z-nmap.xml.tar.gz"}
                }}
            ]
        }, mock.MagicMock())

    results_parser.sns_client.publish.assert_called_once()
    call_details = json.loads(results_parser.sns_client.publish.call_args[1]['Message'])
    assert call_details["summary_lowest_ssl_strength"] == "A"
    assert call_details["summary_lowest_ssl_proto"] == "TLSv1.2"
    for port in call_details["ports"]:
        if port["port_id"] == "443":
            assert port["ssl_least_strength"] == "A"
            assert port["ssl_enum_ciphers"] == [
                {
                    "protocol": "TLSv1.2",
                    "ciphers": [
                        {
                            "kex_info": "ecdh_x25519",
                            "strength": "A",
                            "name": "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"
                        },
                        {
                            "kex_info": "ecdh_x25519",
                            "strength": "A",
                            "name": "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"
                        },
                        {
                            "kex_info": "ecdh_x25519",
                            "strength": "A",
                            "name": "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256"
                        },
                        {
                            "kex_info": "ecdh_x25519",
                            "strength": "A",
                            "name": "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384"
                        },
                        {
                            "kex_info": "ecdh_x25519",
                            "strength": "A",
                            "name": "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA"
                        },
                        {
                            "kex_info": "ecdh_x25519",
                            "strength": "A",
                            "name": "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA"
                        },
                        {
                            "kex_info": "rsa 2048",
                            "strength": "A",
                            "name": "TLS_RSA_WITH_AES_128_GCM_SHA256"
                        },
                        {
                            "kex_info": "rsa 2048",
                            "strength": "A",
                            "name": "TLS_RSA_WITH_AES_128_CBC_SHA"
                        },
                        {
                            "kex_info": "rsa 2048",
                            "strength": "A",
                            "name": "TLS_RSA_WITH_AES_256_CBC_SHA"
                        }
                    ],
                    "cipher_preference": "server"
                }
            ]


@pytest.mark.unit
@serialise_mocks()
@resetting_mocks(
    results_parser.sns_client,
    results_parser.s3_client,
    results_parser.ssm_client
)
def test_parses_cve_info():
    results_parser.ssm_client.get_parameters.return_value = ssm_return_vals()

    # load sample results file and make mock return it
    sample_file_name = f"{TEST_DIR}981cee6c-ed04-4a68-a3ef-49f683d814dc-2019-04-30T12_46_50Z-nmap.xml.tar.gz"
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
                    "object": {"key": "981cee6c-ed04-4a68-a3ef-49f683d814dc-2019-04-30T12%3A46%3A50Z-nmap.xml.tar.gz"}
                }}
            ]
        }, mock.MagicMock())

    results_parser.sns_client.publish.assert_called_once()
    call_details = json.loads(results_parser.sns_client.publish.call_args[1]['Message'])
    assert call_details["summary_highest_cve_severity"] == 7.5
    for port in call_details["ports"]:
        if port["port_id"] == "80":
            assert port["cve_vulners"] == [
                {
                    "cpe_key": "cpe:/a:apache:http_server:2.4.7",
                    "cves": [
                        {
                            "cve_code": "CVE-2017-7679",
                            "cve_severity": "7.5"
                        },
                        {
                            "cve_code": "CVE-2018-1312",
                            "cve_severity": "6.8"
                        },
                        {
                            "cve_code": "CVE-2017-15715",
                            "cve_severity": "6.8"
                        },
                        {
                            "cve_code": "CVE-2014-0226",
                            "cve_severity": "6.8"
                        },
                        {
                            "cve_code": "CVE-2017-9788",
                            "cve_severity": "6.4"
                        },
                        {
                            "cve_code": "CVE-2014-0231",
                            "cve_severity": "5.0"
                        },
                        {
                            "cve_code": "CVE-2017-15710",
                            "cve_severity": "5.0"
                        },
                        {
                            "cve_code": "CVE-2018-17199",
                            "cve_severity": "5.0"
                        },
                        {
                            "cve_code": "CVE-2013-6438",
                            "cve_severity": "5.0"
                        },
                        {
                            "cve_code": "CVE-2017-9798",
                            "cve_severity": "5.0"
                        },
                        {
                            "cve_code": "CVE-2016-8743",
                            "cve_severity": "5.0"
                        },
                        {
                            "cve_code": "CVE-2016-2161",
                            "cve_severity": "5.0"
                        },
                        {
                            "cve_code": "CVE-2014-3523",
                            "cve_severity": "5.0"
                        },
                        {
                            "cve_code": "CVE-2014-0098",
                            "cve_severity": "5.0"
                        },
                        {
                            "cve_code": "CVE-2016-0736",
                            "cve_severity": "5.0"
                        },
                        {
                            "cve_code": "CVE-2016-4975",
                            "cve_severity": "4.3"
                        },
                        {
                            "cve_code": "CVE-2014-0117",
                            "cve_severity": "4.3"
                        },
                        {
                            "cve_code": "CVE-2014-8109",
                            "cve_severity": "4.3"
                        },
                        {
                            "cve_code": "CVE-2015-3185",
                            "cve_severity": "4.3"
                        },
                        {
                            "cve_code": "CVE-2014-0118",
                            "cve_severity": "4.3"
                        },
                        {
                            "cve_code": "CVE-2018-1283",
                            "cve_severity": "3.5"
                        },
                        {
                            "cve_code": "CVE-2016-8612",
                            "cve_severity": "3.3"
                        }
                    ]
                }
            ]


@pytest.mark.unit
@pytest.mark.regression
@serialise_mocks()
@resetting_mocks(
    results_parser.sns_client,
    results_parser.s3_client,
    results_parser.ssm_client
)
def test_parses_multiple_os_cpes_regression_sa_44():
    results_parser.ssm_client.get_parameters.return_value = ssm_return_vals()

    # load sample results file and make mock return it
    sample_file_name = f"{TEST_DIR}b2b68f48-cc77-4ee1-aead-945cb6095f2f-2-2019-05-03T07_19_58Z-nmap.xml.tar.gz"
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
                    "object": {
                        "key": "b2b68f48-cc77-4ee1-aead-945cb6095f2f-2-2019-05-03T07%3A19%3A58Z-nmap.xml.tar.gz"}
                }}
            ]
        }, mock.MagicMock())

    results_parser.sns_client.publish.assert_called_once()


@pytest.mark.unit
@pytest.mark.regression
@serialise_mocks()
@resetting_mocks(
    results_parser.sns_client,
    results_parser.s3_client,
    results_parser.ssm_client
)
def test_parses_no_timestamps_when_host_down_regression_sa_43():
    results_parser.ssm_client.get_parameters.return_value = ssm_return_vals()

    # load sample results file and make mock return it
    sample_file_name = f"{TEST_DIR}e2791270-b64e-4ec8-969c-87af81f169ce-1-2019-05-03T07_16_50Z-nmap.xml.tar.gz"
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
                    "object": {
                        "key": "e2791270-b64e-4ec8-969c-87af81f169ce-1-2019-05-03T07%3A16%3A50Z-nmap.xml.tar.gz"}
                }}
            ]
        }, mock.MagicMock())

    results_parser.sns_client.publish.assert_called_once()


@pytest.mark.unit
@pytest.mark.regression
@serialise_mocks()
@resetting_mocks(
    results_parser.sns_client,
    results_parser.s3_client,
    results_parser.ssm_client
)
def test_parses_os_but_no_osmatch_regression_sa_45():
    results_parser.ssm_client.get_parameters.return_value = ssm_return_vals()

    # load sample results file and make mock return it
    sample_file_name = f"{TEST_DIR}dcca306c-15de-4b22-ae81-a24af6f29de8-1-2019-05-03T08_35_50Z-nmap.xml.tar.gz"
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
                    "object": {
                        "key": "dcca306c-15de-4b22-ae81-a24af6f29de8-1-2019-05-03T08%3A35%3A50Z-nmap.xml.tar.gz"}
                }}
            ]
        }, mock.MagicMock())

    results_parser.sns_client.publish.assert_called_once()


@pytest.mark.unit
@pytest.mark.regression
@serialise_mocks()
@resetting_mocks(
    results_parser.sns_client,
    results_parser.s3_client,
    results_parser.ssm_client
)
def test_parses_http_server_parse_regression_sa_46():
    results_parser.ssm_client.get_parameters.return_value = ssm_return_vals()

    # load sample results file and make mock return it
    sample_file_name = f"{TEST_DIR}8278563c-08dc-468e-9a21-04efb43af885-1-2019-05-03T09_43_02Z-nmap.xml.tar.gz"
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
                    "object": {
                        "key": "8278563c-08dc-468e-9a21-04efb43af885-1-2019-05-03T09%3A43%3A02Z-nmap.xml.tar.gz"}
                }}
            ]
        }, mock.MagicMock())

    results_parser.sns_client.publish.assert_called_once()


@pytest.mark.unit
@serialise_mocks()
@resetting_mocks(
    results_parser.sns_client,
    results_parser.s3_client,
    results_parser.ssm_client
)
def test_parses_ssl_certs():
    results_parser.ssm_client.get_parameters.return_value = ssm_return_vals()
    # load sample results file and make mock return it
    sample_file_name = f"{TEST_DIR}test_ssl_cert.xml.tar.gz"
    with open(sample_file_name, "rb") as sample_data:
        results_parser.s3_client.get_object.return_value = {
            "Body": StreamingBody(sample_data, os.stat(sample_file_name).st_size)
        }

        results_parser.parse_results({
            "Records": [
                {"s3": {
                    "bucket": {"name": "test_bucket"},
                    "object": {"key": "test_ssl_cert.xml.tar.gz"}
                }}
            ]
        }, mock.MagicMock())

    results_parser.sns_client.publish.assert_called_once()
    call_details = json.loads(results_parser.sns_client.publish.call_args[1]['Message'])

    for port in call_details["ports"]:
        if port["port_id"] == "443":
            assert port["ssl_cert"] == {
                "issuer": {
                    "countryName": "US",
                    "commonName": "Let's Encrypt Authority X3",
                    "organizationName": "Let's Encrypt"
                },
                "subject": {
                    "commonName": "scottlogic.com"
                },
                "validity": {
                    "notAfter": "2019-06-29T06:52:46",
                    "notBefore": "2019-03-31T06:52:46"
                },
                "extensions": [{
                    "name": "X509v3 Subject Alternative Name",
                    "value": "DNS:scottlogic.com"
                }]
            }
