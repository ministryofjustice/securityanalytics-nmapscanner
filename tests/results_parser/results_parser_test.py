from unittest.mock import patch, MagicMock, call, Mock
import pytest
import os
from test_utils.test_utils import serialise_mocks, coroutine_of, resetting_mocks
from utils.json_serialisation import dumps
from botocore.response import StreamingBody
from itertools import count

TEST_ENV = {
    "REGION": "eu-west-wood",
    "STAGE": "door",
    "APP_NAME": "me-once",
    "TASK_NAME": "me-twice"
}
TEST_DIR = "./tests/results_parser/"

with patch("utils.json_serialisation.stringify_all"), \
        patch("utils.scan_results.ResultsContext") as results_context_constructor:
    from results_parser import NmapResultsParser

    @patch.dict(os.environ, TEST_ENV)
    def ssm_return_vals():
        stage = os.environ["STAGE"]
        app_name = os.environ["APP_NAME"]
        task_name = os.environ["TASK_NAME"]
        ssm_prefix = f"/{app_name}/{stage}"
        return coroutine_of({
            "Parameters": [
                {"Name": f"{ssm_prefix}/tasks/{task_name}/results/arn", "Value": "test_topic_arn"},
                {"Name": f"{ssm_prefix}/tasks/{task_name}/s3/results/id", "Value": "test_topic_id"}
            ]
        })


    def expected_pub(doc_type, doc):
        return {
            "TopicArn": "test_topic_arn",
            "Subject": doc_type,
            "Message": dumps(doc)
        }


    def filter_tested_interactions(collections, methods, mock_mgr):
        actual_calls = [
            (name, args, kwargs)
            for (name, args, kwargs) in mock_mgr.mock_calls
            if (name == "post_results" and args[0] in collections) or
               (name in methods)
        ]
        return actual_calls


    @resetting_mocks(results_context_constructor)
    @pytest.mark.unit
    def test_parses_hosts_and_ports():
        results_parser, mock_mgr, mock_results_context = execute_test_using_results_archive(
            "hosts-ports-nmap.xml.tar.gz"
        )

        # strip out the calls to str
        actual_calls = filter_tested_interactions(
            ["ports", "os", "data"],
            [
                "ResultsContext",
                "push_context",
                "pop_context",
                "add_summaries",
                "add_summary",
                "publish_results"
            ],
            mock_mgr
        )
        assert actual_calls == [
            # Expect initial construction of the ResultsContext
            call.ResultsContext(
                "test_topic_arn",
                {
                    "address": "45.33.32.156",
                    "address_type": "ipv4",
                },
                "hosts-ports-nmap",
                "2019-04-17T12:55:57Z",  # start
                "2019-04-17T12:56:27Z",  # end
                "me-twice",  # scan type,
                results_parser.sns_client
            ),

            # Expect data for port 22, but first
            # Expect to push the port context
            call.push_context({
                "port_id": "22",
                "protocol": "tcp",
            }),
            call.post_results(
                "ports",
                {
                    "status": "open",
                    "status_reason": "syn-ack",
                    "service": "ssh",
                    "product": "OpenSSH",
                    "version": "6.6.1p1 Ubuntu 2ubuntu2.11",
                    "extra_info": "Ubuntu Linux; protocol 2.0",
                    "os_type": "Linux",
                    "cpes": ["cpe:/a:openbsd:openssh:6.6.1p1", "cpe:/o:linux:linux_kernel"]
                }
            ),

            # Expect to see the pop and push of the new context for port 80 and pusblish
            call.pop_context(),
            call.push_context({
                "port_id": "80",
                "protocol": "tcp",
            }),
            call.post_results(
                "ports",
                {
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
                }
            ),

            # Now the context that is pushed after popping and is expected to be used in the non temporal key
            # is the os name, since we are expecting to report os level info
            call.pop_context(),
            call.push_context({
                "os_name": "Linux 4.4"
            }),
            call.post_results(
                "os",
                {
                    "os_accuracy": 97,
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
                }
            ),

            # Since this accuracy of 97% is the highest seen, we expect the summaries to update
            call.add_summary("most_likely_os", "Linux 4.4"),
            call.add_summary("most_likely_os_accuracy", 97),

            # We expect two os docs in the collection
            call.pop_context(),
            call.push_context({
                "os_name": "Linux 3.11 - 4.1"
            }),
            # then the summaries
            call.post_results(
                "os",
                {
                    "os_accuracy": 93,
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
            ),

            # And now finally we expect the big global doc to be published, including summaries
            call.pop_context(),
            call.post_results(
                "data",
                {
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
                    ],
                    "os_info": [
                        {
                            "os_name": "Linux 4.4",
                            "os_accuracy": 97,
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
                            "os_accuracy": 93,
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
                    "last_boot": "Tue Apr  9 14:15:55 2019"
                },
                include_summaries=True
            ),

            # expect the publish method to be called at the finish
            call.publish_results()
        ]


    @resetting_mocks(results_context_constructor)
    @pytest.mark.unit
    def test_parses_tls_info():
        results_parser, mock_mgr, mock_results_context = execute_test_using_results_archive(
            "tls-info-nmap.xml.tar.gz"
        )

        # filter all the calls to those that allow us to inspect the behaviour
        posted_cipher_doc = filter_tested_interactions(
            ["ssl_ciphers", "ssl_protos"],
            ["push_context", "pop_context", "add_summaries"],
            mock_mgr
        )

        expected = [
            call.push_context({
                "port_id": "443",
                "protocol": "tcp",
            }),
            # first publish all the info in one doc
            call.push_context({"ssl_protocol": "TLSv1.2"}),
            call.post_results("ssl_protos", {
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
                ],
                "cipher_preference": "server"
            }),
            # Then an entry for each cipher is created
            call.push_context({"name": "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"}),
            call.post_results("ssl_ciphers", {"kex_info": "ecdh_x25519", "strength": "A"}),
            call.pop_context(),

            call.push_context({"name": "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"}),
            call.post_results("ssl_ciphers", {"kex_info": "ecdh_x25519", "strength": "A"}),
            call.pop_context(),
            call.pop_context(),
            call.add_summaries({"lowest_ssl_proto": "TLSv1.2", "lowest_ssl_strength": "A"}),
            call.pop_context(),
        ]
        assert posted_cipher_doc == expected


    @resetting_mocks(results_context_constructor)
    @pytest.mark.unit
    def test_parses_cve_info():
        results_parser, mock_mgr, mock_results_context = execute_test_using_results_archive(
            "cve-info-nmap.xml.tar.gz"
        )

        # filter all the calls to those that allow us to inspect the behaviour
        posted_cipher_doc = filter_tested_interactions(
            ["cves"],
            ["push_context", "pop_context"],
            mock_mgr
        )

        assert posted_cipher_doc == [
            call.push_context({
                "port_id": "80",
                "protocol": "tcp",
            }),
            call.push_context({"cve_code": "CVE-2017-7679"}),
            call.post_results("cves", {"cve_severity": 7.5}),
            call.pop_context(),
            call.push_context({"cve_code": "CVE-2018-1312"}),
            call.post_results("cves", {"cve_severity": 6.8}),
            call.pop_context(),
            call.pop_context(),
        ]


    @resetting_mocks(results_context_constructor)
    @pytest.mark.unit
    def test_parses_multiple_os_cpes_regression_sa_44():
        results_parser, mock_mgr, mock_results_context = execute_test_using_results_archive(
            "multiple-os-cpes-regression-sa-44-nmap.xml.tar.gz"
        )

        # filter all the calls to those that allow us to inspect the behaviour
        posted_cipher_doc = filter_tested_interactions(
            ["os"],
            ["push_context", "pop_context"],
            mock_mgr
        )

        assert posted_cipher_doc == [
            call.push_context({"os_name": "D-Link DWL-624+ or DWL-2000AP, or TRENDnet TEW-432BRP WAP"}),
            call.post_results("os", {
                "os_accuracy": 90,
                "os_classes": [
                    {
                        "os_class_type": "WAP",
                        "os_class_vendor": "D-Link",
                        "os_class_os_family": "embedded",
                        "os_class_os_gen": None,
                        "os_class_accuracy": "90",
                        "os_cpes": ["cpe:/h:dlink:dwl-624%2b", "cpe:/h:dlink:dwl-2000ap"]
                    },
                    {
                        "os_class_type": "WAP",
                        "os_class_vendor": "TRENDnet",
                        "os_class_os_family": "embedded",
                        "os_class_os_gen": None,
                        "os_class_accuracy": "90",
                        "os_cpes": ["cpe:/h:trendnet:tew-432brp"]
                    }
                ]
            }),
            call.pop_context(),
        ]


    @resetting_mocks(results_context_constructor)
    @pytest.mark.unit
    def test_parses_multiple_os_cpes_regression_sa_44():
        results_parser, mock_mgr, mock_results_context = execute_test_using_results_archive(
            "no-timestamps-when-host-down-regression-sa-43-nmap.xml.tar.gz"
        )

        # filter all the calls to those that allow us to inspect the behaviour
        posted_cipher_doc = filter_tested_interactions(
            ["os"],
            ["push_context", "pop_context"],
            mock_mgr
        )

        mock_results_context.publish_results.assert_called_once()


    @resetting_mocks(results_context_constructor)
    @pytest.mark.unit
    def test_parses_os_but_no_osmatch_regression_sa_45():
        results_parser, mock_mgr, mock_results_context = execute_test_using_results_archive(
            "os-but-no-osmatch-regression-sa-45-nmap.xml.tar.gz"
        )

        mock_results_context.publish_results.assert_called_once()


    @resetting_mocks(results_context_constructor)
    @pytest.mark.unit
    def test_parses_http_server_parse_regression_sa_46():
        results_parser, mock_mgr, mock_results_context = execute_test_using_results_archive(
            "http-server-parse-regression-sa-46-nmap.xml.tar.gz"
        )

        # filter all the calls to those that allow us to inspect the behaviour
        posted_cipher_doc = filter_tested_interactions(
            ["ports"],
            ["push_context", "pop_context"],
            mock_mgr
        )

        assert posted_cipher_doc == [
            call.push_context({
                "port_id": "80",
                "protocol": "tcp",
            }),
            call.post_results("ports", {
                "status": "open",
                "status_reason": "syn-ack",
                "service": "http",
                "product": "Amazon CloudFront httpd",
                "version": None,
                "extra_info": None,
                "os_type": None,
                "http-server-header": ["AmazonS3", "CloudFront"]
            }),
            call.pop_context()
        ]


    @resetting_mocks(results_context_constructor)
    @pytest.mark.unit
    def test_parses_ssl_certs():
        results_parser, mock_mgr, mock_results_context = execute_test_using_results_archive(
            "test_ssl_cert.xml.tar.gz"
        )

        # filter all the calls to those that allow us to inspect the behaviour
        posted_cipher_doc = filter_tested_interactions(
            ["ssl_cert"],
            ["push_context", "pop_context"],
            mock_mgr
        )

        assert posted_cipher_doc == [
            call.push_context({
                "port_id": "443",
                "protocol": "tcp",
            }),
            call.post_results("ssl_cert", {
                "extensions": [{"name": "X509v3 Subject Alternative Name", "value": "DNS:scottlogic.com"}],
                "issuer": {
                    "commonName": "Let's Encrypt Authority X3",
                    "countryName": "US",
                    "organizationName": "Let's Encrypt"
                },
                "subject": {"commonName": "scottlogic.com"},
                "validity": {"notAfter": "2019-06-29T06:52:46", "notBefore": "2019-03-31T06:52:46"}
            }),
            call.pop_context()
        ]


    @resetting_mocks(results_context_constructor)
    @pytest.mark.unit
    def test_regression_table_format_for_vulns():
        results_parser, mock_mgr, mock_results_context = execute_test_using_results_archive(
            "regression-SA-174-table-format-for-vulns.xml.tar.gz"
        )

        # filter all the calls to those that allow us to inspect the behaviour
        posted_cipher_doc = filter_tested_interactions(
            ["cve_code", "cves"],
            ["push_context", "pop_context"],
            mock_mgr
        )

        assert posted_cipher_doc == [
            call.push_context({
                "port_id": "80",
                "protocol": "tcp",
            }),
            call.push_context({"cve_code": "CVE-2017-7679"}),
            call.post_results("cves", {"cve_severity": 7.5, "is_exploit": "false", "type": "cve"}),
            call.pop_context(),
            call.push_context({"cve_code": "CVE-2018-1312"}),
            call.post_results("cves", {"cve_severity": 6.8, "is_exploit": "false", "type": "cve"}),
            call.pop_context(),
            call.pop_context(),
        ]


    @serialise_mocks()
    def execute_test_using_results_archive(filename):
        with patch("aioboto3.client"), \
                patch.dict(os.environ, TEST_ENV):
            results_parser = NmapResultsParser()

            results_context_constructor.return_value = mock_results_context = MagicMock()

            mock_mgr = Mock()
            mock_mgr.attach_mock(results_context_constructor, "ResultsContext")
            mock_mgr.attach_mock(mock_results_context.push_context, "push_context")
            mock_mgr.attach_mock(mock_results_context.pop_context, "pop_context")
            mock_mgr.attach_mock(mock_results_context.post_results, "post_results")
            mock_mgr.attach_mock(mock_results_context.publish_results, "publish_results")
            mock_mgr.attach_mock(mock_results_context.add_summaries, "add_summaries")
            mock_mgr.attach_mock(mock_results_context.add_summary, "add_summary")

            results_parser.ensure_initialised()
            results_parser.sns_client.publish.return_value = coroutine_of({"MessageId": "foo"})
            results_parser.ssm_client.get_parameters = MagicMock()
            results_parser.ssm_client.get_parameters.return_value = ssm_return_vals()
            mock_results_context.publish_results.side_effect = (coroutine_of(MagicMock()) for _ in count(0, 1))

            # load sample results file and make mock return it
            sample_file_name = f"{TEST_DIR}{filename}"
            with open(sample_file_name, "rb") as sample_data:
                class AsyncReader:
                    async def read(self):
                        return StreamingBody(sample_data, os.stat(sample_file_name).st_size).read()

                results_parser.s3_client.get_object.return_value = coroutine_of({
                    "Body": AsyncReader()
                })

                results_parser.invoke(
                    {
                        "Records": [
                            {"s3": {
                                "bucket": {"name": "test_bucket"},
                                "object": {"key": filename}
                            }}
                        ]
                    },
                    MagicMock()
                )
            return results_parser, mock_mgr, mock_results_context
