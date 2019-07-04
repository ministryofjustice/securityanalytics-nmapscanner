from unittest.mock import patch, MagicMock, call, Mock
import pytest
import os
import itertools
from test_utils.test_utils import resetting_mocks, serialise_mocks, coroutine_of
from utils.json_serialisation import dumps
from botocore.response import StreamingBody
from results_parser import NmapResultsParser

TEST_ENV = {
    "REGION": "eu-west-wood",
    "STAGE": "door",
    "APP_NAME": "me-once",
    "TASK_NAME": "me-twice",
}
TEST_DIR = "./tests/results_parser/"

mock_results_context = MagicMock()

with patch.dict(os.environ, TEST_ENV), \
     patch("boto3.client") as boto_client, \
        patch("aioboto3.client") as aioboto_client, \
        patch("utils.json_serialisation.stringify_all"), \
        patch("utils.scan_results.ResultsContext") as results_context_constructor:
    # ensure each client is a different mock
    boto_client.side_effect = (MagicMock() for _ in itertools.count())
    aioboto_client.side_effect = (MagicMock() for _ in itertools.count())
    results_context_constructor.return_value = mock_results_context

    # Since we want to assert the ordering of calls across multiple mocks, we attach them to a mock manager
    # and assert the calls against that
    mock_mgr = Mock()
    mock_mgr.attach_mock(results_context_constructor, "ResultsContext")
    mock_mgr.attach_mock(mock_results_context.push_context, "push_context")
    mock_mgr.attach_mock(mock_results_context.pop_context, "pop_context")
    mock_mgr.attach_mock(mock_results_context.post_results, "post_results")
    mock_mgr.attach_mock(mock_results_context.publish_results, "publish_results")
    mock_mgr.attach_mock(mock_results_context.add_summaries, "add_summaries")
    mock_mgr.attach_mock(mock_results_context.add_summary, "add_summary")

    # with the mocks in place it is time to import the results parser


@patch.dict(os.environ, TEST_ENV)
def ssm_return_vals():
    stage = os.environ["STAGE"]
    app_name = os.environ["APP_NAME"]
    task_name = os.environ["TASK_NAME"]
    ssm_prefix = f"/{app_name}/{stage}"
    return coroutine_of({
        "Parameters": [
            {"Name": f"{ssm_prefix}/tasks/{task_name}/results/arn", "Value": "test_topic"}
        ]
    })


def expected_pub(doc_type, doc):
    return {
        "TopicArn": "test_topic",
        "Subject": doc_type,
        "Message": dumps(doc)
    }


# @pytest.mark.unit
# @serialise_mocks()
# @patch.dict(os.environ, TEST_ENV)
# @patch("aioboto3.client")
# @patch("utils.json_serialisation.stringify_all")
# def test_parses_hosts_and_ports():
#     results_parser = NmapResultsParser()
#     results_parser
#
#     results_parser.ssm_client.get_parameters.return_value = ssm_return_vals()
#
#     # load sample results file and make mock return it
#     sample_file_name = f"{TEST_DIR}hosts-ports-nmap.xml.tar.gz"
#     with open(sample_file_name, "rb") as sample_data:
#         results_parser.s3_client.get_object.return_value = {
#             "Body": StreamingBody(sample_data, os.stat(sample_file_name).st_size)
#         }
#
#         results_parser.parse_results({
#             "Records": [
#                 {"s3": {
#                     "bucket": {"name": "test_bucket"},
#                     "object": {"key": "hosts-ports-nmap.xml.tar.gz"}
#                 }}
#             ]
#         }, MagicMock())
#
#     actual_calls = [x for x in mock_mgr.mock_calls if x != call.ResultsContext().__str__()]
#     assert actual_calls == [
#         # Expect initial construction of the ResultsContext
#         call.ResultsContext(
#             "test_topic",
#             {
#                 "address": "45.33.32.156",
#                 "address_type": "ipv4",
#             },
#             "hosts-ports-nmap",
#             "2019-04-17T12:55:57Z",  # start
#             "2019-04-17T12:56:27Z",  # end
#             "me-twice",  # scan type,
#             results_parser.sns_client
#         ),
#
#         # Expect data for port 22, but first
#         # Expect to push the port context
#         call.push_context({
#             "port_id": "22",
#             "protocol": "tcp",
#         }),
#         call.post_results(
#             "ports",
#             {
#                 "status": "open",
#                 "status_reason": "syn-ack",
#                 "service": "ssh",
#                 "product": "OpenSSH",
#                 "version": "6.6.1p1 Ubuntu 2ubuntu2.11",
#                 "extra_info": "Ubuntu Linux; protocol 2.0",
#                 "os_type": "Linux",
#                 "cpes": ["cpe:/a:openbsd:openssh:6.6.1p1", "cpe:/o:linux:linux_kernel"]
#             }
#         ),
#
#         # Expect to see the pop and push of the new context for port 80 and pusblish
#         call.pop_context(),
#         call.push_context({
#             "port_id": "80",
#             "protocol": "tcp",
#         }),
#         call.post_results(
#             "ports",
#             {
#                 "status": "open",
#                 "status_reason": "syn-ack",
#                 "service": "http",
#                 "product": "Apache httpd",
#                 "version": "2.4.7",
#                 "extra_info": "(Ubuntu)",
#                 "os_type": None,
#                 "cpes": ["cpe:/a:apache:http_server:2.4.7"],
#                 "http-server-header": [
#                     "Apache/2.4.7 (Ubuntu)"
#                 ]
#             }
#         ),
#
#         # Now the context that is pushed after popping and is expected to be used in the non temporal key
#         # is the os name, since we are expecting to report os level info
#         call.pop_context(),
#         call.push_context({
#             "os_name": "Linux 4.4"
#         }),
#         call.post_results(
#             "os",
#             {
#                 "os_accuracy": 97,
#                 "os_classes": [
#                     {
#                         "os_class_type": "general purpose",
#                         "os_class_vendor": "Linux",
#                         "os_class_os_family": "Linux",
#                         "os_class_os_gen": "4.X",
#                         "os_class_accuracy": "97",
#                         "os_cpes": [
#                             "cpe:/o:linux:linux_kernel:4.4"
#                         ]
#                     }
#                 ]
#             }
#         ),
#
#         # Since this accuracy of 97% is the highest seen, we expect the summaries to update
#         call.add_summary("most_likely_os", "Linux 4.4"),
#         call.add_summary("most_likely_os_accuracy", 97),
#
#         # We expect two os docs in the collection
#         call.pop_context(),
#         call.push_context({
#             "os_name": "Linux 3.11 - 4.1"
#         }),
#         # then the summaries
#         call.post_results(
#             "os",
#             {
#                 "os_accuracy": 93,
#                 "os_classes": [
#                     {
#                         "os_class_type": "general purpose",
#                         "os_class_vendor": "Linux",
#                         "os_class_os_family": "Linux",
#                         "os_class_os_gen": "3.X",
#                         "os_class_accuracy": "93",
#                         "os_cpes": [
#                             "cpe:/o:linux:linux_kernel:3"
#                         ]
#                     },
#                     {
#                         "os_class_type": "general purpose",
#                         "os_class_vendor": "Linux",
#                         "os_class_os_family": "Linux",
#                         "os_class_os_gen": "4.X",
#                         "os_class_accuracy": "93",
#                         "os_cpes": [
#                             "cpe:/o:linux:linux_kernel:4"
#                         ]
#                     }
#                 ]
#             }
#         ),
#
#         # And now finally we expect the big global doc to be published, including summaries
#         call.pop_context(),
#         call.post_results(
#             "data",
#             {
#                 "host_names": [
#                     {
#                         "host_name": "scanme.nmap.org",
#                         "host_name_type": "user"
#                     },
#                     {
#                         "host_name": "scanme.nmap.org",
#                         "host_name_type": "PTR"
#                     }
#                 ],
#                 "ports": [
#                     {
#                         "port_id": "22",
#                         "protocol": "tcp",
#                         "status": "open",
#                         "status_reason": "syn-ack",
#                         "service": "ssh",
#                         "product": "OpenSSH",
#                         "version": "6.6.1p1 Ubuntu 2ubuntu2.11",
#                         "extra_info": "Ubuntu Linux; protocol 2.0",
#                         "os_type": "Linux",
#                         "cpes": ["cpe:/a:openbsd:openssh:6.6.1p1", "cpe:/o:linux:linux_kernel"]
#                     },
#                     {
#                         "port_id": "80",
#                         "protocol": "tcp",
#                         "status": "open",
#                         "status_reason": "syn-ack",
#                         "service": "http",
#                         "product": "Apache httpd",
#                         "version": "2.4.7",
#                         "extra_info": "(Ubuntu)",
#                         "os_type": None,
#                         "cpes": ["cpe:/a:apache:http_server:2.4.7"],
#                         "http-server-header": [
#                             "Apache/2.4.7 (Ubuntu)"
#                         ]
#                     },
#                 ],
#                 "os_info": [
#                     {
#                         "os_name": "Linux 4.4",
#                         "os_accuracy": 97,
#                         "os_classes": [
#                             {
#                                 "os_class_type": "general purpose",
#                                 "os_class_vendor": "Linux",
#                                 "os_class_os_family": "Linux",
#                                 "os_class_os_gen": "4.X",
#                                 "os_class_accuracy": "97",
#                                 "os_cpes": [
#                                     "cpe:/o:linux:linux_kernel:4.4"
#                                 ]
#                             }
#                         ]
#                     },
#                     {
#                         "os_name": "Linux 3.11 - 4.1",
#                         "os_accuracy": 93,
#                         "os_classes": [
#                             {
#                                 "os_class_type": "general purpose",
#                                 "os_class_vendor": "Linux",
#                                 "os_class_os_family": "Linux",
#                                 "os_class_os_gen": "3.X",
#                                 "os_class_accuracy": "93",
#                                 "os_cpes": [
#                                     "cpe:/o:linux:linux_kernel:3"
#                                 ]
#                             },
#                             {
#                                 "os_class_type": "general purpose",
#                                 "os_class_vendor": "Linux",
#                                 "os_class_os_family": "Linux",
#                                 "os_class_os_gen": "4.X",
#                                 "os_class_accuracy": "93",
#                                 "os_cpes": [
#                                     "cpe:/o:linux:linux_kernel:4"
#                                 ]
#                             }
#                         ]
#                     }
#                 ],
#                 "host_scan_start_time": "2019-04-17T12:55:57Z",
#                 "host_scan_end_time": "2019-04-17T12:56:27Z",
#                 "status": "up",
#                 "status_reason": "echo-reply",
#                 "uptime": "686432",
#                 "last_boot": "Tue Apr  9 14:15:55 2019"
#             },
#             include_summaries=True
#         ),
#
#         # expect the publish method to be called at the finish
#         call.publish_results()
#     ]

#
# @patch.dict(os.environ, TEST_ENV)
# @pytest.mark.unit
# @serialise_mocks()
# @resetting_mocks(
#     mock_mgr,
#     mock_results_context,
#     results_parser.sns_client,
#     results_parser.s3_client,
#     results_parser.ssm_client
# )
# def test_parses_tls_info():
#     results_parser.ssm_client.get_parameters.return_value = ssm_return_vals()
#
#     # load sample results file and make mock return it
#     sample_file_name = f"{TEST_DIR}tls-info-nmap.xml.tar.gz"
#     with open(sample_file_name, "rb") as sample_data:
#         results_parser.s3_client.get_object.return_value = {
#             "Body": StreamingBody(sample_data, os.stat(sample_file_name).st_size)
#         }
#
#         results_parser.parse_results({
#             "Records": [
#                 {"s3": {
#                     "bucket": {"name": "test_bucket"},
#                     "object": {"key": "tls-info-nmap.xml.tar.gz"}
#                 }}
#             ]
#         }, MagicMock())
#
#     assert mock_results_context.add_summaries.call_args_list == [
#         call({"lowest_ssl_proto": "TLSv1.2", "lowest_ssl_strength": "A"})
#     ]
#
#     # filter all the calls to those that allow us to inspect the behaviour
#     posted_cipher_doc = [
#         (name, args, kwargs)
#         for (name, args, kwargs) in mock_mgr.mock_calls
#         if (name == "post_results" and args[0] in ["ssl_ciphers", "ssl_protos"]) or
#            (name == "push_context" or name == "pop_context")
#     ]
#
#     assert posted_cipher_doc == [
#         call.push_context({
#             "port_id": "443",
#             "protocol": "tcp",
#         }),
#         # first publish all the info in one doc
#         call.push_context({"ssl_protocol": "TLSv1.2"}),
#         call.post_results("ssl_protos", {
#             "ciphers": [
#                 {
#                     "kex_info": "ecdh_x25519",
#                     "strength": "A",
#                     "name": "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"
#                 },
#                 {
#                     "kex_info": "ecdh_x25519",
#                     "strength": "A",
#                     "name": "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"
#                 },
#             ],
#             "cipher_preference": "server"
#         }),
#         # Then an entry for each cipher is created
#         call.push_context({"name": "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"}),
#         call.post_results("ssl_ciphers", {"kex_info": "ecdh_x25519", "strength": "A"}),
#         call.pop_context(),
#
#         call.push_context({"name": "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"}),
#         call.post_results("ssl_ciphers", {"kex_info": "ecdh_x25519", "strength": "A"}),
#         call.pop_context(),
#         call.pop_context(),
#         call.pop_context(),
#     ]
#
#
# @patch.dict(os.environ, TEST_ENV)
# @pytest.mark.unit
# @serialise_mocks()
# @resetting_mocks(
#     mock_mgr,
#     mock_results_context,
#     results_parser.sns_client,
#     results_parser.s3_client,
#     results_parser.ssm_client
# )
# def test_parses_cve_info():
#     results_parser.ssm_client.get_parameters.return_value = ssm_return_vals()
#
#     # load sample results file and make mock return it
#     sample_file_name = f"{TEST_DIR}cve-info-nmap.xml.tar.gz"
#     with open(sample_file_name, "rb") as sample_data:
#         results_parser.s3_client.get_object.return_value = {
#             "Body": StreamingBody(sample_data, os.stat(sample_file_name).st_size)
#         }
#
#         results_parser.parse_results({
#             "Records": [
#                 {"s3": {
#                     "bucket": {"name": "test_bucket"},
#                     # Please note that the / characters in the key are replaced with %2F, the key is
#                     # urlencoded
#                     "object": {"key": "cve-info-nmap.xml.tar.gz"}
#                 }}
#             ]
#         }, MagicMock())
#
#     # filter all the calls to those that allow us to inspect the behaviour
#     posted_cipher_doc = [
#         (name, args, kwargs)
#         for (name, args, kwargs) in mock_mgr.mock_calls
#         if (name == "post_results" and args[0] in ["cves"]) or
#            (name == "push_context" or name == "pop_context")
#     ]
#
#     assert posted_cipher_doc == [
#         call.push_context({
#             "port_id": "80",
#             "protocol": "tcp",
#         }),
#         call.push_context({"cve_code": "CVE-2017-7679"}),
#         call.post_results("cves", {"cve_severity": 7.5}),
#         call.pop_context(),
#         call.push_context({"cve_code": "CVE-2018-1312"}),
#         call.post_results("cves", {"cve_severity": 6.8}),
#         call.pop_context(),
#         call.pop_context(),
#     ]
#
#
# @pytest.mark.unit
# @pytest.mark.regression
# @serialise_mocks()
# @resetting_mocks(
#     mock_mgr,
#     mock_results_context,
#     results_parser.sns_client,
#     results_parser.s3_client,
#     results_parser.ssm_client
# )
# def test_parses_multiple_os_cpes_regression_sa_44():
#     results_parser.ssm_client.get_parameters.return_value = ssm_return_vals()
#
#     # load sample results file and make mock return it
#     sample_file_name = f"{TEST_DIR}multiple-os-cpes-regression-sa-44-nmap.xml.tar.gz"
#     with open(sample_file_name, "rb") as sample_data:
#         results_parser.s3_client.get_object.return_value = {
#             "Body": StreamingBody(sample_data, os.stat(sample_file_name).st_size)
#         }
#
#         results_parser.parse_results({
#             "Records": [
#                 {"s3": {
#                     "bucket": {"name": "test_bucket"},
#                     # Please note that the / characters in the key are replaced with %2F, the key is
#                     # urlencoded
#                     "object": {
#                         "key": "multiple-os-cpes-regression-sa-44-nmap.xml.tar.gz"}
#                 }}
#             ]
#         }, MagicMock())
#
#         # filter all the calls to those that allow us to inspect the behaviour
#         posted_cipher_doc = [
#             (name, args, kwargs)
#             for (name, args, kwargs) in mock_mgr.mock_calls
#             if (name == "post_results" and args[0] in ["os"]) or
#                (name == "push_context" or name == "pop_context")
#         ]
#
#         assert posted_cipher_doc == [
#             call.push_context({"os_name": "D-Link DWL-624+ or DWL-2000AP, or TRENDnet TEW-432BRP WAP"}),
#             call.post_results("os", {
#                 "os_accuracy": 90,
#                 "os_classes": [
#                     {
#                         "os_class_type": "WAP",
#                         "os_class_vendor": "D-Link",
#                         "os_class_os_family": "embedded",
#                         "os_class_os_gen": None,
#                         "os_class_accuracy": "90",
#                         "os_cpes": ["cpe:/h:dlink:dwl-624%2b", "cpe:/h:dlink:dwl-2000ap"]
#                     },
#                     {
#                         "os_class_type": "WAP",
#                         "os_class_vendor": "TRENDnet",
#                         "os_class_os_family": "embedded",
#                         "os_class_os_gen": None,
#                         "os_class_accuracy": "90",
#                         "os_cpes": ["cpe:/h:trendnet:tew-432brp"]
#                     }
#                 ]
#             }),
#             call.pop_context(),
#         ]
#
#
# @pytest.mark.unit
# @pytest.mark.regression
# @serialise_mocks()
# @resetting_mocks(
#     mock_mgr,
#     mock_results_context,
#     results_parser.sns_client,
#     results_parser.s3_client,
#     results_parser.ssm_client
# )
# def test_parses_no_timestamps_when_host_down_regression_sa_43():
#     results_parser.ssm_client.get_parameters.return_value = ssm_return_vals()
#
#     # load sample results file and make mock return it
#     sample_file_name = f"{TEST_DIR}no-timestamps-when-host-down-regression-sa-43-nmap.xml.tar.gz"
#     with open(sample_file_name, "rb") as sample_data:
#         results_parser.s3_client.get_object.return_value = {
#             "Body": StreamingBody(sample_data, os.stat(sample_file_name).st_size)
#         }
#
#         results_parser.parse_results({
#             "Records": [
#                 {"s3": {
#                     "bucket": {"name": "test_bucket"},
#                     # Please note that the / characters in the key are replaced with %2F, the key is
#                     # urlencoded
#                     "object": {
#                         "key": "e2791270-b64e-4ec8-969c-87af81f169ce-1-2019-05-03T07%3A16%3A50Z-nmap.xml.tar.gz"}
#                 }}
#             ]
#         }, MagicMock())
#
#     mock_results_context.publish_results.assert_called_once()
#
#
# @patch.dict(os.environ, TEST_ENV)
# @pytest.mark.unit
# @pytest.mark.regression
# @serialise_mocks()
# @resetting_mocks(
#     mock_mgr,
#     mock_results_context,
#     results_parser.sns_client,
#     results_parser.s3_client,
#     results_parser.ssm_client
# )
# def test_parses_os_but_no_osmatch_regression_sa_45():
#     results_parser.ssm_client.get_parameters.return_value = ssm_return_vals()
#
#     # load sample results file and make mock return it
#     sample_file_name = f"{TEST_DIR}os-but-no-osmatch-regression-sa-45-nmap.xml.tar.gz"
#     with open(sample_file_name, "rb") as sample_data:
#         results_parser.s3_client.get_object.return_value = {
#             "Body": StreamingBody(sample_data, os.stat(sample_file_name).st_size)
#         }
#
#         results_parser.parse_results({
#             "Records": [
#                 {"s3": {
#                     "bucket": {"name": "test_bucket"},
#                     # Please note that the / characters in the key are replaced with %2F, the key is
#                     # urlencoded
#                     "object": {
#                         "key": "os-but-no-osmatch-regression-sa-45-nmap.xml.tar.gz"}
#                 }}
#             ]
#         }, MagicMock())
#
#     mock_results_context.publish_results.assert_called_once()
#
#
# @patch.dict(os.environ, TEST_ENV)
# @pytest.mark.unit
# @pytest.mark.regression
# @serialise_mocks()
# @resetting_mocks(
#     mock_mgr,
#     mock_results_context,
#     results_parser.sns_client,
#     results_parser.s3_client,
#     results_parser.ssm_client
# )
# def test_parses_http_server_parse_regression_sa_46():
#     results_parser.ssm_client.get_parameters.return_value = ssm_return_vals()
#
#     # load sample results file and make mock return it
#     sample_file_name = f"{TEST_DIR}http-server-parse-regression-sa-46-nmap.xml.tar.gz"
#     with open(sample_file_name, "rb") as sample_data:
#         results_parser.s3_client.get_object.return_value = {
#             "Body": StreamingBody(sample_data, os.stat(sample_file_name).st_size)
#         }
#
#         results_parser.parse_results({
#             "Records": [
#                 {"s3": {
#                     "bucket": {"name": "test_bucket"},
#                     "object": {
#                         "key": "http-server-parse-regression-sa-46-nmap.xml.tar.gz"}
#                 }}
#             ]
#         }, MagicMock())
#
#     # filter all the calls to those that allow us to inspect the behaviour
#     posted_cipher_doc = [
#         (name, args, kwargs)
#         for (name, args, kwargs) in mock_mgr.mock_calls
#         if (name == "post_results" and args[0] in ["ports"]) or
#            (name == "push_context" or name == "pop_context")
#     ]
#
#     assert posted_cipher_doc == [
#         call.push_context({
#             "port_id": "80",
#             "protocol": "tcp",
#         }),
#         call.post_results("ports", {
#             "status": "open",
#             "status_reason": "syn-ack",
#             "service": "http",
#             "product": "Amazon CloudFront httpd",
#             "version": None,
#             "extra_info": None,
#             "os_type": None,
#             "http-server-header": ["AmazonS3", "CloudFront"]
#         }),
#         call.pop_context()
#     ]
#
#
# @patch.dict(os.environ, TEST_ENV)
# @pytest.mark.unit
# @serialise_mocks()
# @resetting_mocks(
#     mock_mgr,
#     mock_results_context,
#     results_parser.sns_client,
#     results_parser.s3_client,
#     results_parser.ssm_client
# )
# def test_parses_ssl_certs():
#     results_parser.ssm_client.get_parameters.return_value = ssm_return_vals()
#     # load sample results file and make mock return it
#     sample_file_name = f"{TEST_DIR}test_ssl_cert.xml.tar.gz"
#     with open(sample_file_name, "rb") as sample_data:
#         results_parser.s3_client.get_object.return_value = {
#             "Body": StreamingBody(sample_data, os.stat(sample_file_name).st_size)
#         }
#
#         results_parser.parse_results({
#             "Records": [
#                 {"s3": {
#                     "bucket": {"name": "test_bucket"},
#                     "object": {"key": "test_ssl_cert.xml.tar.gz"}
#                 }}
#             ]
#         }, MagicMock())
#
#     # filter all the calls to those that allow us to inspect the behaviour
#     posted_cipher_doc = [
#         (name, args, kwargs)
#         for (name, args, kwargs) in mock_mgr.mock_calls
#         if (name == "post_results" and args[0] in ["ssl_cert"]) or
#            (name == "push_context" or name == "pop_context")
#     ]
#
#     assert posted_cipher_doc == [
#         call.push_context({
#             "port_id": "443",
#             "protocol": "tcp",
#         }),
#         call.post_results("ssl_cert", {
#             "extensions": [{"name": "X509v3 Subject Alternative Name", "value": "DNS:scottlogic.com"}],
#             "issuer": {
#                 "commonName": "Let's Encrypt Authority X3",
#                 "countryName": "US",
#                 "organizationName": "Let's Encrypt"
#             },
#             "subject": {"commonName": "scottlogic.com"},
#             "validity": {"notAfter": "2019-06-29T06:52:46", "notBefore": "2019-03-31T06:52:46"}
#         }),
#         call.pop_context()
#     ]
#
# @patch.dict(os.environ, TEST_ENV)
# @pytest.mark.unit
# @serialise_mocks()
# @resetting_mocks(
#     mock_mgr,
#     mock_results_context,
#     results_parser.sns_client,
#     results_parser.s3_client,
#     results_parser.ssm_client
# )
# def test_regression_foo():
#     results_parser.ssm_client.get_parameters.return_value = ssm_return_vals()
#
#     # load sample results file and make mock return it
#     sample_file_name = f"{TEST_DIR}regression-SA-174-table-format-for-vulns.xml.tar.gz"
#     with open(sample_file_name, "rb") as sample_data:
#         results_parser.s3_client.get_object.return_value = {
#             "Body": StreamingBody(sample_data, os.stat(sample_file_name).st_size)
#         }
#
#         results_parser.parse_results({
#             "Records": [
#                 {"s3": {
#                     "bucket": {"name": "test_bucket"},
#                     # Please note that the / characters in the key are replaced with %2F, the key is
#                     # urlencoded
#                     "object": {"key": "regression-SA-174-table-format-for-vulns.xml.tar.gz"}
#                 }}
#             ]
#         }, MagicMock())
#
#     # filter all the calls to those that allow us to inspect the behaviour
#     posted_cipher_doc = [
#         (name, args, kwargs)
#         for (name, args, kwargs) in mock_mgr.mock_calls
#         if (name == "post_results" and args[0] in ["cve_code", "cves"]) or
#            (name == "push_context" or name == "pop_context")
#     ]
#
#     assert posted_cipher_doc == [
#         call.push_context({
#             "port_id": "80",
#             "protocol": "tcp",
#         }),
#         call.push_context({"cve_code": "CVE-2017-7679"}),
#         call.post_results("cves", {"cve_severity": 7.5, "is_exploit": "false", "type": "cve"}),
#         call.pop_context(),
#         call.push_context({"cve_code": "CVE-2018-1312"}),
#         call.post_results("cves", {"cve_severity": 6.8, "is_exploit": "false", "type": "cve"}),
#         call.pop_context(),
#         call.pop_context(),
#     ]