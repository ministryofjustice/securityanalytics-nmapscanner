# import importlib
# import pytest
# import os
# from test_utils.test_utils import serialise_mocks
# from unittest import mock
#
#
# TEST_ENV = {
#     "REGION": "eu-west-wood",
#     "STAGE": "door",
#     "APP_NAME": "me-once",
#     "TASK_NAME": "me-twice",
# }
#
#
# @mock.patch.dict(os.environ, TEST_ENV)
# def import_ciphers():
#     return importlib.import_module("results_parser.ssl-enum-ciphers")
#
#
# ssl_enum_ciphers = import_ciphers()
#
#
# @mock.patch.dict(os.environ, TEST_ENV)
# @pytest.mark.unit
# @serialise_mocks()
# def test_adds_to_empty():
#     summaries = {}
#     ssl_enum_ciphers.summarise_proto("TLSv1.1", summaries)
#     assert summaries["lowest_ssl_proto"] == "TLSv1.1"
#     assert "unknown_ssl_proto" not in summaries
#
#
# @mock.patch.dict(os.environ, TEST_ENV)
# @pytest.mark.unit
# @serialise_mocks()
# def test_adds_unknown_flag():
#     summaries = {}
#     ssl_enum_ciphers.summarise_proto("nonsenes", summaries)
#     ssl_enum_ciphers.summarise_proto("TLSv1.1", summaries)
#     assert summaries["lowest_ssl_proto"] == "TLSv1.1"
#     assert summaries["unknown_ssl_proto"]
#
#
# @mock.patch.dict(os.environ, TEST_ENV)
# @pytest.mark.unit
# @serialise_mocks()
# def test_orders_by_protocol():
#     summaries = {
#         "lowest_ssl_proto": "TLSv1.1"
#     }
#     ssl_enum_ciphers.summarise_proto("TLSv1.2", summaries)
#     ssl_enum_ciphers.summarise_proto("TLSv1.0", summaries)
#     ssl_enum_ciphers.summarise_proto("silly", summaries)
#     assert summaries["lowest_ssl_proto"] == "TLSv1.0"
#     assert summaries["unknown_ssl_proto"]
