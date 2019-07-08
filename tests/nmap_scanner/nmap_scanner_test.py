from nmap_scanner.nmap_scanner import NmapScanner
import pytest
from unittest.mock import patch, MagicMock, call
import os
from itertools import count
from test_utils.test_utils import serialise_mocks, coroutine_of


TEST_ENV = {
    "REGION": "eu-west-wood",
    "STAGE": "door",
    "APP_NAME": "me-once",
    "TASK_NAME": "me-twice",
}


@patch.dict(os.environ, TEST_ENV)
def ssm_return_vals(using_private):
    stage = os.environ["STAGE"]
    app_name = os.environ["APP_NAME"]
    task_name = os.environ["TASK_NAME"]
    ssm_prefix = f"/{app_name}/{stage}"
    return coroutine_of({
        "Parameters": [
            {"Name": f"{ssm_prefix}/vpc/using_private_subnets", "Value": "true" if using_private else "false"},
            {"Name": f"{ssm_prefix}/tasks/{task_name}/security_group/id", "Value": "sg-123"},
            {"Name": f"{ssm_prefix}/tasks/{task_name}/image/id", "Value": "imagination"},
            {"Name": f"{ssm_prefix}/tasks/{task_name}/s3/results/id", "Value": "bid"},
            {"Name": f"{ssm_prefix}/vpc/subnets/instance", "Value": "subnet-123,subnet-456"},
            {"Name": f"{ssm_prefix}/ecs/cluster", "Value": "cid"}
        ]
    })


def expected_params(public_ip_str, scan_targets, message_id):
    return {
        "cluster": "cid",
        "networkConfiguration": {
            "awsvpcConfiguration": {
                "subnets": ["subnet-123", "subnet-456"],
                "securityGroups": ["sg-123"],
                "assignPublicIp": public_ip_str}
        },
        "taskDefinition": "imagination",
        "launchType": "FARGATE",
        "overrides": {
            "containerOverrides": [
                {
                    "name": "me-twice",
                    "environment": [
                        {"name": "NMAP_TARGET_STRING", "value": scan_targets},
                        {"name": "SCAN_REQUEST_ID", "value": message_id},
                        {"name": "RESULTS_BUCKET", "value": "bid"}
                    ]
                }
            ]
        }
    }


with patch("utils.json_serialisation.stringify_all"):

    @pytest.mark.unit
    @serialise_mocks()
    @patch.dict(os.environ, TEST_ENV)
    @patch("aioboto3.client")
    def test_scanner_private_subnet(aioboto):
        scanner = NmapScanner()
        scanner.ensure_initialised()
        scanner.ecs_client.run_task.return_value = coroutine_of({})
        scanner.ssm_client.get_parameters.return_value = ssm_return_vals(True)
        scanner.invoke(
            {"Records": [{"body": "url.to.scan.rogers", "messageId": "12"}]},
            MagicMock()
        )
        expected = expected_params("DISABLED", "url.to.scan.rogers", "12")
        scanner.ecs_client.run_task.assert_called_once_with(**expected)


    @pytest.mark.unit
    @serialise_mocks()
    @patch.dict(os.environ, TEST_ENV)
    @patch("aioboto3.client")
    def test_scanner_no_subnet(aioboto3):
        scanner = NmapScanner()
        scanner.ensure_initialised()
        scanner.ssm_client.get_parameters.return_value = ssm_return_vals(False)
        scanner.ecs_client.run_task.return_value = coroutine_of({})

        scanner.invoke(
            {"Records": [{"body": "url.to.scan.mamos", "messageId": "13"}]},
            MagicMock())
        expected = expected_params("ENABLED", "url.to.scan.mamos", "13")
        scanner.ecs_client.run_task.assert_called_once_with(**expected)


    @pytest.mark.unit
    @serialise_mocks()
    @patch.dict(os.environ, TEST_ENV)
    @patch("aioboto3.client")
    def test_sanitises_input_cidr4(aioboto):
        scanner = NmapScanner()
        scanner.ensure_initialised()
        scanner.ssm_client.get_parameters.return_value = ssm_return_vals(False)
        scanner.ecs_client.run_task.return_value = coroutine_of({})
        scanner.invoke(
            {"Records": [{"body": "123.3.2.12/16", "messageId": "13"}]},
            MagicMock())
        expected = expected_params("ENABLED", "123.3.2.12/16", "13")
        scanner.ecs_client.run_task.assert_called_once_with(**expected)


    @pytest.mark.unit
    @serialise_mocks()
    @patch.dict(os.environ, TEST_ENV)
    @patch("aioboto3.client")
    def test_sanitises_input_cidr6(aioboto):
        scanner = NmapScanner()
        scanner.ensure_initialised()
        scanner.ecs_client.run_task.return_value = coroutine_of({})
        scanner.ssm_client.get_parameters.return_value = ssm_return_vals(False)
        scanner.invoke(
            {"Records": [{"body": "2001:d80::/26", "messageId": "13"}]},
            MagicMock())
        expected = expected_params("ENABLED", "2001:d80::/26", "13")
        scanner.ecs_client.run_task.assert_called_once_with(**expected)


    @pytest.mark.unit
    @serialise_mocks()
    @patch.dict(os.environ, TEST_ENV)
    @patch("aioboto3.client")
    def test_sanitises_input_ip4(aioboto):
        scanner = NmapScanner()
        scanner.ensure_initialised()
        scanner.ecs_client.run_task.return_value = coroutine_of({})
        scanner.ssm_client.get_parameters.return_value = ssm_return_vals(False)
        scanner.invoke(
            {"Records": [{"body": "123.3.2.124", "messageId": "13"}]},
            MagicMock())
        expected = expected_params("ENABLED", "123.3.2.124", "13")
        scanner.ecs_client.run_task.assert_called_once_with(**expected)


    @pytest.mark.unit
    @serialise_mocks()
    @patch.dict(os.environ, TEST_ENV)
    @patch("aioboto3.client")
    def test_sanitises_input_ip6(aioboto):
        scanner = NmapScanner()
        scanner.ensure_initialised()
        scanner.ecs_client.run_task.return_value = coroutine_of({})
        scanner.ssm_client.get_parameters.return_value = ssm_return_vals(False)
        scanner.invoke(
            {"Records": [{"body": "2001:0db8:85a3:0000:0000:8a2e:0370:7334", "messageId": "13"}]},
            MagicMock())
        expected = expected_params("ENABLED", "2001:0db8:85a3:0000:0000:8a2e:0370:7334", "13")
        scanner.ecs_client.run_task.assert_called_once_with(**expected)


    @pytest.mark.unit
    @serialise_mocks()
    @patch.dict(os.environ, TEST_ENV)
    @patch("aioboto3.client")
    def test_processes_batches(aioboto):
        scanner = NmapScanner()
        scanner.ensure_initialised()
        scanner.ecs_client.run_task.side_effect = (coroutine_of({}) for _ in count(0, 1))
        scanner.ssm_client.get_parameters.return_value = ssm_return_vals(False)

        scanner.invoke({
            "Records": [
                {"body": "2001:0db8:85a3:0000:0000:8a2e:0370:7334", "messageId": "13"},
                {"body": "123.3.2.124", "messageId": "14"},
                {"body": "scan.me.everyone", "messageId": "15"},
            ]}, MagicMock())
        expected = [
            call(**exp) for exp in
            [
                expected_params("ENABLED", "2001:0db8:85a3:0000:0000:8a2e:0370:7334", "13"),
                expected_params("ENABLED", "123.3.2.124", "14"),
                expected_params("ENABLED", "scan.me.everyone", "15")
            ]
        ]
        assert expected == scanner.ecs_client.run_task.call_args_list


    @pytest.mark.unit
    @serialise_mocks()
    @patch.dict(os.environ, TEST_ENV)
    @patch("aioboto3.client")
    def test_sanitises_input_multiple_targets(aioboto):
        scanner = NmapScanner()
        scanner.ensure_initialised()
        scanner.ecs_client.run_task.side_effect = (coroutine_of({}) for _ in count(0, 1))

        scanner.ssm_client.get_parameters.return_value = ssm_return_vals(False)
        scanner.invoke({
            "Records": [
                {"body": "2001:0db8:85a3:0000:0000:8a2e:0370:7334 123.3.2.124 scan.me.everyone", "messageId": "13"},
            ]}, MagicMock())
        expected = expected_params("ENABLED", "2001:0db8:85a3:0000:0000:8a2e:0370:7334 123.3.2.124 scan.me.everyone", "13")
        scanner.ecs_client.run_task.assert_called_once_with(**expected)


    # Although testing injections by sample is a bad way to test, its good to see some basic scenarios
    # covered
    @pytest.mark.unit
    @serialise_mocks()
    @patch.dict(os.environ, TEST_ENV)
    @patch("aioboto3.client")
    def test_sanitises_input_dodgy_input(aioboto):
        scanner = NmapScanner()
        scanner.ensure_initialised()
        scanner.ecs_client.run_task.side_effect = (coroutine_of({}) for _ in count(0, 1))

        scanner.ssm_client.get_parameters.return_value = ssm_return_vals(False)
        with pytest.raises(ValueError):
            scanner.invoke(
                {"Records": [{"body": "; rm -rf", "messageId": "13"}]},
                MagicMock())


    # Although testing injections by sample is a bad way to test, its good to see some basic scenarios
    # covered
    @pytest.mark.unit
    @serialise_mocks()
    @patch.dict(os.environ, TEST_ENV)
    @patch("aioboto3.client")
    def test_sanitises_input_dodgy_input_url(aioboto):
        scanner = NmapScanner()
        scanner.ensure_initialised()
        scanner.ecs_client.run_task.side_effect = (coroutine_of({}) for _ in count(0, 1))

        scanner.ssm_client.get_parameters.return_value = ssm_return_vals(False)
        with pytest.raises(ValueError):
            scanner.invoke(
                {"Records": [{"body": "http://foo.bar?hello=foo; rm -rf", "messageId": "13"}]},
                MagicMock())


    @pytest.mark.unit
    @serialise_mocks()
    @patch.dict(os.environ, TEST_ENV)
    @patch("aioboto3.client")
    def test_raises_when_ecs_failures_present(aioboto):
        scanner = NmapScanner()
        scanner.ensure_initialised()
        scanner.ssm_client.get_parameters.return_value = ssm_return_vals(False)
        scanner.ecs_client.run_task.return_value = coroutine_of({"failures": [
            {"arn": "arn::some:::arn", "reason": "failed miserably"}
        ]})
        with pytest.raises(RuntimeError, match=r"\{\"arn\": \"arn::some:::arn\", \"reason\": \"failed miserably\"\}"):
            scanner.invoke({"Records": [{"body": "some.host", "messageId": "13"}]}, MagicMock())

    @pytest.mark.unit
    @serialise_mocks()
    @patch.dict(os.environ, TEST_ENV)
    @patch("aioboto3.client")
    def test_json_input_one_ip4(aioboto):
        scanner = NmapScanner()
        scanner.ensure_initialised()
        scanner.ecs_client.run_task.side_effect = (coroutine_of({}) for _ in count(0, 1))

        scanner.ssm_client.get_parameters.return_value = ssm_return_vals(False)
        scanner.invoke(
            {
                "Records": [
                    {
                        "body": "{\"AddressToScan\":\"123.3.2.124\"}",
                        "messageId": "13-1"
                    }
                ]
            },
            MagicMock())
        expected = expected_params("ENABLED", "123.3.2.124", "13-1")
        scanner.ecs_client.run_task.assert_called_once_with(**expected)


    @pytest.mark.unit
    @serialise_mocks()
    @patch.dict(os.environ, TEST_ENV)
    @patch("aioboto3.client")
    def test_sanitises_input_short_name(aioboto):
        scanner = NmapScanner()
        scanner.ensure_initialised()
        scanner.ecs_client.run_task.side_effect = (coroutine_of({}) for _ in count(0, 1))

        scanner.ssm_client.get_parameters.return_value = ssm_return_vals(False)
        with pytest.raises(ValueError):
            scanner.invoke(
                {"Records": [{"body": "host", "messageId": "100"}]},
                MagicMock())


    @pytest.mark.unit
    @serialise_mocks()
    @patch.dict(os.environ, TEST_ENV)
    @patch("aioboto3.client")
    def test_sanitises_input_mid_underscore(aioboto):
        scanner = NmapScanner()
        scanner.ensure_initialised()
        scanner.ecs_client.run_task.side_effect = (coroutine_of({}) for _ in count(0, 1))

        scanner.ssm_client.get_parameters.return_value = ssm_return_vals(False)
        with pytest.raises(ValueError):
            scanner.invoke(
                {"Records": [{"body": "underscores_are.not.allowed.mid.domain", "messageId": "101"}]},
                MagicMock())


    @pytest.mark.unit
    @serialise_mocks()
    @patch.dict(os.environ, TEST_ENV)
    @patch("aioboto3.client")
    def test_sanitises_input_underscore_hostname(aioboto):
        scanner = NmapScanner()
        scanner.ensure_initialised()
        scanner.ecs_client.run_task.side_effect = (coroutine_of({}) for _ in count(0, 1))

        scanner.ssm_client.get_parameters.return_value = ssm_return_vals(False)
        scanner.invoke(
            {"Records": [{"body": "_valid.if._first.test.com", "messageId": "102"}]},
            MagicMock())
        expected = expected_params("ENABLED", "_valid.if._first.test.com", "102")
        scanner.ecs_client.run_task.assert_called_once_with(**expected)


    @pytest.mark.unit
    @serialise_mocks()
    @patch.dict(os.environ, TEST_ENV)
    @patch("aioboto3.client")
    def test_sanitises_input_last_underscore(aioboto):
        scanner = NmapScanner()
        scanner.ensure_initialised()
        scanner.ecs_client.run_task.return_value = coroutine_of({})
        scanner.ssm_client.get_parameters.return_value = ssm_return_vals(False)
        with pytest.raises(ValueError):
            scanner.invoke(
                {"Records": [{"body": "_notvalid.if._at.end", "messageId": "103"}]},
                MagicMock())
