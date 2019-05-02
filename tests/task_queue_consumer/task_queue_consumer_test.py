from unittest import mock
import pytest
import os
import itertools
from test_utils.test_utils import resetting_mocks, serialise_mocks


TEST_ENV = {
    'REGION': 'eu-west-wood',
    'STAGE': 'door',
    'APP_NAME': 'me-once',
    'TASK_NAME': 'me-twice',
}

with mock.patch.dict(os.environ, TEST_ENV), \
        mock.patch('boto3.client') as boto_client, \
        mock.patch('utils.json_serialisation.stringify_all'):
    # ensure each client is a different mock
    boto_client.side_effect = (mock.MagicMock() for _ in itertools.count())
    from task_queue_consumer import task_queue_consumer


@mock.patch.dict(os.environ, TEST_ENV)
def ssm_return_vals(using_private):
    stage = os.environ["STAGE"]
    app_name = os.environ["APP_NAME"]
    task_name = os.environ["TASK_NAME"]
    ssm_prefix = f"/{app_name}/{stage}"
    return {
        'Parameters': [
            {"Name": f"{ssm_prefix}/vpc/using_private_subnets", "Value": "true" if using_private else "false"},
            {"Name": f"{ssm_prefix}/tasks/{task_name}/security_group/id", "Value": "sg-123"},
            {"Name": f"{ssm_prefix}/tasks/{task_name}/image/id", "Value": "imagination"},
            {"Name": f"{ssm_prefix}/tasks/{task_name}/s3/results/id", "Value": "bid"},
            {"Name": f"{ssm_prefix}/vpc/subnets/instance", "Value": "subnet-123,subnet-456"},
            {"Name": f"{ssm_prefix}/ecs/cluster", "Value": "cid"}
        ]
    }


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
                        {"name": "HOST_TO_SCAN", "value": scan_targets},
                        {"name": "MESSAGE_ID", "value": message_id},
                        {"name": "RESULTS_BUCKET", "value": "bid"}
                    ]
                }
            ]
        }
    }


@pytest.mark.unit
@serialise_mocks()
@resetting_mocks(task_queue_consumer.ecs_client, task_queue_consumer.ssm_client.get_parameters)
def test_task_queue_consumer_private_subnet():
    task_queue_consumer.ssm_client.get_parameters.return_value = ssm_return_vals(True)
    task_queue_consumer.submit_scan_task(
        {"Records": [{"body": "url.to.scan.rogers", "messageId": "12"}]},
        mock.MagicMock())
    expected = expected_params("DISABLED", "url.to.scan.rogers", "12")
    task_queue_consumer.ecs_client.run_task.assert_called_once_with(**expected)


@pytest.mark.unit
@serialise_mocks()
@resetting_mocks(task_queue_consumer.ecs_client, task_queue_consumer.ssm_client.get_parameters)
def test_task_queue_consumer_no_subnet():
    task_queue_consumer.ssm_client.get_parameters.return_value = ssm_return_vals(False)
    task_queue_consumer.submit_scan_task(
        {"Records": [{"body": "url.to.scan.mamos", "messageId": "13"}]},
        mock.MagicMock())
    expected = expected_params("ENABLED", "url.to.scan.mamos", "13")
    task_queue_consumer.ecs_client.run_task.assert_called_once_with(**expected)


@pytest.mark.unit
@serialise_mocks()
@resetting_mocks(task_queue_consumer.ecs_client, task_queue_consumer.ssm_client.get_parameters)
def test_sanitises_input_cidr4():
    task_queue_consumer.ssm_client.get_parameters.return_value = ssm_return_vals(False)
    task_queue_consumer.submit_scan_task(
        {"Records": [{"body": "123.3.2.12/16", "messageId": "13"}]},
        mock.MagicMock())
    expected = expected_params("ENABLED", "123.3.2.12/16", "13")
    task_queue_consumer.ecs_client.run_task.assert_called_once_with(**expected)


@pytest.mark.unit
@serialise_mocks()
@resetting_mocks(task_queue_consumer.ecs_client, task_queue_consumer.ssm_client.get_parameters)
def test_sanitises_input_cidr6():
    task_queue_consumer.ssm_client.get_parameters.return_value = ssm_return_vals(False)
    task_queue_consumer.submit_scan_task(
        {"Records": [{"body": "2001:d80::/26", "messageId": "13"}]},
        mock.MagicMock())
    expected = expected_params("ENABLED", "2001:d80::/26", "13")
    task_queue_consumer.ecs_client.run_task.assert_called_once_with(**expected)


@pytest.mark.unit
@serialise_mocks()
@resetting_mocks(task_queue_consumer.ecs_client, task_queue_consumer.ssm_client.get_parameters)
def test_sanitises_input_ip4():
    task_queue_consumer.ssm_client.get_parameters.return_value = ssm_return_vals(False)
    task_queue_consumer.submit_scan_task(
        {"Records": [{"body": "123.3.2.124", "messageId": "13"}]},
        mock.MagicMock())
    expected = expected_params("ENABLED", "123.3.2.124", "13")
    task_queue_consumer.ecs_client.run_task.assert_called_once_with(**expected)


@pytest.mark.unit
@serialise_mocks()
@resetting_mocks(task_queue_consumer.ecs_client, task_queue_consumer.ssm_client.get_parameters)
def test_sanitises_input_ip6():
    task_queue_consumer.ssm_client.get_parameters.return_value = ssm_return_vals(False)
    task_queue_consumer.submit_scan_task(
        {"Records": [{"body": "2001:0db8:85a3:0000:0000:8a2e:0370:7334", "messageId": "13"}]},
        mock.MagicMock())
    expected = expected_params("ENABLED", "2001:0db8:85a3:0000:0000:8a2e:0370:7334", "13")
    task_queue_consumer.ecs_client.run_task.assert_called_once_with(**expected)


@pytest.mark.unit
@serialise_mocks()
@resetting_mocks(task_queue_consumer.ecs_client, task_queue_consumer.ssm_client.get_parameters)
def test_processes_batches():
    task_queue_consumer.ssm_client.get_parameters.return_value = ssm_return_vals(False)
    task_queue_consumer.submit_scan_task({
        "Records": [
            {"body": "2001:0db8:85a3:0000:0000:8a2e:0370:7334", "messageId": "13"},
            {"body": "123.3.2.124", "messageId": "14"},
            {"body": "scan.me.everyone", "messageId": "15"},
        ]}, mock.MagicMock())
    expected = [
        mock.call(**exp) for exp in
        [
            expected_params("ENABLED", "2001:0db8:85a3:0000:0000:8a2e:0370:7334", "13"),
            expected_params("ENABLED", "123.3.2.124", "14"),
            expected_params("ENABLED", "scan.me.everyone", "15")
        ]
    ]
    assert expected == task_queue_consumer.ecs_client.run_task.call_args_list


@pytest.mark.unit
@serialise_mocks()
@resetting_mocks(task_queue_consumer.ecs_client, task_queue_consumer.ssm_client.get_parameters)
def test_sanitises_input_multiple_targets():
    task_queue_consumer.ssm_client.get_parameters.return_value = ssm_return_vals(False)
    task_queue_consumer.submit_scan_task({
        "Records": [
            {"body": "2001:0db8:85a3:0000:0000:8a2e:0370:7334 123.3.2.124 scan.me.everyone", "messageId": "13"},
        ]}, mock.MagicMock())
    expected = expected_params("ENABLED", "2001:0db8:85a3:0000:0000:8a2e:0370:7334 123.3.2.124 scan.me.everyone", "13")
    task_queue_consumer.ecs_client.run_task.assert_called_once_with(**expected)


# Although testing injections by sample is a bad way to test, its good to see some basic scenarios
# covered
@pytest.mark.unit
@serialise_mocks()
@resetting_mocks(task_queue_consumer.ecs_client, task_queue_consumer.ssm_client.get_parameters)
def test_sanitises_input_dodgy_input():
    task_queue_consumer.ssm_client.get_parameters.return_value = ssm_return_vals(False)
    with pytest.raises(ValueError):
        task_queue_consumer.submit_scan_task(
            {"Records": [{"body": "; rm -rf", "messageId": "13"}]},
            mock.MagicMock())


# Although testing injections by sample is a bad way to test, its good to see some basic scenarios
# covered
@pytest.mark.unit
@serialise_mocks()
@resetting_mocks(task_queue_consumer.ecs_client, task_queue_consumer.ssm_client.get_parameters)
def test_sanitises_input_dodgy_input_url():
    task_queue_consumer.ssm_client.get_parameters.return_value = ssm_return_vals(False)
    with pytest.raises(ValueError):
        task_queue_consumer.submit_scan_task(
            {"Records": [{"body": "http://foo.bar?hello=foo; rm -rf", "messageId": "13"}]},
            mock.MagicMock())


@pytest.mark.unit
@serialise_mocks()
@resetting_mocks(task_queue_consumer.ecs_client.run_task, task_queue_consumer.ssm_client.get_parameters)
def test_raises_when_ecs_failures_present():
    task_queue_consumer.ssm_client.get_parameters.return_value = ssm_return_vals(False)
    task_queue_consumer.ecs_client.run_task.return_value = {'failures': [
        {'arn': 'arn::some:::arn', 'reason': 'failed miserably'}
    ]}
    with pytest.raises(RuntimeError, match=r"\{\"arn\": \"arn::some:::arn\", \"reason\": \"failed miserably\"\}"):
        task_queue_consumer.submit_scan_task({"Records": [{"body": "some.host", "messageId": "13"}]}, mock.MagicMock())


@pytest.mark.unit
@serialise_mocks()
@resetting_mocks(task_queue_consumer.ecs_client, task_queue_consumer.ssm_client.get_parameters)
def test_json_input_one_ip4():
    task_queue_consumer.ssm_client.get_parameters.return_value = ssm_return_vals(
        False)
    task_queue_consumer.submit_scan_task(
        {"Records": [
            {"body": "{\"CloudWatchEventHosts\":[\"123.3.2.124\"]}",
                "messageId": "13"}
        ]},
        mock.MagicMock())
    expected = expected_params("ENABLED", "123.3.2.124", "13-1")
    task_queue_consumer.ecs_client.run_task.assert_called_once_with(**expected)


@pytest.mark.unit
@serialise_mocks()
@resetting_mocks(task_queue_consumer.ecs_client, task_queue_consumer.ssm_client.get_parameters)
def test_json_input_multiple_targets_one_line():
    task_queue_consumer.ssm_client.get_parameters.return_value = ssm_return_vals(
        False)
    task_queue_consumer.submit_scan_task(
        {"Records": [
            {"body": "{\"CloudWatchEventHosts\":[\"123.3.2.124 scan.me.everyone\"]}",
                "messageId": "13"}
        ]},
        mock.MagicMock())
    expected = expected_params(
        "ENABLED", "123.3.2.124 scan.me.everyone", "13-1")
    task_queue_consumer.ecs_client.run_task.assert_called_once_with(**expected)


@pytest.mark.unit
@serialise_mocks()
@resetting_mocks(task_queue_consumer.ecs_client, task_queue_consumer.ssm_client.get_parameters)
def test_json_input_multiple_targets_comma_separated_list():
    task_queue_consumer.ssm_client.get_parameters.return_value = ssm_return_vals(
        False)
    task_queue_consumer.submit_scan_task(
        {"Records": [
            {"body": "{\"CloudWatchEventHosts\":[\"123.3.2.124\", \"scan.me.everyone\"]}",
                "messageId": "13"}
        ]},
        mock.MagicMock())
    expected = [
        mock.call(**exp) for exp in
        [
            expected_params("ENABLED", "123.3.2.124", "13-1"),
            expected_params("ENABLED", "scan.me.everyone", "13-2")
        ]
    ]
    assert expected == task_queue_consumer.ecs_client.run_task.call_args_list


@pytest.mark.unit
@serialise_mocks()
@resetting_mocks(task_queue_consumer.ecs_client.get_parameters, task_queue_consumer.ssm_client)
def test_json_input_multiple_targets_mixed():
    # test multiple targets in one line and comma separated
    task_queue_consumer.ssm_client.get_parameters.return_value = ssm_return_vals(
        False)
    task_queue_consumer.submit_scan_task(
        {"Records": [
            {"body": "{\"CloudWatchEventHosts\":[\"123.3.2.124 scan.me.everyone\", \"124.3.2.124\", \"scan1.me.everyone\"]}",
                "messageId": "13"}
        ]},
        mock.MagicMock())
    expected = [
        mock.call(**exp) for exp in
        [
            expected_params("ENABLED", "123.3.2.124 scan.me.everyone", "13-1"),
            expected_params("ENABLED", "124.3.2.124", "13-2"),
            expected_params("ENABLED", "scan1.me.everyone", "13-3")
        ]
    ]
    assert expected == task_queue_consumer.ecs_client.run_task.call_args_list
