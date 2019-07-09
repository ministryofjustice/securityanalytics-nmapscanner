import pytest
import aioboto3
import os
from json import loads
import re
from .integration_test_helpers import QueueContextMgr
from asyncio import gather, sleep
from abc import ABC, abstractmethod
from concurrent.futures import CancelledError

MESSAGE_ID = re.compile(r"^([a-f0-9]{8}(-[a-f0-9]{4}){3}-[a-f0-9]{12}).*$")


class SqsToSnsServiceTester(ABC):
    def __init__(self, timeout_seconds=120):
        self.ssm_client = None
        self.sqs_client = None
        self.sns_client = None
        self.sqs_input_queue_url = None
        self.sns_output_notifier_arn = None
        self.gathering_coro = None
        self.region = os.environ["REGION"]
        self.stage = os.environ["STAGE"]
        self.app_name = os.environ["APP_NAME"]
        self.task_name = os.environ["TASK_NAME"]
        self.ssm_prefix = f"/{self.app_name}/{self.stage}"

        self.sqs_input_queue = f"{self.ssm_prefix}/tasks/{self.task_name}/task_queue/url"
        self.sns_output_notifier = f"{self.ssm_prefix}/tasks/{self.task_name}/results/arn"

        self.timeout = timeout_seconds
        self.incomplete = True

    async def __aenter__(self):
        self.ssm_client = aioboto3.client("ssm", region_name=self.region)
        self.sqs_client = aioboto3.client("sqs", region_name=self.region)
        self.sns_client = aioboto3.client("sns", region_name=self.region)

        params = await self.ssm_client.get_parameters(Names=[
            self.sqs_input_queue,
            self.sns_output_notifier
        ])
        params = {p["Name"]: p["Value"] for p in params["Parameters"]}

        self.sqs_input_queue_url = params[self.sqs_input_queue]
        self.sns_output_notifier_arn = params[self.sns_output_notifier]

        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await gather(
            self.ssm_client.close(),
            self.sns_client.close(),
            self.sqs_client.close()
        )

    @abstractmethod
    async def send_request(self):
        pass

    @abstractmethod
    async def handle_results(self, body):
        pass

    async def run_test(self):
        async with self, QueueContextMgr(
                self.sqs_client,
                self.sns_client,
                self.sns_output_notifier_arn,
                self.task_name
        ) as queue_context:
            self.gathering_coro = gather(
                self.poll_responses(queue_context.queue_url),
                self.failure_timeout(),
                self.send_request()
            )
            try:
                await self.gathering_coro
            except CancelledError:
                print("Test was terminated")

    async def poll_responses(self, queue_url):
        while self.incomplete:
            print("Polling...", flush=True)
            poll_resp = await self.sqs_client.receive_message(
                QueueUrl=queue_url,
                MaxNumberOfMessages=1,
                VisibilityTimeout=20,
                WaitTimeSeconds=10
            )
            if "Messages" in poll_resp:
                message = poll_resp["Messages"][0]
                receipt_handle = message["ReceiptHandle"]

                # Delete received message from queue
                await self.sqs_client.delete_message(
                    QueueUrl=queue_url,
                    ReceiptHandle=receipt_handle
                )

                await self.handle_results(message["Body"])

    async def cancel_polling(self):
        print("Cancelling results polling...", flush=True)
        self.incomplete = False
        self.gathering_coro.cancel()

    async def failure_timeout(self):
        await sleep(self.timeout)
        await self.cancel_polling()
        raise AssertionError("Testcase timed out")


@pytest.mark.asyncio
@pytest.mark.integration
async def test_integration():
    timeout = 120

    class NmapIntegrationTester(SqsToSnsServiceTester):
        def __init__(self, timeout_seconds=120):
            super().__init__(timeout_seconds)
            self.request_msg_id = None

        async def send_request(self):
            resp = await self.sqs_client.send_message(
               QueueUrl=self.sqs_input_queue_url,
               # TODO relying on an external resource like this is error prone and unreliable,
               # we should setup a host to scan as part of the test setup instead
               MessageBody="scanme.nmap.org"
            )
            self.request_msg_id = resp["MessageId"]
            print(f"Made request {self.request_msg_id}")

        async def handle_results(self, body):
            result = loads(loads(body)["Message"])
            scan_id = result["scan_id"]

            # TODO need a proper tracing id, this pulling out of the scan of the original
            # input queue message id is not good enough
            original_msg_id_from_scan_id = re.match(MESSAGE_ID, scan_id)[1]
            if original_msg_id_from_scan_id == self.request_msg_id:
                assert True
                print(f"Have received results for initial request with message id {self.request_msg_id}", flush=True)
                await self.cancel_polling()

    await NmapIntegrationTester(timeout).run_test()
