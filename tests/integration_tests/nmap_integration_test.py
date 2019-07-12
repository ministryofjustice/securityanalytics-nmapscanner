import pytest
from json import loads
import re
from tests.scan_integration_test_utils.scan_integration_tester import ScanIntegrationTester

MESSAGE_ID = re.compile(r"^([a-f0-9]{8}(-[a-f0-9]{4}){3}-[a-f0-9]{12}).*$")


@pytest.mark.integration
@pytest.mark.asyncio
async def test_integration():
    timeout = 600

    class NmapIntegrationTester(ScanIntegrationTester):
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
