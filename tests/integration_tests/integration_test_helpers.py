from utils.json_serialisation import dumps
from datetime import datetime


class QueueContextMgr:
    def __init__(self, sqs_client, sns_client, sns_output_notifier_arn, task_name):
        self.task_name = task_name
        self.queue_name = f"{task_name}{int(datetime.now().timestamp())}"
        print(f"Using temporary queue {self.queue_name}", flush=True)
        self.sqs_client = sqs_client
        self.sns_client = sns_client
        self.sns_output_notifier_arn = sns_output_notifier_arn
        self.queue_url = None
        self.queue_arn = None
        self.subscription = None

    async def __aenter__(self):
        queue = await self.sqs_client.create_queue(QueueName=self.queue_name)
        self.queue_url = queue["QueueUrl"]

        response = await self.sqs_client.get_queue_attributes(
            QueueUrl=self.queue_url,
            AttributeNames=["QueueArn"]
        )

        self.queue_arn = response["Attributes"]["QueueArn"]

        # ensure we can subscribe too
        await self.sqs_client.set_queue_attributes(
            QueueUrl=self.queue_url,
            Attributes={
                'Policy': dumps({
                    "Version": "2008-10-17",
                    "Id": f"{self.queue_arn}/SQSDefaultPolicy",
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Principal": "*",
                            "Action": "SQS:SendMessage",
                            "Resource": self.queue_arn
                        }
                    ]
                })
            }
        )

        self.subscription = (
            await self.sns_client.subscribe(
                TopicArn=self.sns_output_notifier_arn,
                Protocol="sqs",
                Endpoint=self.queue_arn
            )
        )["SubscriptionArn"]

        print(f"Subscribed {self.queue_name} to {self.task_name}", flush=True)
        return self

    async def __aexit__(self, type, value, traceback):
        try:
            if self.subscription:
                await self.sns_client.unsubscribe(SubscriptionArn=self.subscription)
                print(f"Unsubscribed {self.queue_name} from {self.task_name}", flush=True)
        finally:
            if self.queue_url:
                await self.sqs_client.delete_queue(QueueUrl=self.queue_url)
                print(f"Deleted temporary queue {self.queue_name}", flush=True)
