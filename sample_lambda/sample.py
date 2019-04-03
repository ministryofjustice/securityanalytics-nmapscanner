from lambda_decorators import load_json_body, dump_json_body, async_handler


@load_json_body
@dump_json_body
@async_handler
async def sample(event, context):
    return {'statusCode': 200, 'body': {'message': 'hello lambda world', 'request': event}}
