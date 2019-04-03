import pytest
import json
from unittest.mock import MagicMock
from sample_lambda.sample import sample


@pytest.mark.unit
def test_lambda():
    event = {'foo': 'bar'}
    result = sample(event, MagicMock())
    assert result['statusCode'] == 200
    assert result['body'] == json.dumps({'message': 'hello lambda world', 'request': {'foo': 'bar'}})

