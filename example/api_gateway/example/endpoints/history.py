import simplejson as json
import os

import sentry_sdk

from example.api_gateway.example.utils import get_config
from scoutr.providers.aws import DynamoAPI
from scoutr.exceptions import HttpException

from example.utils import configure_sentry

configure_sentry()

def main(event, context):
    # Get parameters
    item = event['pathParameters']['id']
    query_params = event.get('multiValueQueryStringParameters', {}) or {}

    try:
        api = DynamoAPI(get_config())

        # Fetch the item's history
        history = api.history(
            key='id',
            value=item,
            query_params=query_params,
            actions=('CREATE', 'UPDATE', 'DELETE')
        )

    except HttpException as e:
        if e.status == 500:
            sentry_sdk.capture_exception(e)
        return {
            'statusCode': e.status,
            'body': json.dumps({'error': str(e)})
        }

    except Exception as e:
        sentry_sdk.capture_exception(e)
        return {
            'statusCode': 500,
            'body': json.dumps({'error': '%s: %s' % (e.__class__.__name__, str(e))})
        }

    return {
        'statusCode': 200,
        'body': json.dumps(history)
    }
