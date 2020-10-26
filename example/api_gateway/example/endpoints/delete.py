import simplejson as json
import os

import sentry_sdk

from example.utils import get_config
from scoutr.helpers.api_gateway import build_api_gateway_request
from scoutr.providers.aws import DynamoAPI
from scoutr.exceptions import HttpException

from example.utils import configure_sentry

configure_sentry()


def main(event, context):
    # Get item id
    item_id = event['pathParameters']['id']

    try:
        api = DynamoAPI(get_config())

        # Perform deletion
        data = api.delete(
            request=build_api_gateway_request(event),
            partition_key={'id': item_id}
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
        'body': json.dumps(data)
    }
