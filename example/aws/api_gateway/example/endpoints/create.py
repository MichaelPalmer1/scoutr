import simplejson as json
import os

import sentry_sdk

from example.utils import get_config
from scoutr.helpers.api_gateway import build_api_gateway_request
from scoutr.providers.aws import DynamoAPI
from scoutr.exceptions import HttpException

from example.constants import CREATE_FIELDS
from example.utils import configure_sentry

configure_sentry()


def main(event, context):
    try:
        api = DynamoAPI(get_config())
        item = json.loads(event['body'])

        # Perform field validation
        data = api.create(
            request=build_api_gateway_request(event),
            data=item,
            validation=CREATE_FIELDS
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
