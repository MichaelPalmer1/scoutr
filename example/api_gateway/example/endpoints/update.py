import simplejson as json
import os

import sentry_sdk

from scoutr.helpers.api_gateway import build_api_gateway_request
from scoutr.dynamo import DynamoAPI
from scoutr.exceptions import HttpException

from example.constants import UPDATE_FIELDS
from example.utils import configure_sentry

configure_sentry()

def main(event, context):
    # Get item id
    item_id = event['pathParameters']['id']

    try:
        api = DynamoAPI(
            table_name=os.getenv('TableName'),
            auth_table_name=os.getenv('AuthTable'),
            group_table_name=os.getenv('GroupTable'),
            audit_table_name=os.getenv('AuditTable')
        )

        # Perform the update
        body = json.loads(event['body'])
        data = api.update(
            request=build_api_gateway_request(event),
            partition_key={'id': item_id},
            data=body,
            field_validation=UPDATE_FIELDS
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
