import simplejson as json
import os

import sentry_sdk

from scoutr.dynamo import DynamoAPI
from scoutr.exceptions import HttpException

from example.utils import configure_sentry

configure_sentry()

def main(event, context):
    # Get parameters
    item = event['pathParameters']['id']
    query_params = event.get('queryStringParameters', {}) or {}

    try:
        api = DynamoAPI(
            table_name=os.getenv('TableName'),
            auth_table_name=os.getenv('AuthTable'),
            group_table_name=os.getenv('GroupTable'),
            audit_table_name=os.getenv('AuditTable')
        )

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
