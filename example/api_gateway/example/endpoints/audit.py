import simplejson as json
import os

import sentry_sdk

from scoutr.api_gateway.utils import build_api_gateway_request
from scoutr.dynamo import DynamoAPI
from scoutr.exceptions import HttpException
from example.utils import configure_sentry

configure_sentry()

def main(event, context):
    # Get parameters
    path_params = event.get('pathParameters', {}) or {}
    query_params = event.get('multiValueQueryStringParameters', {}) or {}

    try:
        api = DynamoAPI(
            table_name=os.getenv('TableName'),
            auth_table_name=os.getenv('AuthTable'),
            group_table_name=os.getenv('GroupTable'),
            audit_table_name=os.getenv('AuditTable')
        )

        # Validate item id
        item = path_params.get('item')
        if item:
            search_params = {'resource.id': item}
        else:
            search_params = {}

        # Perform the search
        data = api.list_audit_logs(
            request=build_api_gateway_request(event),
            search_params=search_params,
            query_params=query_params
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
