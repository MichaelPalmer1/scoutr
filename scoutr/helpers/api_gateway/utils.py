import json

from scoutr.exceptions import HttpException
from scoutr.models.request import Request, RequestUser


def build_api_gateway_request(event: dict) -> Request:
    request = Request(
        method=event['httpMethod'],
        path=event['path'],
        source_ip=event['requestContext']['identity']['sourceIp'],
        user_agent=event['requestContext']['identity']['userAgent'],
        user=get_api_gateway_user(event)
    )

    query_params = event.get('multiValueQueryStringParameters', {}) or {}
    if query_params:
        request.query_params = query_params

    path_params = event.get('pathParameters', {}) or {}
    if path_params:
        request.path_params = path_params

    body = event.get('body', '{}') or '{}'
    if not isinstance(body, dict):
        try:
            body = json.loads(body)
        except json.JSONDecodeError:
            pass
    if body:
        request.body = body

    return request


def get_api_gateway_user(event: dict) -> RequestUser:
    return RequestUser(id=event['requestContext']['identity']['apiKeyId'], data=None)


def handle_http_exception(e: HttpException):
    if len(e.args) == 1 and isinstance(e.args[0], (list, dict)):
        return {
            'statusCode': e.status,
            'body': json.dumps({'errors': e.args[0]})
        }

    return {
        'statusCode': e.status,
        'body': json.dumps({'error': str(e)})
    }
