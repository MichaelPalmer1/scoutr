import json

from scoutr.exceptions import HttpException
from scoutr.models.request import Request, RequestUser, UserData


def build_api_gateway_request(event: dict) -> Request:
    version = event.get('version', '1.0')

    if version == '1.0':
        return _build_version_1_request(event)
    # elif version == '2.0':
    #     return _build_version_2_request(event)
    else:
        raise Exception('Event version %s is not supported' % version)


def _build_version_1_request(event):
    request = Request(
        method=event['httpMethod'],
        path=event['path'],
        source_ip=event['requestContext']['identity']['sourceIp'],
        user_agent=event['requestContext']['identity']['userAgent'],
        user=_build_version_1_user(event)
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


def _build_version_1_user(event):
    return RequestUser(id=event['requestContext']['identity']['apiKeyId'], data=None)


def _build_version_2_request(event):
    request = Request(
        method=event['requestContext']['http']['method'],
        path=event['requestContext']['http']['path'],
        source_ip=event['requestContext']['http']['sourceIp'],
        user_agent=event['requestContext']['http']['userAgent'],
        user=_build_version_2_user(event)
    )

    query_params = event.get('queryStringParameters', {}) or {}
    if query_params:
        params = {}
        for key, value in query_params.items():
            if ',' in value:
                params[key] = value.split(',')
            else:
                params[key] = [value]
        request.query_params = params

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


def _build_version_2_user(event):
    user_id = event['requestContext']['authorizer']['jwt']['claims'].get('id')
    return RequestUser(
        id=user_id,
        data=UserData(
            **event['requestContext']['authorizer']['jwt']['claims']
        )
    )


def get_api_gateway_user(event: dict) -> RequestUser:
    version = event.get('version', '1.0')
    if version == '1.0':
        return _build_version_1_user(event)
    # elif version == '2.0':
    #     return _build_version_2_user(event)
    else:
        raise Exception('Event version %s is not supported' % version)


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
