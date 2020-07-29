import json


def build_api_gateway_request(event):
    request_data = {
        'method': event['httpMethod'],
        'path': event['path'],
        'source_ip': event['requestContext']['identity']['sourceIp'],
        'user_agent': event['requestContext']['identity']['userAgent'],
        'user': get_api_gateway_user(event)
    }

    query_params = event.get('multiValueQueryStringParameters', {}) or {}
    if query_params:
        request_data.update({'query_params': query_params})

    path_params = event.get('pathParameters', {}) or {}
    if path_params:
        request_data.update({'path_params': path_params})

    body = event.get('body', '{}') or '{}'
    if not isinstance(body, dict):
        try:
            body = json.loads(body)
        except json.JSONDecodeError:
            pass
    if body:
        request_data.update({'body': body})

    return request_data

def get_api_gateway_user(event):
    return {'id': event['requestContext']['identity']['apiKeyId']}
