import os

try:
    import sentry_sdk
    has_sentry = True
except ImportError:
    has_sentry = False


class OIDCUser(object):
    def __init__(self, request, group_attribute=None):
        for key, value in request.headers.items():
            if key.startswith('Oidc-Claim-'):
                attr_name = key.split('Oidc-Claim-')[-1].lower().replace('-', '_').replace(' ', '_')

                if group_attribute and attr_name == group_attribute:
                    value = value.split(',')

                setattr(self, attr_name, value)


def get_oidc_user(user, group_attribute=None):
    try:
        return {
            'id': user.sub,
            'data': {
                'username': user.sub,
                'email': user.mail,
                'name': f'{user.firstname} {user.lastname}',
                'groups': getattr(user, group_attribute, []) if group_attribute else []
            }
        }
    except AttributeError as e:
        if os.getenv('DEBUG', 'false') == 'false':
            if has_sentry:
                sentry_sdk.capture_exception(e)
            return {'id': 'UNKNOWN'}
        else:
            # Return a dummy user when in debug mode
            return {
                'id': '222222222',
                'data': {
                    'username': '222222222',
                    'email': 'george.p.burdell@ge.com',
                    'name': 'George Burdell',
                    'groups': []
                }
            }


def build_oidc_request(request, group_attribute):
    from scoutr.helpers.flask import parse_query_params
    request_data = {
        'method': request.method,
        'path': request.path,
        'source_ip': request.remote_addr,
        'user_agent': request.user_agent.string,
        'user': get_oidc_user(request.user, group_attribute)
    }

    query_params = parse_query_params(request.query_string)
    if query_params:
        request_data.update({'query_params': query_params})

    if request.data:
        request_data.update({'body': request.data})

    return request_data
