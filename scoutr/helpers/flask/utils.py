from functools import wraps
from typing import List, Dict
from urllib.parse import parse_qsl

from flask_api.exceptions import NotFound, PermissionDenied, APIException, ParseError
from flask_api.request import APIRequest

from scoutr.exceptions import HttpException, UnauthorizedException, NotFoundException, BadRequestException
from scoutr.helpers.flask.oidc import get_user_from_oidc
from scoutr.models.request import RequestUser
from scoutr.providers.base.api import BaseAPI

try:
    import sentry_sdk
    has_sentry = True
except ImportError:
    has_sentry = False


def flaskapi_exception_wrapper(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except HttpException as e:
            if isinstance(e, UnauthorizedException):
                raise PermissionDenied(e.args)
            elif isinstance(e, NotFoundException):
                raise NotFound(e.args)
            elif isinstance(e, BadRequestException):
                raise ParseError(e.args)
            else:
                if has_sentry:
                    sentry_sdk.capture_exception(e)
                raise APIException(e.args)
        except Exception as e:
            if has_sentry:
                sentry_sdk.capture_exception(e)
            raise APIException('%s: %s' % (e.__class__.__name__, str(e)))
    return wrapper


def parse_query_params(query_string: bytes) -> Dict[str, List[str]]:
    params: Dict[str, List[str]] = {}

    for key, value in parse_qsl(query_string):
        key_str = key.decode('utf-8')
        value_str = value.decode('utf-8')
        params.setdefault(key_str, [])
        params[key_str].append(value_str)

    return params


def init_flask_user(api: BaseAPI, request: APIRequest) -> RequestUser:
    user = get_user_from_oidc(api, request)
    if has_sentry:
        import sentry_sdk
        with sentry_sdk.configure_scope() as scope:
            scope.set_user({
                'id': user.id,
                'ip_address': request.remote_addr,
                'username': user.data.username,
                'name': user.data.name,
                'email': user.data.email,
                'groups': user.data.groups
            })
    return user
