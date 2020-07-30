from functools import wraps
from urllib.parse import parse_qsl

from flask_api.exceptions import NotFound, PermissionDenied, APIException, ParseError

from scoutr.exceptions import HttpException, UnauthorizedException, NotFoundException, BadRequestException
from scoutr.helpers.flask.oidc import OIDCUser, get_oidc_user

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


def parse_query_params(query_string):
    return {
        key.decode('utf-8'): value.decode('utf-8')
        for key, value in parse_qsl(query_string)
    }


def init_flask_user(request, group_attribute=None):
    user = OIDCUser(request, group_attribute)
    if has_sentry:
        with sentry_sdk.configure_scope() as scope:
            oidc_user = get_oidc_user(user)
            sentry_user = {'id': oidc_user['id']}
            sentry_user.update({'ip_address': request.remote_addr})
            for key, value in oidc_user.get('data', {}).items():
                sentry_user[key] = value
            scope.user = sentry_user
    return user
