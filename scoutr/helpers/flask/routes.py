from typing import Tuple

import simplejson
from flask import request
from flask_api import FlaskAPI
from flask_api.exceptions import ParseError
from werkzeug.middleware.proxy_fix import ProxyFix

from scoutr.helpers.flask.oidc import get_user_from_oidc, build_oidc_request
from scoutr.helpers.flask.utils import init_flask_user, flaskapi_exception_wrapper
from scoutr.providers.base.api import BaseAPI


def init_flask(api: BaseAPI, primary_list_endpoint: str, history_actions: Tuple[str] = ('CREATE', 'UPDATE')):
    """
    Initialize flask app

    :param scoutr.providers.base.api.BaseAPI api:
    :param str primary_list_endpoint:
    :param tuple of str history_actions:
    :return: Flask App
    :rtype: flask_api.FlaskAPI
    """
    # Make sure primary list endpoint is formatted as /endpoint/
    if not primary_list_endpoint.startswith('/'):
        primary_list_endpoint = '/' + primary_list_endpoint
    if not primary_list_endpoint.endswith('/'):
        primary_list_endpoint += '/'

    # Initialize the app
    app = FlaskAPI(__name__)
    app.wsgi_app = ProxyFix(app.wsgi_app)
    app.json_encoder = simplejson.JSONEncoder

    @app.before_request
    def before_request():
        request.user = init_flask_user(api, request)

    @app.route('/user/', methods=['GET'])
    @flaskapi_exception_wrapper
    def get_user():
        return request.user.dict()

    @app.route('/user/has-permission/', methods=['POST'])
    @flaskapi_exception_wrapper
    def check_user_permissions():
        if 'method' not in request.data or 'path' not in request.data:
            raise ParseError("Body should contain 'method' and 'path' keys")

        return {
            'authorized': api.can_access_endpoint(
                method=request.data['method'],
                path=request.data['path'],
                user=request.user,
                request=build_oidc_request(api, request)
            )
        }

    @app.route(primary_list_endpoint, methods=['GET'])
    @flaskapi_exception_wrapper
    def list_items():
        return api.list(request=build_oidc_request(api, request))

    @app.route('/audit/', methods=['GET'], defaults={'item': None})
    @app.route('/audit/<item>/', methods=['GET'])
    @flaskapi_exception_wrapper
    def audit(item):
        path_params = {}
        if item:
            path_params = {f'resource.{api.config.primary_key}': item}
        return api.list_audit_logs(
            request=build_oidc_request(api, request),
            param_overrides=path_params
        )

    @app.route('/history/<item>/', methods=['GET'])
    @flaskapi_exception_wrapper
    def history(item):
        return api.history(
            request=build_oidc_request(api, request),
            key=api.config.primary_key,
            value=item,
            actions=history_actions
        )

    @app.route('/search/<search_key>/', methods=['POST'])
    @flaskapi_exception_wrapper
    def search(search_key):
        return api.search(
            request=build_oidc_request(api, request),
            key=search_key,
            values=request.data
        )

    return app
