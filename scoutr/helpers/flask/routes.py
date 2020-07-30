import simplejson
from flask import request
from flask_api import FlaskAPI
from flask_api.exceptions import ParseError
from werkzeug.middleware.proxy_fix import ProxyFix

from scoutr.helpers.flask.oidc import get_oidc_user, build_oidc_request
from scoutr.helpers.flask import init_flask_user, flaskapi_exception_wrapper, parse_query_params


def init_flask(api, partition_key, primary_list_endpoint, history_actions=('CREATE', 'UPDATE'), group_attribute=None):
    """
    Initialize flask app

    :param simple_api.dynamo.DynamoAPI api:
    :param str partition_key:
    :param str primary_list_endpoint:
    :param tuple of str history_actions:
    :param str group_attribute:
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
        request.user = init_flask_user(request, group_attribute)

    @app.route('/user/', methods=['GET'])
    @flaskapi_exception_wrapper
    def get_user():
        user = get_oidc_user(request.user, group_attribute)
        user_data = user.get('data', {})
        return {
            'username': user_data.get('username'),
            'name': user_data.get('name'),
            'email': user_data.get('email')
        }

    @app.route('/user/has-permission/', methods=['POST'])
    @flaskapi_exception_wrapper
    def check_user_permissions():
        if 'method' not in request.data or 'path' not in request.data:
            raise ParseError("Body should contain 'method' and 'path' keys")

        return {
            'authorized': api.can_access_endpoint(
                method=request.data['method'],
                path=request.data['path'],
                request=build_oidc_request(request, group_attribute)
            )
        }

    @app.route(primary_list_endpoint, methods=['GET'])
    @flaskapi_exception_wrapper
    def list_items():
        return api.list_table(
            request=build_oidc_request(request, group_attribute),
            query_params=parse_query_params(request.query_string)
        )

    @app.route('/audit/', methods=['GET'], defaults={'item': None})
    @app.route('/audit/<item>/', methods=['GET'])
    @flaskapi_exception_wrapper
    def audit(item):
        search_params = {}
        if item:
            search_params = {f'resource.{partition_key}': item}
        return api.list_audit_logs(
            request=build_oidc_request(request, group_attribute),
            search_params=search_params,
            query_params=parse_query_params(request.query_string)
        )

    @app.route('/history/<item>/', methods=['GET'])
    @flaskapi_exception_wrapper
    def history(item):
        return api.history(
            request=build_oidc_request(request, group_attribute),
            key=partition_key,
            value=item,
            query_params=parse_query_params(request.query_string),
            actions=history_actions
        )

    @app.route('/search/<search_key>/', methods=['POST'])
    @flaskapi_exception_wrapper
    def search(search_key):
        return api.search(
            request=build_oidc_request(request, group_attribute),
            key=search_key,
            values=request.data
        )

    return app
