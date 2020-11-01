# import sentry_sdk
from flask import request
# from sentry_sdk.integrations.flask import FlaskIntegration
from scoutr.models.config import MongoConfig
from scoutr.helpers.flask.oidc import build_oidc_request
from scoutr.helpers.flask.routes import init_flask
from scoutr.helpers.flask.utils import flaskapi_exception_wrapper

# sentry_sdk.init(
#     dsn='https://APIKEY@sentry.io/PROJECT-ID',
#     integrations=[FlaskIntegration()],
#     environment=os.getenv('ENV', 'dev'),
#     release='PROJECT-NAME@VERSION'
# )
from scoutr.providers.mongo import MongoAPI

config = MongoConfig(
    data_table='scoutr_data',
    auth_table='scoutr_auth',
    group_table='scoutr_groups',
    audit_table='scoutr_audit',
    primary_key='id',
    oidc_username_header='Oidc-Claim-Sub',
    oidc_name_header='Oidc-Claim-Name',
    oidc_email_header='Oidc-Claim-Mail',
    oidc_group_header='Oidc-Claim-Groups',
    database='scoutr',
    connection_string='mongodb://localhost'
)

# Create Scoutr instance
api = MongoAPI(config)
app = init_flask(
    api=api,
    primary_list_endpoint='/items/',
)


@app.route('/item/<item>/', methods=['GET'])
@flaskapi_exception_wrapper
def get_item(item):
    """Get an item"""
    return api.get(
        request=build_oidc_request(api, request),
        key=api.config.primary_key,
        value=item
    )


@app.route("/item/", methods=['POST'])
@flaskapi_exception_wrapper
def create_item():
    """Create an item"""
    return api.create(
        request=build_oidc_request(api, request),
        data=request.data
    )


@app.route("/names/", methods=['GET'])
@flaskapi_exception_wrapper
def list_names():
    """List unique values for name"""
    return api.list_unique_values(
        request=build_oidc_request(api, request),
        key='name'
    )


if __name__ == "__main__":
    app.run(debug=True)
