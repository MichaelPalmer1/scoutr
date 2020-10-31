import os

# import sentry_sdk
from flask import request
# from sentry_sdk.integrations.flask import FlaskIntegration
from scoutr.models.config import Config
from scoutr.providers.aws.api import DynamoAPI
from scoutr.helpers.flask.oidc import build_oidc_request
from scoutr.helpers.flask.routes import init_flask
from scoutr.helpers.flask.utils import flaskapi_exception_wrapper

# sentry_sdk.init(
#     dsn='https://APIKEY@sentry.io/PROJECT-ID',
#     integrations=[FlaskIntegration()],
#     environment=os.getenv('ENV', 'dev'),
#     release='PROJECT-NAME@VERSION'
# )

config = Config(
    data_table='data',
    auth_table='auth',
    group_table='groups',
    audit_table='audit',
    primary_key='id',
    oidc_username_header='Oidc-Claim-Sub',
    oidc_name_header='Oidc-Claim-Name',
    oidc_email_header='Oidc-Claim-Mail',
    oidc_group_header='Oidc-Claim-Groups'
)

api = DynamoAPI(config)
app = init_flask(
    api=api,
    primary_list_endpoint='/items/',
)


@app.route("/item/", methods=['POST'])
@flaskapi_exception_wrapper
def create_item():
    """Create an item"""
    return api.create(
        request=build_oidc_request(api, request),
        data=request.data
    )


if __name__ == "__main__":
    app.run(debug=True)
