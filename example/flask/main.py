import os

import sentry_sdk
from flask import request
from sentry_sdk.integrations.flask import FlaskIntegration

from scoutr.dynamo import DynamoAPI
from scoutr.flask.oidc import build_oidc_request
from scoutr.flask.routes import init_flask
from scoutr.flask.utils import flaskapi_exception_wrapper

sentry_sdk.init(
    dsn='https://APIKEY@sentry.io/PROJECT-ID',
    integrations=[FlaskIntegration()],
    environment=os.getenv('ENV', 'dev'),
    release='PROJECT-NAME@VERSION'
)

api = DynamoAPI(
    table_name='scoutr',
    auth_table_name='scoutr-auth',
    group_table_name='scoutrgroups',
    audit_table_name='scoutr-audit',
)

app = init_flask(
    api=api,
    partition_key='item_id',
    primary_list_endpoint='/items/',
    group_attribute='groups'
)

@app.route("/item/", methods=['POST'])
@flaskapi_exception_wrapper
def create_item():
    """Create an item"""
    return api.create(
        request=build_oidc_request(request, 'groups'),
        item=request.data
    )

if __name__ == "__main__":
    app.run(debug=True)
