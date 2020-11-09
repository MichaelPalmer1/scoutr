import os

# import sentry_sdk
import random
import time

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


def wait_random_time(value, item, existing_item=None):
    random.seed(time.time())
    delay = random.randint(1, 5)
    print('waiting for %s seconds' % delay)
    time.sleep(delay)
    print('done waiting')

    if random.choice([True, False]):
        raise Exception('failure triggered')


@app.route("/item/", methods=['POST'])
@flaskapi_exception_wrapper
def create_item():
    """Create an item"""
    return api.create(
        request=build_oidc_request(api, request),
        data=request.data,
        validation={
            'val1': wait_random_time,
            'val2': wait_random_time,
            'val3': wait_random_time,
            'val4': wait_random_time
        }
    )


if __name__ == "__main__":
    app.run(debug=True)
