import os

import boto3

from scoutr.models.config import Config

try:
    import sentry_sdk
    from sentry_sdk.integrations.aws_lambda import AwsLambdaIntegration
    has_sentry = True
except ImportError:
    has_sentry = False


def configure_sentry():
    if not has_sentry:
        return

    secret_id = os.getenv('SENTRY_DSN_SECRET_ID')
    if not secret_id:
        return

    # Pull from secrets manager
    secrets_manager = boto3.client('secretsmanager')
    dsn = secrets_manager.get_secret_value(secret_id)['SecretString']
    if dsn:
        sentry_sdk.init(
            dsn=dsn,
            integrations=[AwsLambdaIntegration()],
            environment=os.getenv('Stage')
        )


def get_config():
    return Config(
        data_table=os.getenv('TableName'),
        auth_table=os.getenv('AuthTable'),
        group_table=os.getenv('GroupTable'),
        audit_table=os.getenv('AuditTable'),
        primary_key='id'
    )
