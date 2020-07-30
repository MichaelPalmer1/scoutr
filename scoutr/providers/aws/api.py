from typing import List

import boto3
import mypy_boto3_dynamodb as dynamodb

from scoutr.models.request import Request
from scoutr.models.user import User
from scoutr.providers.aws.filtering import AWSFiltering
from scoutr.providers.base.api import BaseAPI


class DynamoAPI(BaseAPI):
    filter = AWSFiltering()

    def __init__(self):
        resource: dynamodb.DynamoDBServiceResource = boto3.resource('dynamodb')
        self.client = resource.Table(self.get_config().get('data_table'))

    def get_auth(self, user_id: str) -> User:
        # Try to find user in the auth table
        result: dict = self.client.get_item(Key={'id': user_id})

        if not result.get('Item'):
            return

        # Create user object
        return User.load(result['Item'])

    def get_group(self, group_id: str) -> User:
        pass

    def get_config(self):
        pass

    def initialize_request(self, request: Request) -> User:
        pass

    def create(self, request: Request, data: dict, validation: dict) -> dict:
        pass

    def update(self, request: Request, partition_key: dict, data: dict, validation: dict) -> dict:
        pass

    def get(self, request: Request, record: str) -> dict:
        pass

    def list(self, request: Request) -> List[dict]:
        pass

    def list_unique_values(self, request: Request, key: str) -> List[str]:
        pass

    def list_audit_logs(self, request: Request, path_params: dict, query_params: dict) -> List[dict]:
        pass

    def history(self, request: Request, key: str, value: str, query_params: dict, actions: List[str]) -> List[dict]:
        pass

    def search(self, request: Request, key: str, values: List[str]) -> List[dict]:
        pass

    def delete(self, request: Request, partition_key: dict):
        pass
