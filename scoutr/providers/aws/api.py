from typing import List, Union, Dict

import boto3
import mypy_boto3_dynamodb as dynamodb
from botocore.exceptions import ClientError

from scoutr.models.request import Request
from scoutr.models.user import User, Group
from scoutr.providers.aws.filtering import AWSFiltering
from scoutr.providers.base.api import BaseAPI


class DynamoAPI(BaseAPI):
    filtering = AWSFiltering()

    def __init__(self, **kwargs):
        super(DynamoAPI, self).__init__(**kwargs)
        resource: dynamodb.DynamoDBServiceResource = boto3.resource('dynamodb')
        self.resource = resource
        self.client = resource.Table(self.config.data_table)

    def get_auth(self, user_id: str) -> Union[User, None]:
        # Try to find user in the auth table
        result: dict = self.client.get_item(Key={'id': user_id})

        if not result.get('Item'):
            return None

        # Create user object
        return User.load(result['Item'])

    def get_group(self, group_id: str) -> Group:
        pass

    def store_item(self, table: str, item: dict) -> bool:
        try:
            self.resource.Table(table).put_item(Item=item)
        except ClientError as e:
            print('Failed to store record: %s', e)
            return False

        return True

    @staticmethod
    def _scan(resource, **kwargs):
        response = resource.scan(**kwargs)
        items = response['Items']
        while response.get('LastEvaluatedKey', False):
            kwargs.update({'ExclusiveStartKey': response['LastEvaluatedKey']})
            response = resource.scan(**kwargs)
            items.extend(response['Items'])
        return items

    def create(self, request: Request, data: dict, validation: dict) -> dict:
        pass

    def update(self, request: Request, partition_key: dict, data: dict, validation: dict) -> dict:
        pass

    def get(self, request: Request, record: str) -> dict:
        pass

    def list(self, request: Request) -> List[dict]:
        user = self.initialize_request(request)

        params: Dict[str, str] = {}
        params.update(request.query_params)
        params.update(request.path_params)

        # Generate dynamo search
        search_key = request.path_params.get('search_key')
        search_value = request.path_params.get('search_value')
        if search_key and search_value:
            # Map the search key and value into params
            params[search_key] = search_value
            del params['search_key']
            del params['search_value']

        args = {}
        conditions = self.filtering.filter(user, params)
        if conditions:
            args.update({'FilterExpression': conditions})

        data = self._scan(self.client, **args)
        data = self.post_process(data, user)

        self.audit_log('LIST', request, user)

        return data

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
