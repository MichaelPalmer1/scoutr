import json
import logging
from copy import deepcopy
from typing import List, Union, Dict, Tuple

import boto3
import mypy_boto3_dynamodb as dynamodb
from botocore.exceptions import ClientError

from scoutr.exceptions import NotFoundException
from scoutr.models.config import Config
from scoutr.models.request import Request
from scoutr.models.user import User, Group
from scoutr.providers.aws.filtering import AWSFiltering
from scoutr.providers.base.api import BaseAPI

try:
    import sentry_sdk
    has_sentry = True
except ImportError:
    has_sentry = False

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)


class DynamoAPI(BaseAPI):
    filtering = AWSFiltering()

    def __init__(self, config: Config):
        super(DynamoAPI, self).__init__(config)
        resource: dynamodb.DynamoDBServiceResource = boto3.resource('dynamodb')
        self.resource = resource
        self.data_table = resource.Table(self.config.data_table)
        self.auth_table = resource.Table(self.config.auth_table)
        self.group_table = resource.Table(self.config.group_table)
        self.audit_table = resource.Table(self.config.audit_table)

    def get_auth(self, user_id: str) -> Union[User, None]:
        # Try to find user in the auth table
        result: dict = self.auth_table.get_item(Key={'id': user_id})

        if not result.get('Item'):
            return None

        # Create user object
        return User.load(result['Item'])

    def get_group(self, group_id: str) -> Group:
        # Try to find user in the auth table
        result: dict = self.group_table.get_item(Key={'group_id': group_id})

        if not result.get('Item'):
            return None

        # Create user object
        return Group.load(result['Item'])

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

    def create(self, request: Request, data: dict, validation: dict = None) -> dict:
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

        data = self._scan(self.data_table, **args)
        data = self.post_process(data, user)

        self.audit_log('LIST', request, user)

        return data

    def list_unique_values(self, request: Request, key: str) -> List[str]:
        pass

    def list_audit_logs(self, request: Request, param_overrides: dict = None) -> List[dict]:
        if not self.config.audit_table:
            raise NotFoundException('Audit logs are not enabled')

        if param_overrides is None:
            param_overrides = {}

        # Merge parameter overrides into query params
        request.query_params.update(param_overrides)

        # Get user
        user = self.initialize_request(request)

        # Build filters
        args = {}
        conditions = self.filtering.filter(None, request.query_params)
        if conditions:
            args['FilterExpression'] = conditions

        # Download data
        try:
            data = self._scan(self.audit_table, **args)
        except ClientError as e:
            logger.error(
                '[%(user)s] Encountered error while attempting to list audit logs: [%(code)s] %(error)s' % {
                    'user': self.user_identifier(user),
                    'code': e.response['Error']['Code'],
                    'error': e.response['Error']['Message']
                }
            )
            raise
        except Exception as e:
            logger.error(
                '[%(user)s] Encountered error while attempting to list audit logs: %(error)s' % {
                    'user': self.user_identifier(user),
                    'error': str(e)
                }
            )
            raise

        # Add sentry breadcrumb
        if has_sentry:
            sentry_sdk.add_breadcrumb(
                category='query',
                message=args.get('FilterExpression', 'Scanned table'),
                level='info',
                table=self.config.audit_table
            )

        # Sort the data
        data = sorted(data, key=lambda item: item['time'], reverse=True)

        return data

    def history(self, request: Request, key: str, value: str, actions: tuple = ('CREATE', 'UPDATE', 'DELETE')) -> List[dict]:
        if not self.config.audit_table:
            raise NotFoundException('Audit logs are not enabled')

        param_overrides = {
            f'resource.{key}': value,
            'action__in': json.dumps(actions)
        }

        # Get user
        user = self.initialize_request(request)

        # Get the audit logs (reverse results so oldest item is first)
        logs = self.list_audit_logs(request, param_overrides)[::-1]

        # Check for no results
        if len(logs) == 0:
            return []

        # Get the original record
        current_item: dict = {'data': {}, 'time': None}
        for item in logs:
            if item['action'] == 'CREATE':
                current_item['time'] = item['time']
                current_item['data'] = item['body']
                break

        # Build the record history
        history = [current_item]
        for item in logs:
            # Skip creation calls
            if item['action'] == 'CREATE':
                continue
            elif item['action'] == 'DELETE':
                history.insert(0, {'time': item['time'], 'data': {}})
                continue

            # Make a full copy of the current item
            current_item = deepcopy(current_item)

            # Update the current item with the changes
            current_item['time'] = item['time']
            current_item['data'].update(item.get('body', {}))

            # Insert at the top of the history (i.e. most recent first)
            history.insert(0, current_item)

        return history

    def search(self, request: Request, key: str, values: List[str]) -> List[dict]:
        pass

    def delete(self, request: Request, partition_key: dict):
        pass
