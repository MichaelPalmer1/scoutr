import logging
from typing import List, Dict, Optional, Any, Callable, Tuple, Union

import boto3
from mypy_boto3_dynamodb.service_resource import DynamoDBServiceResource
from boto3.dynamodb.conditions import Attr
from botocore.exceptions import ClientError

from scoutr.exceptions import NotFoundException, BadRequestException
from scoutr.models.config import Config
from scoutr.models.request import Request
from scoutr.models.user import User, Group
from scoutr.providers.aws.filtering import AWSFiltering
from scoutr.providers.base.api import BaseAPI

try:
    import sentry_sdk
except ImportError:
    from scoutr.utils import mock_sentry
    sentry_sdk = mock_sentry

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)


class DynamoAPI(BaseAPI):
    filtering = AWSFiltering()

    def __init__(self, config: Config):
        super(DynamoAPI, self).__init__(config)
        resource: DynamoDBServiceResource = boto3.resource('dynamodb')
        self.resource = resource
        self.data_table = resource.Table(self.config.data_table)
        self.auth_table = resource.Table(self.config.auth_table)
        self.group_table = resource.Table(self.config.group_table)
        self.audit_table = resource.Table(self.config.audit_table)

    def get_auth(self, user_id: str) -> Optional[User]:
        # Try to find user in the auth table
        result = self.auth_table.get_item(Key={'id': user_id})

        if not result.get('Item'):
            return None

        # Create user object
        return User.load(result['Item'])

    def get_group(self, group_id: str) -> Optional[Group]:
        # Try to find user in the auth table
        result = self.group_table.get_item(Key={'id': group_id})

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

    def create(self, request: Request, data: dict, validation: dict = None,
               required_fields: Union[List, Tuple] = ()) -> dict:
        """
        Create an item

        :param Request request: Request object
        :param dict data: Item to create
        :param dict validation: Optional dictionary containing mappings of field name to callable. See the docstring
        in the _validate_fields method for more information.
        :param list required_fields: Optional list of required fields
        :return: Created item
        :rtype: dict
        """
        user = self._prepare_create(request, data, validation, required_fields)

        # Build condition to ensure the unique key does not exist
        resource: Dict[str, str] = {}
        conditions = self.filtering.filter(user, None)
        for schema in self.data_table.key_schema:
            resource.update({schema['AttributeName']: data.get(schema['AttributeName'])})
            conditions = self.filtering.And(
                conditions,
                Attr(schema['AttributeName']).not_exists()
            )

        try:
            self.data_table.put_item(Item=data, ConditionExpression=conditions)
            logger.info('[%(user)s] Successfully created item:\n%(item)s' % {
                'user': self.user_identifier(user),
                'item': data
            })
        except ClientError as e:
            if e.response['Error']['Code'] == 'ConditionalCheckFailedException':
                logger.warning('[%(user)s] Unable to create item because the conditional check failed:\n%(item)s' % {
                    'user': self.user_identifier(user),
                    'item': data
                })
                raise BadRequestException('Item already exists or you do not have permission to create it.')
            elif e.response['Error']['Code'] == 'ValidationException':
                logger.error('[%(user)s] Validation error - %(error)s:\n%(item)s' % {
                    'user': self.user_identifier(user),
                    'error': e.response['Error']['Message'],
                    'item': data
                })
                raise BadRequestException(e.response['Error']['Message'])
            logger.error(
                '[%(user)s] Encountered error while attempting to create record '
                '[%(code)s] %(error)s. Item:\n%(item)s' % {
                    'user': self.user_identifier(user),
                    'code': e.response['Error']['Code'],
                    'error': e.response['Error']['Message'],
                    'item': data
                }
            )
            raise
        except Exception as e:
            logger.error(
                '[%(user)s] Encountered error while attempting to create record %(error)s. Item:\n%(item)s' % {
                    'user': self.user_identifier(user),
                    'error': str(e),
                    'item': data
                }
            )
            raise

        sentry_sdk.add_breadcrumb(category='data', message='Created item', level='info')

        # Create audit log
        self.audit_log(action='CREATE', resource=resource, request=request, user=user)

        return resource

    def update(self, request: Request, primary_key: dict, data: dict, validation: dict = None, condition=None,
               condition_failure_message='', audit_action='UPDATE') -> dict:
        """
        Update an item

        :param Request request: Request object
        :param dict primary_key: Dictionary formatted as {"primary_key": "value_of_row_to_update"}
        :param dict data: Fields to update, formatted as {"key": "value"}
        :param dict validation: Optional dictionary containing mappings of field name to callable. See the
        docstring in the _validate_fields method for more information.
        :param dict condition: Optional condition expression to apply to this update. If the condition fails to return
        successful, then this item will not be updated.
        :param str condition_failure_message: If the conditional check fails, this optional error message
        will be displayed to the user.
        :param str audit_action: Action to use in the audit log. This defaults to UPDATE, and is provided as a
        convenience to the user in case customizing the phrasing is desired. This cannot be one of the reserved
        built-in actions: CREATE, DELETE, GET, LIST, SEARCH.
        :return: Updated item
        :rtype: dict
        """
        # Get user
        user = self.initialize_request(request)

        # Validate audit action
        audit_action = audit_action.upper()
        if audit_action in ('CREATE', 'DELETE', 'GET', 'LIST', 'SEARCH'):
            raise Exception('%s is a reserved built-in audit action' % audit_action)

        # Get the existing item / make sure it actually exists and user has permission to access it
        base_conditions = None
        for key, value in primary_key.items():
            # Check if the partition key is specified in the data input
            if key in data:
                raise BadRequestException('Partition key cannot be updated')

            cond = Attr(key).eq(value)
            if base_conditions:
                base_conditions &= cond
            else:
                base_conditions = cond

        # Check user update permissions
        self.validate_update(user, data)

        # Add in the user's permissions
        user_conditions = self.filtering.filter(user)
        if user_conditions:
            if base_conditions:
                base_conditions &= user_conditions
            else:
                base_conditions = user_conditions

        # Get the existing item
        existing_item = self._scan(self.data_table, FilterExpression=base_conditions)
        if len(existing_item) == 0:
            logger.info('[%(user)s] Partition key "%(primary_key)s" does not exist or user does '
                        'not have permission to access it' % {
                            'user': self.user_identifier(user),
                            'primary_key': primary_key
                        })
            raise NotFoundException('Item does not exist or you do not have permission to access it')
        elif len(existing_item) > 1:
            # Should not have found more than one item
            raise BadRequestException('Multiple items found')

        # Found the item
        existing_item = existing_item[0]

        # Perform field validation
        if validation:
            self.validate_fields(
                validation=validation,
                required_fields=(),
                item=data,
                existing_item=existing_item
            )
            sentry_sdk.add_breadcrumb(category='validate', message='Validated input fields', level='info')

        # Build the update expression
        updates = []
        names = {}
        values = {}
        for key, value in data.items():
            names['#' + key] = key
            values[':' + key] = value
            updates.append(f'#{key} = :{key}')
        update_expression = 'SET ' + ', '.join(updates)

        # Perform the update item call
        try:
            args = {}
            if condition:
                args['ConditionExpression'] = condition

            response = self.data_table.update_item(
                Key=primary_key,
                UpdateExpression=update_expression,
                ExpressionAttributeNames=names,
                ExpressionAttributeValues=values,
                ReturnValues='ALL_NEW',
                **args
            )
            logger.info('[%(user)s] Successfully updated record "%(primary_key)s" with values:\n%(item)s' % {
                'user': self.user_identifier(user),
                'primary_key': primary_key,
                'item': data
            })
        except ClientError as e:
            if e.response['Error']['Code'] == 'ConditionalCheckFailedException':
                logger.warning('[%(user)s] Unable to update item because the conditional check failed:\n%(item)s' % {
                    'user': self.user_identifier(user),
                    'item': data
                })
                raise BadRequestException(condition_failure_message or 'Conditional check failed')
            logger.error(
                '[%(user)s] Encountered error while attempting to update record '
                '"%(primary_key)s": [%(code)s] %(error)s. Item:\n%(item)s' % {
                    'user': self.user_identifier(user),
                    'primary_key': primary_key,
                    'code': e.response['Error']['Code'],
                    'error': e.response['Error']['Message'],
                    'item': data
                }
            )
            raise
        except Exception as e:
            logger.error(
                '[%(user)s] Encountered error while attempting to update record '
                '"%(primary_key)s": %(error)s. Item:\n%(item)s' % {
                    'user': self.user_identifier(user),
                    'primary_key': primary_key,
                    'error': str(e),
                    'item': data
                }
            )
            raise

        sentry_sdk.add_breadcrumb(category='data', message='Updated item', level='info')

        # Create audit log
        self.audit_log(action=audit_action, resource=primary_key, changes=data, request=request, user=user)

        # Return updated record
        return self.post_process([response['Attributes']], user)[0]

    def get(self, request: Request, key: Any, value: Any) -> dict:
        """
        Get a specific item from the table

        :param Request request: Request object
        :param str key: Key to search on
        :param str value: Value to search for
        :return: Item
        :rtype: dict
        """
        # Get user
        user = self.initialize_request(request)

        # Filter the data according to the user's permissions
        conditions = self.filtering.And(
            self.filtering.filter(user),
            self.filtering.equals(key, value)
        )

        # Search for the item
        data = self._scan(self.data_table, FilterExpression=conditions)
        sentry_sdk.add_breadcrumb(
            category='query', message='%s = %s' % (key, value), level='info', table=self.config.data_table
        )

        # There should only be a single item returned
        if len(data) == 0:
            raise NotFoundException('Item not found')
        elif len(data) > 1:
            # This should only be returning a single item
            raise BadRequestException('Multiple items returned')

        # Filter the response
        output = self.post_process(data, user)[0]

        # Item was found, return the single item
        self.audit_log(action='GET', request=request, user=user, resource={key: value})
        return output

    def list(self, request: Request) -> List[dict]:
        """
        List all values in a table

        :param Request request: Request object
        :return: Data from the table
        :rtype: dict
        """
        user, params = self._prepare_list(request)

        args = {}
        conditions = self.filtering.filter(user, params)
        if conditions:
            args.update({'FilterExpression': conditions})

        data = self._scan(self.data_table, **args)
        data = self.post_process(data, user)

        self.audit_log('LIST', request, user)

        return data

    def list_unique_values(self, request: Request, key: str,
                           unique_func: Callable[[List, str], List[str]] = BaseAPI.unique_func) -> List[str]:
        user, params = self._prepare_list(request, False, False)

        # Build filters
        conditions = self.filtering.And(
            self.filtering.filter(user, params),
            self.filtering.exists(key, 'true')
        )

        # Download the data
        try:
            data = self._scan(self.data_table, FilterExpression=conditions)
        except ClientError as e:
            logger.error(
                '[%(user)s] Encountered error while attempting to list records: [%(code)s] %(error)s' % {
                    'user': self.user_identifier(user),
                    'code': e.response['Error']['Code'],
                    'error': e.response['Error']['Message']
                }
            )
            raise
        except Exception as e:
            logger.error(
                '[%(user)s] Encountered error while attempting to list records: %(error)s' % {
                    'user': self.user_identifier(user),
                    'error': str(e)
                }
            )
            raise

        # Post process the data
        data = self.post_process(data, user)

        # Make sure a unique, sorted list is returned
        output = unique_func(data, key)

        # Create audit log
        self.audit_log('LIST', request, user)

        return output

    def list_audit_logs(self, request: Request, param_overrides: dict = None) -> List[dict]:
        """
        List all audit logs

        :param Request request: Request object
        :param dict param_overrides: Parameter overrides: Each parameter should be formatted as:

            {
                "field_name": "search_value"
            }

        :return: List of audit logs, sorted with most recent entry first
        :rtype: list of dict
        """
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
        sentry_sdk.add_breadcrumb(
            category='query',
            message=args.get('FilterExpression', 'Scanned table'),
            level='info',
            table=self.config.audit_table
        )

        # Sort the data
        data = sorted(data, key=lambda item: item['time'], reverse=True)

        return data

    def search(self, request: Request, key: str, values: List[str]) -> List[dict]:
        """
        Perform a multi-value search of a field in the table. The search endpoint should be configured in API Gateway:

            POST /search/{search_key}

        The value of {search_key} should be passed in as `key` and the contents of the POST request body should be
        passed in as the `values` list.

        :param Request request: Request object
        :param str key: Field to search
        :param list of str values: Search values
        :return: Search results
        :rtype: dict
        """
        # Get user
        user = self.initialize_request(request)

        # Build multi-value filter expressions
        expressions = self.filtering.multi_filter(user, key, values)
        sentry_sdk.add_breadcrumb(category='data', message='Built multi-value filter', level='info')

        # Perform each generated filter expression and then combine the results together
        output = []
        for expression in expressions:
            # Download data
            data = self._scan(self.data_table, FilterExpression=expression)

            sentry_sdk.add_breadcrumb(
                category='query', message=expression, level='info', table=self.config.data_table
            )

            # Add to output
            output.extend(data)

        # Create audit log
        self.audit_log(action='SEARCH', request=request, user=user)

        # Return the filtered response
        return self.post_process(output, user)

    def delete(self, request: Request, primary_key: dict, condition=None, condition_failure_message='') -> dict:
        """
        Delete an item

        :param Request request: Request object
        :param dict primary_key: Dictionary formatted as {"primary_key": "value_of_row_to_delete"}
        :param boto3.dynamodb.conditions.ComparisonCondition condition: Optional condition to apply to this deletion.
        :param str condition_failure_message: If the conditional check fails, this optional error message
        will be displayed
        to the user.
        :return: Success
        :rtype: dict
        """
        # Get user
        user = self.initialize_request(request)

        # Build default conditional failure message
        if condition:
            default_condition_message = 'Conditional check failed'
        else:
            default_condition_message = 'Item does not exist'

        # Default conditional expression to make sure the item actually exists
        for key, value in primary_key.items():
            cond = Attr(key).eq(value)
            if condition:
                condition &= cond
            else:
                condition = cond

        # Add in the user's permissions
        user_conditions = self.filtering.filter(user)
        if user_conditions:
            if condition:
                condition &= user_conditions
            else:
                condition = user_conditions

        # Perform the deletion
        try:
            self.data_table.delete_item(Key=primary_key, ConditionExpression=condition)
            logger.info('[%(user)s] Successfully deleted record "%(primary_key)s"' % {
                'user': self.user_identifier(user),
                'primary_key': primary_key,
            })
        except ClientError as e:
            if e.response['Error']['Code'] == 'ConditionalCheckFailedException':
                logger.warning(
                    '[%(user)s] Unable to delete record "%(primary_key)s" because the conditional check failed' % {
                        'user': self.user_identifier(user),
                        'primary_key': primary_key
                    }
                )
                raise BadRequestException(condition_failure_message or default_condition_message)
            logger.error(
                '[%(user)s] Encountered error while attempting to delete record '
                '"%(primary_key)s": [%(code)s] %(error)s' % {
                    'user': self.user_identifier(user),
                    'primary_key': primary_key,
                    'code': e.response['Error']['Code'],
                    'error': e.response['Error']['Message'],
                }
            )
            raise
        except Exception as e:
            logger.error(
                '[%(user)s] Encountered error while attempting to delete record "%(primary_key)s": %(error)s' % {
                    'user': self.user_identifier(user),
                    'primary_key': primary_key,
                    'error': str(e)
                }
            )
            raise

        sentry_sdk.add_breadcrumb(category='data', message='Deleted item', level='info')

        # Create audit log
        self.audit_log(
            action='DELETE',
            request=request,
            user=user,
            resource=primary_key,
        )

        # Return updated record
        return {'deleted': True}
