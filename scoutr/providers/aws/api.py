import json
import logging
from copy import deepcopy
from typing import List, Dict, Optional, Any, Callable

import boto3
import mypy_boto3_dynamodb as dynamodb
from boto3.dynamodb.conditions import Attr
from botocore.exceptions import ClientError

from scoutr.exceptions import NotFoundException, BadRequestException, UnauthorizedException
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

    def get_auth(self, user_id: str) -> Optional[User]:
        # Try to find user in the auth table
        result: dict = self.auth_table.get_item(Key={'id': user_id})

        if not result.get('Item'):
            return None

        # Create user object
        return User.load(result['Item'])

    def get_group(self, group_id: str) -> Optional[Group]:
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
        """
        Create an item in Dynamo

        :param Request request: Request object
        :param dict data: Item to create
        :param dict validation: Optional dictionary containing mappings of field name to callable. See the docstring
        in the _validate_fields method for more information.
        :return: Created item
        :rtype: dict
        """
        # Get user
        user = self.initialize_request(request)

        # Make sure the user has permission to update all of the fields specified
        for key in data.keys():
            if key in user.exclude_fields:
                raise UnauthorizedException(f'Not authorized to create item with field {key}')

        # Check that required fields have values
        if validation:
            self.validate_fields(validation, data)
            if has_sentry:
                sentry_sdk.add_breadcrumb(category='validate', message='Validated input fields', level='info')

        # Build creation filters
        for filter_field in user.filter_fields:
            for sub_item in filter_field:
                key = sub_item.field
                filter_value = sub_item.value
                if key not in data:
                    raise BadRequestException(f'Missing required field {key}')

                # Perform the filter
                value = data[key]
                if isinstance(filter_value, list) and value not in filter_value or \
                        isinstance(filter_value, str) and value != filter_value:
                    raise BadRequestException(f'Unauthorized value for field {key}')

        # Build condition to ensure the unique key does not exist
        resource = {}
        conditions = None
        for schema in self.data_table.key_schema:
            condition = Attr(schema['AttributeName']).not_exists()
            resource.update({schema['AttributeName']: data.get(schema['AttributeName'])})
            if not conditions:
                conditions = condition
            else:
                conditions &= condition

        # Add to dynamo
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

        if has_sentry:
            sentry_sdk.add_breadcrumb(category='data', message='Created item in Dynamo', level='info')

        # Create audit log
        self.audit_log(action='CREATE', resource=resource, request=request, user=user)

        return {'created': True}

    def update(self, request: Request, partition_key: dict, data: dict, validation: dict, condition=None,
               condition_failure_message='', audit_action='UPDATE') -> dict:
        """
        Update an item in Dynamo

        :param Request request: Request object
        :param dict partition_key: Dictionary formatted as {"partition_key": "value_of_row_to_update"}
        :param dict data: Fields to update, formatted as {"key": "value"}
        :param dict validation: Optional dictionary containing mappings of field name to callable. See the
        docstring in the _validate_fields method for more information.
        :param dict condition: Optional condition expression to apply to this update. If the condition fails to return
        successful, then this item will not be updated in Dynamo.
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
        for key, value in partition_key.items():
            # Check if the partition key is specified in the data input
            if key in data:
                raise BadRequestException('Partition key cannot be updated')

            cond = Attr(key).eq(value)
            if base_conditions:
                base_conditions &= cond
            else:
                base_conditions = cond

        # Make sure the user has permission to update all of the fields specified
        if user.update_fields_permitted:
            # User is only permitted to update specified list of fields. Determine list of fields the user
            # is not authorized to update
            unauthorized_fields = set(data.keys()).difference(set(user.update_fields_permitted))
            if unauthorized_fields:
                raise UnauthorizedException(f'Not authorized to update fields {unauthorized_fields}')
        elif user.update_fields_restricted:
            # User is restricted from updating certain fields. Determine list of fields the user
            # is not authorized to update.
            unauthorized_fields = set(data.keys()).intersection(set(user.update_fields_restricted))
            if unauthorized_fields:
                raise UnauthorizedException(f'Not authorized to update fields {unauthorized_fields}')

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
            logger.info('[%(user)s] Partition key "%(partition_key)s" does not exist or user does '
                        'not have permission to access it' % {
                            'user': self.user_identifier(user),
                            'partition_key': partition_key
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
                item=data,
                existing_item=existing_item,
                ignore_field_presence=True
            )
            if has_sentry:
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
                Key=partition_key,
                UpdateExpression=update_expression,
                ExpressionAttributeNames=names,
                ExpressionAttributeValues=values,
                ReturnValues='ALL_NEW',
                **args
            )
            logger.info('[%(user)s] Successfully updated record "%(partition_key)s" with values:\n%(item)s' % {
                'user': self.user_identifier(user),
                'partition_key': partition_key,
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
                '"%(partition_key)s": [%(code)s] %(error)s. Item:\n%(item)s' % {
                    'user': self.user_identifier(user),
                    'partition_key': partition_key,
                    'code': e.response['Error']['Code'],
                    'error': e.response['Error']['Message'],
                    'item': data
                }
            )
            raise
        except Exception as e:
            logger.error(
                '[%(user)s] Encountered error while attempting to update record '
                '"%(partition_key)s": %(error)s. Item:\n%(item)s' % {
                    'user': self.user_identifier(user),
                    'partition_key': partition_key,
                    'error': str(e),
                    'item': data
                }
            )
            raise

        if has_sentry:
            sentry_sdk.add_breadcrumb(category='data', message='Updated item in Dynamo', level='info')

        # Create audit log
        self.audit_log(action=audit_action, resource=partition_key, changes=data, request=request, user=user)

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
        conditions = self.filtering.filter(user)
        if conditions:
            conditions &= Attr(key).eq(value)
        else:
            conditions = Attr(key).eq(value)

        # Search for the item
        data = self._scan(self.data_table, FilterExpression=conditions)
        if has_sentry:
            sentry_sdk.add_breadcrumb(
                category='query', message='%s = %s' % (key, value), level='info', table=self.config.data_table
            )

        # Filter the response
        output = self.post_process(data, user)

        # There should only be a single item returned
        if len(output) == 0:
            raise NotFoundException('Item not found')
        elif len(output) > 1:
            # We should not be returning more than a single item
            raise BadRequestException('Multiple items returned')
        else:
            # Item was found, return the single item
            self.audit_log(action='GET', request=request, user=user, resource={key: value})
            return output[0]

    def list(self, request: Request) -> List[dict]:
        """
        List all values in a table

        :param Request request: Request object
        :return: Data from the table
        :rtype: dict
        """
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

    def list_unique_values(self, request: Request, key: str,
                           unique_func: Callable[[List[Dict], str], List[str]] = BaseAPI.unique_func) -> List[str]:
        # Get the user
        user = self.initialize_request(request)

        # Combine filter parameters
        params: Dict[str, str] = {}
        params.update(request.query_params)
        params.update(request.path_params)

        # Build filters
        conditions = self.filtering.filter(user, params)

        # Add unique key existence filter
        key_cond = Attr(key).exists()
        if conditions:
            conditions &= key_cond
        else:
            conditions = key_cond

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
        """
        Given a resource key and value, build the history of the item over time.

        :param Request request: Request object
        :param str key: Resource key
        :param str value: Resource value
        :param tuple of str actions: List of actions to filter on
        :return: List of the record's history
        :rtype: list of dict
        """
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
        if has_sentry:
            sentry_sdk.add_breadcrumb(category='data', message='Built multi-value filter', level='info')

        # Perform each generated filter expression and then combine the results together
        output = []
        for expression in expressions:
            # Download data
            data = self._scan(self.data_table, FilterExpression=expression)

            if has_sentry:
                sentry_sdk.add_breadcrumb(
                    category='query', message=expression, level='info', table=self.config.data_table
                )

            # Add to output
            output.extend(data)

        # Create audit log
        self.audit_log(action='SEARCH', request=request, user=user)

        # Return the filtered response
        return self.post_process(output, user)

    def delete(self, request: Request, partition_key: dict, condition=None, condition_failure_message=''):
        """
        Delete an item from Dynamo

        :param Request request: Request object
        :param dict partition_key: Dictionary formatted as {"partition_key": "value_of_row_to_delete"}
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
        for key, value in partition_key.items():
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
            self.data_table.delete_item(Key=partition_key, ConditionExpression=condition)
            logger.info('[%(user)s] Successfully deleted record "%(partition_key)s"' % {
                'user': self.user_identifier(user),
                'partition_key': partition_key,
            })
        except ClientError as e:
            if e.response['Error']['Code'] == 'ConditionalCheckFailedException':
                logger.warning(
                    '[%(user)s] Unable to delete record "%(partition_key)s" because the conditional check failed' % {
                        'user': self.user_identifier(user),
                        'partition_key': partition_key
                    }
                )
                raise BadRequestException(condition_failure_message or default_condition_message)
            logger.error(
                '[%(user)s] Encountered error while attempting to delete record '
                '"%(partition_key)s": [%(code)s] %(error)s' % {
                    'user': self.user_identifier(user),
                    'partition_key': partition_key,
                    'code': e.response['Error']['Code'],
                    'error': e.response['Error']['Message'],
                }
            )
            raise
        except Exception as e:
            logger.error(
                '[%(user)s] Encountered error while attempting to delete record "%(partition_key)s": %(error)s' % {
                    'user': self.user_identifier(user),
                    'partition_key': partition_key,
                    'error': str(e)
                }
            )
            raise

        if has_sentry:
            sentry_sdk.add_breadcrumb(category='data', message='Deleted item from Dynamo', level='info')

        # Create audit log
        self.audit_log(
            action='DELETE',
            request=request,
            user=user,
            resource=partition_key,
        )

        # Return updated record
        return {'deleted': True}
