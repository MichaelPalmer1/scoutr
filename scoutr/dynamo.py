import json
import logging
import re
from copy import deepcopy
from datetime import datetime, timedelta
from decimal import Decimal
from urllib.parse import unquote_plus

import boto3
from boto3.dynamodb.conditions import Attr, ConditionBase, Not
from botocore.exceptions import ClientError

from .exceptions import BadRequestException, NotFoundException, UnauthorizedException

try:
    import sentry_sdk
    has_sentry = True
except ImportError:
    has_sentry = False


logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)


class DynamoAPI:
    """
    A generic API class for performing full RBAC queries on a Dynamo table
    """

    def __init__(self, table_name, auth_table_name, group_table_name, audit_table_name=None, audit_retention_days=30):
        if not table_name:
            raise Exception('Data table name not specified')
        if not auth_table_name:
            raise Exception('Auth table name not specified')
        if not group_table_name:
            raise Exception('Group table name not specified')

        # Initialize tables
        dynamo = boto3.resource('dynamodb')
        self.table = dynamo.Table(table_name)
        self.auth_table = dynamo.Table(auth_table_name)
        self.group_table = dynamo.Table(group_table_name)

        if not isinstance(audit_retention_days, int):
            raise Exception('audit_expiry_days must be an integer')
        self.audit_retention_days = audit_retention_days

        if audit_table_name:
            self.audit_table = dynamo.Table(audit_table_name)
        else:
            self.audit_table = None

    def _initialize_request(self, request):
        # Get user
        user_data = request['user'].get('data', {})
        user = self.get_user(
            user_id=request['user']['id'],
            user_data=user_data,
            groups=user_data.get('groups', [])
        )

        # Validate user
        self._validate_user(user)

        # Validate and log request
        self._validate_request(request, user)

        return user

    @staticmethod
    def _validate_user(user):
        """Validate an user"""
        required_user_keys = {'id', 'username', 'name', 'email'}

        # Extract user information
        user_keys = required_user_keys.difference(set(user.keys()))
        if user_keys:
            raise UnauthorizedException('Auth id %s missing fields: %s' % (user['id'], user_keys))
        for key, value in user.items():
            if key in required_user_keys and not isinstance(value, str):
                raise UnauthorizedException(
                    "User '%s' field %s does not have a valid string value" % (user['id'], key))

        if has_sentry:
            sentry_sdk.add_breadcrumb(
                category='validate',
                message='Validated required fields on user',
                level='info'
            )

        # Validate exclude_fields
        for item in user.get('exclude_fields', []):
            if not isinstance(item, str):
                raise UnauthorizedException(
                    "User '%s' field 'exclude_fields' must be a list of strings" % user['id']
                )

        if has_sentry:
            sentry_sdk.add_breadcrumb(
                category='validate',
                message='Validated field exclusions on user',
                level='info'
            )

        # Validate filter_fields
        for item in user.get('filter_fields', []):
            if not isinstance(item, list):
                raise UnauthorizedException(
                    "User '%s' field 'filter_fields' must be a list of lists of dictionaries with each item "
                    "formatted as {'field': 'field_name', 'value': 'value'}" % user['id']
                )
            for sub_item in item:
                if not isinstance(sub_item, dict) or 'field' not in sub_item or 'value' not in sub_item:
                    raise UnauthorizedException(
                        "User '%s' field 'filter_fields' must be a list of lists of dictionaries with each item "
                        "formatted as {'field': 'field_name', 'value': 'value'}" % user['id']
                    )

        if has_sentry:
            sentry_sdk.add_breadcrumb(
                category='validate',
                message='Validated filter fields on user',
                level='info'
            )

        # Validate permitted_endpoints
        for item in user.get('permitted_endpoints', []):
            if not isinstance(item, dict) or not isinstance(item.get('method'), str) or \
                    not isinstance(item.get('endpoint'), str):
                raise UnauthorizedException(
                    "User '%s' field 'permitted_endpoints' must be a list of dictionaries with each item formatted as "
                    "{'method': 'HTTP_METHOD', 'endpoint': '^/endpoint/regex/$'}" % user['id']
                )

            # Validate methods
            if not re.match('^(GET|PUT|POST|DELETE)$', item['method']):
                raise UnauthorizedException(
                    "User '%s' field 'permitted_endpoints' is mis-configured. "
                    "Valid HTTP method values are: GET, PUT, POST, DELETE" % user['id']
                )

            # Validate endpoints
            try:
                re.compile(item['endpoint'])
            except re.error:
                raise UnauthorizedException(
                    "User '%s' field 'permitted_endpoints' is mis-configured. "
                    "An invalid regex was found: '%s'" % (user['id'], item['endpoint'])
                )

        if has_sentry:
            sentry_sdk.add_breadcrumb(
                category='validate',
                message='Validated permitted endpoints for user',
                level='info'
            )

    @staticmethod
    def _validate_fields(field_validation, item, existing_item=None, ignore_field_presence=False):
        """
        Perform field validation before creating/updating items into Dynamo

        Expected that the field_validation argument consists of a dictionary formatted as:

            {
                "field_name": callable_that_returns_bool,
                "field_name_2": callable_that_returns_dict
            }

            The callable should accept three arguments. The first is the input value and the second is the entire
            item that is being validating (in case complex filters are needed that cross-reference against other
            field values). The last argument is the value of the existing item (used during record updates). When
            validating record creations, the passed value will be `None`.

            It can either return a boolean or a dictionary. If it returns a boolean that evaluates to
            False, then a BadRequestException will be raised with the default error message "Invalid value for key
            'field_name'". If the callable returns a dictionary, it is expected that the dictionary is structured as:

                {
                    "result": bool,
                    "message": "message that should be returned to the user if 'result' is False"
                }

            This dictionary format allows for customizing the error message returned to the user.

        :param dict field_validation: Dictionary that maps fields to their validation callables
        :param dict item: Data that should be validated
        :param dict existing_item: Existing item in Dynamo
        :param bool ignore_field_presence: If True and a field specified in `field_validation` does not exist in
        `data`, this will raise a BadRequestException. If False, missing fields will be ignored.
        :raises: BadRequestException
        """
        # Check for required fields
        if not ignore_field_presence:
            missing_keys = set(field_validation.keys()).difference(set(item.keys()))
            if missing_keys:
                raise BadRequestException('Missing required fields %s' % missing_keys)

        # Perform field validation
        for key, func in field_validation.items():
            if key in item:
                response = func(item[key], item, existing_item)
                if isinstance(response, dict):
                    if 'result' not in response:
                        raise BadRequestException('Validator for %s is not properly configured' % key)
                    elif not response['result']:
                        if not isinstance(response.get('message'), str):
                            raise BadRequestException('Validator for %s is not properly configured' % key)
                        raise BadRequestException(response['message'])
                elif not response:
                    raise BadRequestException("Invalid value for key '%s'" % key)

    @classmethod
    def value_in_list(cls, value, valid_options, option_name='option', custom_error_message=None):
        """
        Check if a value is contained in a list of valid options. This is supplied as a convenience function
        and is intended to be used with the input field validation on creates/updates.

        :param str value: Value to check
        :param list of str valid_options: List of options that the value should be included in for this to be successful
        :param str option_name: Optional descriptive name of the option that can be used to enrich an error message.
        :param str custom_error_message: Optional custom error message to return instead of the default one.
        :return: Dictionary that can be used with the field_validation
        :rtype: dict
        """
        return {
            'result': value in valid_options,
            'message': custom_error_message or "%s is not a valid %s. Valid options: %s" % (
                value,
                option_name,
                valid_options
            )
        }

    @staticmethod
    def user_identifier(user):
        return '%(id)s: %(name)s (%(username)s - %(email)s)' % {
            'id': user['id'],
            'name': user['name'],
            'username': user['username'],
            'email': user['email']
        }

    def can_access_endpoint(self, method, path, request=None, user=None):
        if request:
            # Get user
            user_data = request['user'].get('data', {})
            user = self.get_user(
                user_id=request['user']['id'],
                user_data=user_data,
                groups=user_data.get('groups', [])
            )

            # Validate user
            self._validate_user(user)

        for item in user.get('permitted_endpoints', []):
            if method == item['method'] and re.match(item['endpoint'], path):
                return True
        return False

    def _validate_request(self, request, user):
        """
        Perform checks against the request to ensure the user is permitted to perform this request.

        :param dict request: Request from API gateway. This should be the `event` object passed into Lambda.
        :param dict user: User object
        """
        # Make sure the body is valid JSON
        if request['method'] in ('POST', 'PUT'):
            body = request.get('body', '{}') or '{}'
            if not isinstance(body, (dict, list)):
                try:
                    json.loads(body)
                except json.JSONDecodeError as e:
                    raise BadRequestException(
                        f'Request body contains invalid JSON on line {e.lineno} column {e.colno} (char {e.pos}): {e.msg}'
                    )

        # Check if the user can access an endpoint
        if self.can_access_endpoint(request['method'], request['path'], user=user):
            # User is authorized
            self._log_request(request, user)
            return True

        # User is not authorized
        logger.warning(
            '[%(user)s] Not authorized to perform %(method)s on %(path)s' % {
                'user': self.user_identifier(user),
                'method': request['method'],
                'path': request['path']
            }
        )
        raise UnauthorizedException("Not authorized to perform %s on endpoint %s" % (
            request['method'], request['path']
        ))

    def _log_request(self, request, user):
        if request['method'] != 'GET':
            body = request.get('body', '{}') or '{}'
            if not isinstance(body, (dict, list)):
                try:
                    body = json.loads(body)
                except json.JSONDecodeError:
                    pass

            logger.info(
                '[%(user)s] Performed %(method)s on %(path)s:\n%(body)s' % {
                    'user': self.user_identifier(user),
                    'method': request['method'],
                    'path': request['path'],
                    'body': body
                }
            )
        else:
            logger.info(
                '[%(user)s] Performed %(method)s on %(path)s' % {
                    'user': self.user_identifier(user),
                    'method': request['method'],
                    'path': request['path']
                }
            )

    @staticmethod
    def _scan(resource, **kwargs):
        """
        Scan a table until all results are returned

        :param resource: DynamoDB table resource
        :param dict kwargs: Arguments to pass to the scan call
        :return: Scan results
        :rtype: list
        """
        response = resource.scan(**kwargs)
        items = response['Items']
        while response.get('LastEvaluatedKey', False):
            kwargs.update({'ExclusiveStartKey': response['LastEvaluatedKey']})
            response = resource.scan(**kwargs)
            items.extend(response['Items'])
        return items

    def _audit_log(self, action, request, user, resource=None, changes=None):
        if not self.audit_table:
            return

        now = datetime.utcnow()
        audit_log = {
            'time': now.isoformat(),
            'user': {
                'id': user['id'],
                'name': user['name'],
                'username': user['username'],
                'source_ip': request['source_ip'],
                'user_agent': request['user_agent'],
                'filter_fields': user['filter_fields']
            },
            'action': action,
            'method': request['method'],
            'path': request['path']
        }

        # Expire the read logs
        if action in ('GET', 'LIST', 'SEARCH'):
            expire_time = now + timedelta(days=self.audit_retention_days)
            audit_log.update({'expire_time': int(expire_time.timestamp())})

        # Get the body
        body = request.get('body', '{}') or '{}'
        if not isinstance(body, (list, dict)):
            try:
                body = json.loads(body)
            except json.JSONDecodeError:
                pass

        # Conditionally add the body
        if body:
            audit_log.update({'body': body})
        elif changes:
            audit_log.update({'body': changes})

        # Conditionally add query parameters
        query_params = request.get('query_params', {}) or {}
        if query_params:
            audit_log.update({'query_params': query_params})

        if resource:
            audit_log.update({'resource': resource})

        try:
            self.audit_table.put_item(Item=audit_log)
        except Exception as e:
            logger.error('Failed to log request to audit table - %(type)s: %(error)s:\n%(audit_log)s' % {
                'type': e.__class__.__name__,
                'error': str(e),
                'audit_log': audit_log
            })
            if has_sentry:
                with sentry_sdk.configure_scope() as scope:
                    scope.set_extra('audit_log', audit_log)
                sentry_sdk.capture_exception(e)

    def list_audit_logs(self, request, search_params=None, query_params=None):
        """
        List all audit logs

        :param dict request: Request object
        :param dict search_params: Search parameters: Each parameter should be formatted as:

            {
                "field_name": "search_value"
            }

        It should be noted that in the event that the same parameter is passed in both search_params and query_params,
        the value in search_params takes precedence.

        :param dict query_params: Query parameters passed in from API Gateway. Each parameter should be formatted as:

            {
                "field_name": "search_value"
            }

        Multiple items in the dictionary will be chained together and function as an AND statement. It should be noted
        that in the event that the same parameter is passed in both search_params and query_params, the value in
        search_params takes precedence.

        :return: List of audit logs, sorted with most recent entry first
        :rtype: list of dict
        """
        if not self.audit_table:
            return {'message': 'Audit log table is not configured'}

        if search_params is None:
            search_params = {}

        if query_params is None:
            query_params = {}

        user = self._initialize_request(request)

        # Add in search parameters
        query_params.update(search_params)

        args = {}
        conditions = self.filter({}, query_params)
        if conditions:
            args.update({'FilterExpression': conditions})

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

        if has_sentry:
            sentry_sdk.add_breadcrumb(
                category='query',
                message=args.get('FilterExpression', 'Scanned table'),
                level='info',
                table=self.table.name
            )

        # Sort the data
        data = sorted(data, key=lambda item: item['time'], reverse=True)

        return data

    def history(self, request, key, value, query_params, actions=('CREATE', 'UPDATE', 'DELETE')):
        """
        Given a resource key and value, build the history of the item over time.

        :param dict request: Request object
        :param str key: Resource key
        :param str value: Resource value
        :param dict query_params: Query parameters passed in from API Gateway. Each parameter should be formatted as:

            {
                "field_name": "search_value"
            }

        Multiple items in the dictionary will be chained together and function as an AND statement. It should be noted
        that in the event that the same parameter is passed in both search_params and query_params, the value in
        search_params takes precedence.

        :param tuple of str actions: List of actions to filter on
        :return: List of the record's history
        :rtype: list of dict
        """
        # Build search parameters
        search_params = {
            f'resource.{key}': value,
            'action__in': json.dumps(actions)
        }

        # Perform the search, reversing the results so the oldest item is first
        logs = self.list_audit_logs(request, search_params, query_params)[::-1]
        if not logs:
            return []

        # Get the original record
        current_item = {'data': {}, 'time': None}
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

    def create(self, request, item, field_validation=None):
        """
        Create an item in Dynamo

        :param dict request: Request object
        :param dict item: Item to create
        :param field_validation: Optional dictionary containing mappings of field name to callable. See the docstring
        in the _validate_fields method for more information.
        :return: Created item
        :rtype: dict
        """
        # Get user
        user = self._initialize_request(request)

        # Make sure the user has permission to update all of the fields specified
        for key in item.keys():
            if key in user['exclude_fields']:
                raise UnauthorizedException(f'Not authorized to create item with field {key}')

        # Check that required fields have values
        if field_validation:
            self._validate_fields(field_validation, item)
            if has_sentry:
                sentry_sdk.add_breadcrumb(category='validate', message='Validated input fields', level='info')

        # Build creation filters
        for filter_field in user['filter_fields']:
            key = filter_field['field']
            filter_value = filter_field['value']
            if key not in item:
                raise BadRequestException(f'Missing required field {key}')

            # Perform the filter
            value = item[key]
            if isinstance(filter_value, list) and value not in filter_value or \
                isinstance(filter_value, str) and value != filter_value:
                raise BadRequestException(f'Unauthorized value for field {key}')

        # Build condition to ensure the unique key does not exist
        resource = {}
        conditions = None
        for schema in self.table.key_schema:
            condition = Attr(schema['AttributeName']).not_exists()
            resource.update({schema['AttributeName']: item.get(schema['AttributeName'])})
            if not conditions:
                conditions = condition
            else:
                conditions &= condition

        # Add to dynamo
        try:
            self.table.put_item(Item=item, ConditionExpression=conditions)
            logger.info('[%(user)s] Successfully created item:\n%(item)s' % {
                'user': self.user_identifier(user),
                'item': item
            })
        except ClientError as e:
            if e.response['Error']['Code'] == 'ConditionalCheckFailedException':
                logger.warning('[%(user)s] Unable to create item because the conditional check failed:\n%(item)s' % {
                    'user': self.user_identifier(user),
                    'item': item
                })
                raise BadRequestException('Item already exists or you do not have permission to create it.')
            elif e.response['Error']['Code'] == 'ValidationException':
                logger.error('[%(user)s] Validation error - %(error)s:\n%(item)s' % {
                    'user': self.user_identifier(user),
                    'error': e.response['Error']['Message'],
                    'item': item
                })
                raise BadRequestException(e.response['Error']['Message'])
            logger.error(
                '[%(user)s] Encountered error while attempting to create record '
                '[%(code)s] %(error)s. Item:\n%(item)s' % {
                    'user': self.user_identifier(user),
                    'code': e.response['Error']['Code'],
                    'error': e.response['Error']['Message'],
                    'item': item
                }
            )
            raise
        except Exception as e:
            logger.error(
                '[%(user)s] Encountered error while attempting to create record %(error)s. Item:\n%(item)s' % {
                    'user': self.user_identifier(user),
                    'error': str(e),
                    'item': item
                }
            )
            raise

        if has_sentry:
            sentry_sdk.add_breadcrumb(category='data', message='Created item in Dynamo', level='info')

        # Create audit log
        self._audit_log(action='CREATE', resource=resource, request=request, user=user)

        return {'created': True}

    def update(self, request, partition_key, data, field_validation=None, condition=None, condition_failure_message=None,
               audit_action='UPDATE'):
        """
        Update an item in Dynamo

        :param dict request: Request object
        :param dict partition_key: Dictionary formatted as {"partition_key": "value_of_row_to_update"}
        :param dict data: Fields to update, formatted as {"key": "value"}
        :param dict field_validation: Optional dictionary containing mappings of field name to callable. See the
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
        user = self._initialize_request(request)

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
        if user['update_fields_permitted']:
            # User is only permitted to update specified list of fields. Determine list of fields the user
            # is not authorized to update
            unauthorized_fields = set(data.keys()).difference(set(user['update_fields_permitted']))
            if unauthorized_fields:
                raise UnauthorizedException(f'Not authorized to update fields {unauthorized_fields}')
        elif user['update_fields_restricted']:
            # User is restricted from updating certain fields. Determine list of fields the user
            # is not authorized to update.
            unauthorized_fields = set(data.keys()).intersection(set(user['update_fields_restricted']))
            if unauthorized_fields:
                raise UnauthorizedException(f'Not authorized to update fields {unauthorized_fields}')

        # Add in the user's permissions
        user_conditions = self.filter(user)
        if user_conditions:
            if base_conditions:
                base_conditions &= user_conditions
            else:
                base_conditions = user_conditions

        # Get the existing item
        existing_item = self._scan(self.table, FilterExpression=base_conditions)
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
        if field_validation:
            self._validate_fields(
                field_validation=field_validation,
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

            response = self.table.update_item(
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
        self._audit_log(action=audit_action, resource=partition_key, changes=data, request=request, user=user)

        # Return updated record
        return self.filter_response(user, [response['Attributes']])[0]

    def delete(self, request, partition_key, condition=None, condition_failure_message=None):
        """
        Delete an item from Dynamo

        :param dict request: Request object
        :param dict partition_key: Dictionary formatted as {"partition_key": "value_of_row_to_delete"}
        :param boto3.dynamodb.conditions.ComparisonCondition condition: Optional condition to apply to this deletion.
        :param str condition_failure_message: If the conditional check fails, this optional error message
        will be displayed
        to the user.
        :return: Success
        :rtype: dict
        """
        # Get user
        user = self._initialize_request(request)

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
        user_conditions = self.filter(user)
        if user_conditions:
            if condition:
                condition &= user_conditions
            else:
                condition = user_conditions

        # Perform the deletion
        try:
            self.table.delete_item(Key=partition_key, ConditionExpression=condition)
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
        self._audit_log(
            action='DELETE',
            resource=partition_key,
            request=request,
            user=user
        )

        # Return updated record
        return {'deleted': True}

    def list_table(self, request, unique_key=None, path_params=None, query_params=None):
        """
        List all values in a table

        :param dict request: Request object
        :param str unique_key: If specified, then only the unique values of rows containing this column will be returned
        :param dict path_params: Path parameters passed in from API Gateway: Each parameter should be formatted as:

            {
                "field_name": "search_value"
            }

        Additionally, a dynamic search is supported if a "search_key" path parameter is configured as shown:

            /list/{search_key}/{search_value}

        Which should produce a path parameters dict:

            {
                "search_key": "field name",
                "search_value": "value to search"
            }

        It should be noted that in the event that the same parameter is passed in both path_params and query_params,
        the value in path_params takes precedence.

        :param dict query_params: Query parameters passed in from API Gateway. Each parameter should be formatted as:

            {
                "field_name": "search_value"
            }

        Multiple items in the dictionary will be chained together and function as an AND statement. It should be noted
        that in the event that the same parameter is passed in both path_params and query_params, the value in
        path_params takes precedence.
        :return: Data from the table
        :rtype: dict
        """
        if path_params is None:
            path_params = {}
        if query_params is None:
            query_params = {}

        # Get user
        user = self._initialize_request(request)

        # Check if a unique key should be returned
        args = {}
        if unique_key:
            filter_expression = self.filter(user, query_params)
            if filter_expression:
                filter_expression &= Attr(unique_key).exists()
            else:
                filter_expression = Attr(unique_key).exists()

            unique_key_name = '#' + unique_key
            args.update({
                'FilterExpression': filter_expression,
                'ExpressionAttributeNames': {unique_key_name: unique_key},
                'ProjectionExpression': unique_key_name
            })
        else:
            # Generate dynamic search
            if 'search_key' in path_params and 'search_value' in path_params:
                # Map `search_key` and `search_value`
                path_params.update({path_params['search_key']: path_params['search_value']})

                # Remove these from path parameters
                del path_params['search_key']
                del path_params['search_value']

            # Path parameters take precedence
            query_params.update(path_params)

            # Generate the filter arguments
            conditions = self.filter(user, query_params)

            if conditions:
                args.update({'FilterExpression': conditions})

        # Download data
        try:
            data = self._scan(self.table, **args)
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

        if has_sentry:
            sentry_sdk.add_breadcrumb(
                category='query',
                message=args.get('FilterExpression', 'Scanned table'),
                level='info',
                table=self.table.name
            )

        # Filter response
        output = self.filter_response(user, data)
        if has_sentry:
            sentry_sdk.add_breadcrumb(category='data', message='Filtered data response', level='info')

        # Make sure a unique, sorted list is returned
        if unique_key:
            output = sorted(set([item[unique_key] for item in output if item]))

        # Create audit log
        self._audit_log(action='LIST', request=request, user=user)

        return output

    def list_table_set(self, request, unique_key=None, path_params=None, query_params=None):
        """
        List all values in a table
        :param dict request: Request object
        :param str unique_key: If specified, then only the unique values of rows containing this column will be returned
        :param dict path_params: Path parameters passed in from API Gateway: Each parameter should be formatted as:
            {
                "field_name": "search_value"
            }
        Additionally, a dynamic search is supported if a "search_key" path parameter is configured as shown:
            /list/{search_key}/{search_value}
        Which should produce a path parameters dict:
            {
                "search_key": "field name",
                "search_value": "value to search"
            }
        It should be noted that in the event that the same parameter is passed in both path_params and query_params,
        the value in path_params takes precedence.
        :param dict query_params: Query parameters passed in from API Gateway. Each parameter should be formatted as:
            {
                "field_name": "search_value"
            }
        Multiple items in the dictionary will be chained together and function as an AND statement. It should be noted
        that in the event that the same parameter is passed in both path_params and query_params, the value in
        path_params takes precedence.
        :return: Data from the table
        :rtype: dict
        """
        if path_params is None:
            path_params = {}
        if query_params is None:
            query_params = {}

        # Get user
        user = self._initialize_request(request)

        # Check if a unique key should be returned
        args = {}
        if unique_key:
            filter_expression = self.filter(user, query_params)
            if filter_expression:
                filter_expression &= Attr(unique_key).exists()
            else:
                filter_expression = Attr(unique_key).exists()

            unique_key_name = '#' + unique_key
            args.update({
                'FilterExpression': filter_expression,
                'ExpressionAttributeNames': {unique_key_name: unique_key},
                'ProjectionExpression': unique_key_name
            })
        else:
            # Generate dynamic search
            if 'search_key' in path_params and 'search_value' in path_params:
                # Map `search_key` and `search_value`
                path_params.update({path_params['search_key']: path_params['search_value']})

                # Remove these from path parameters
                del path_params['search_key']
                del path_params['search_value']

            # Path parameters take precedence
            query_params.update(path_params)

            # Generate the filter arguments
            conditions = self.filter(user, query_params)

            if conditions:
                args.update({'FilterExpression': conditions})

        # Download data
        try:
            data = self._scan(self.table, **args)
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

        if has_sentry:
            sentry_sdk.add_breadcrumb(
                category='query',
                message=args.get('FilterExpression', 'Scanned table'),
                level='info',
                table=self.table.name
            )

        # Filter response
        output = self.filter_response(user, data)
        if has_sentry:
            sentry_sdk.add_breadcrumb(category='data', message='Filtered data response', level='info')

        # Make sure a unique, sorted list is returned
        if unique_key:
            output = sorted(set([item for sublist in [item[unique_key] for item in data] for item in sublist]))

        # Create audit log
        self._audit_log(action='LIST', request=request, user=user)

        return output

    def search(self, request, key, values):
        """
        Perform a multi-value search of a field in the table. The search endpoint should be configured in API Gateway:

            POST /search/{search_key}

        The value of {search_key} should be passed in as `key` and the contents of the POST request body should be
        passed in as the `values` list.

        :param dict request: Request object
        :param str key: Field to search
        :param list of str values: Search values
        :return: Search results
        :rtype: dict
        """
        # Get user
        user = self._initialize_request(request)

        # Build multi-value filter expressions
        expressions = self.multi_filter(user, key, values)
        if has_sentry:
            sentry_sdk.add_breadcrumb(category='data', message='Built multi-value filter', level='info')

        # Perform each generated filter expression and then combine the results together
        output = []
        for expression in expressions:
            # Download data
            data = self._scan(self.table, FilterExpression=expression)

            if has_sentry:
                sentry_sdk.add_breadcrumb(
                    category='query', message=expression, level='info', table=self.table.name
                )

            # Add to output
            output.extend(data)

        # Create audit log
        self._audit_log(request=request, user=user, action='SEARCH')

        # Return the filtered response
        return self.filter_response(user, output)

    def get_item(self, request, key, value):
        """
        Get a specific item from the table

        :param dict request: Request object
        :param str key: Key to search on
        :param str value: Value to search for
        :return: Item
        :rtype: dict
        """
        # Get user
        user = self._initialize_request(request)

        # Filter the data according to the user's permissions
        conditions = self.filter(user)
        if conditions:
            conditions &= Attr(key).eq(value)
        else:
            conditions = Attr(key).eq(value)

        # Search for the item
        data = self._scan(self.table, FilterExpression=conditions)
        if has_sentry:
            sentry_sdk.add_breadcrumb(
                category='query', message='%s = %s' % (key, value), level='info', table=self.table.name
            )

        # Filter the response
        output = self.filter_response(user, data)

        # There should only be a single item returned
        if len(output) == 0:
            raise NotFoundException('Item not found')
        elif len(output) > 1:
            # We should not be returning more than a single item
            raise BadRequestException('Multiple items returned')
        else:
            # Item was found, return the single item
            self._audit_log(action='GET', request=request, user=user, resource={key: value})
            return output[0]

    @staticmethod
    def _merge_lists(primary_list, secondary_list):
        """Merge two lists together and return a unique list"""
        return primary_list + [item for item in secondary_list if item not in primary_list]

    def get_user(self, user_id, user_data=None, groups=None):
        """
        Get user and group information from the user and group tables

        :param str user_id: User identifier
        :param dict user_data: Metadata about user
        :param list groups: List of OIDC user groups
        :return: User
        :rtype: dict
        """
        if user_data is None:
            user_data = {}
        if groups is None:
            groups = []

        # Try to find user by id
        user = {'id': user_id, 'filter_fields': []}
        permitted_endpoints = []
        exclude_fields = []
        filter_fields = []
        update_fields_restricted = []
        update_fields_permitted = []

        try:
            user = self.auth_table.get_item(Key={'id': user_id})['Item']
            if 'filter_fields' not in user:
                user['filter_fields'] = []

            is_user = True
            permitted_endpoints = self._merge_lists(
                permitted_endpoints,
                user.get('permitted_endpoints', [])
            )
            exclude_fields = self._merge_lists(
                exclude_fields,
                user.get('exclude_fields', [])
            )
            update_fields_restricted = self._merge_lists(
                update_fields_restricted,
                user.get('update_fields_restricted', [])
            )
            update_fields_permitted = self._merge_lists(
                update_fields_permitted,
                user.get('update_fields_permitted', [])
            )

            user_filters = user.get('filter_fields', [])

            # If the user is a member of a group, merge in the group's permissions
            for group_id in user.get('groups', []):
                # Get groups for user
                try:
                    group = self.group_table.get_item(Key={'group_id': group_id})['Item']
                except KeyError:
                    raise UnauthorizedException("Group '%s' does not exist" % group_id)

                if has_sentry:
                    sentry_sdk.add_breadcrumb(
                        category='data',
                        message='Fetched group %s from group table' % group_id,
                        level='info'
                    )

                # Merge permitted endpoints
                permitted_endpoints = self._merge_lists(
                    permitted_endpoints,
                    group.get('permitted_endpoints', [])
                )

                # Merge exclude_fields
                exclude_fields = self._merge_lists(
                    exclude_fields,
                    group.get('exclude_fields', [])
                )

                # Merge update_fields_restricted
                update_fields_restricted = self._merge_lists(
                    update_fields_restricted,
                    group.get('update_fields_restricted', [])
                )

                # Merge update_fields_permitted
                update_fields_permitted = self._merge_lists(
                    update_fields_permitted,
                    group.get('update_fields_permitted', [])
                )

                # Merge filter_fields
                if group.get('filter_fields', []):
                    user_filters += group['filter_fields']

            if user_filters:
                filter_fields.append(user_filters)

        except KeyError:
            is_user = False

        # Try to find group permissions
        group_ids = []
        oidc_groups = {}
        for group_id in groups:
            try:
                group = self.auth_table.get_item(Key={'id': group_id})['Item']
            except KeyError:
                continue

            # Merge in group permissions
            group_ids.append(group_id)

            # Add any sub-groups
            oidc_groups[group_id] = group.get('groups', [])

            permitted_endpoints = self._merge_lists(
                permitted_endpoints,
                group.get('permitted_endpoints', [])
            )
            exclude_fields = self._merge_lists(
                exclude_fields,
                group.get('exclude_fields', [])
            )
            update_fields_restricted = self._merge_lists(
                update_fields_restricted,
                group.get('update_fields_restricted', [])
            )
            update_fields_permitted = self._merge_lists(
                update_fields_permitted,
                group.get('update_fields_permitted', [])
            )
            filter_fields += group.get('filter_fields', [])

        if not is_user and not group_ids:
            raise UnauthorizedException("User '%s' is not authorized" % user_id)

        if has_sentry:
            sentry_sdk.add_breadcrumb(category='data', message='Fetched user/groups from auth table', level='info')

        # If the user is a member of a group, merge in the group's permissions
        for group_id, groups in oidc_groups.items():
            group_filters = []
            for item in groups:
                # Get groups for user
                try:
                    group = self.group_table.get_item(Key={'group_id': item})['Item']
                except KeyError:
                    raise UnauthorizedException("Group '%s' does not exist" % item)

                if has_sentry:
                    sentry_sdk.add_breadcrumb(
                        category='data',
                        message='Fetched group %s from group table' % item,
                        level='info'
                    )

                # Merge permitted endpoints
                permitted_endpoints = self._merge_lists(
                    permitted_endpoints,
                    group.get('permitted_endpoints', [])
                )

                # Merge exclude_fields
                exclude_fields = self._merge_lists(
                    exclude_fields,
                    group.get('exclude_fields', [])
                )

                # Merge update_fields_restricted
                update_fields_restricted = self._merge_lists(
                    update_fields_restricted,
                    group.get('update_fields_restricted', [])
                )

                # Merge update_fields_permitted
                update_fields_permitted = self._merge_lists(
                    update_fields_permitted,
                    group.get('update_fields_permitted', [])
                )

                # Merge filter_fieldsF
                if group.get('filter_fields', []):
                    group_filters += group['filter_fields']

            if group_filters:
                filter_fields.append(group_filters)

        # Add permissions to the user object
        user.update({
            'permitted_endpoints': permitted_endpoints,
            'exclude_fields': exclude_fields,
            'update_fields_restricted': update_fields_restricted,
            'update_fields_permitted': update_fields_permitted,
            'filter_fields': filter_fields
        })

        # Save user groups before applying metadata
        user_groups = user.get('groups', [])

        # Update user object with user metadata
        if user_data:
            user.update(user_data)

        # For OIDC groups, update user object with all applied groups
        if group_ids:
            user['groups'] = self._merge_lists(user_groups, group_ids)

        return user

    def filter_response(self, user, output):
        """
        Filter a response based on what the user's authorizations.

        Filter fields should be formatted as:

            [
                {
                    "field": "field_name",
                    "value": "value that must match in order to be returned to the user"
                },
                {
                    "field": "field_name",
                    "value": [
                        "values that must match in order to be returned to the user",
                        "values that must match in order to be returned to the user"
                    ]
                }
            ]

        If multiple field expressions are specified, they will be combined as an AND expression. There should only be
        one value for each field name.

        Exclude fields should be formatted as a list of field names to exclude from the results:

            [
                "field_name",
                "field_name_2"
            ]

        :param dict user: User object
        :param list of dict output: Output to perform filters on
        :return: Filtered output
        :rtype: list of dict
        """
        # Get filters from the user object
        field_exclusions = user.get('exclude_fields', [])

        # If no filtering is necessary, return output
        if not field_exclusions:
            return output

        fields_logged = set()
        for item in output:
            # Remove fields the user shouldn't be able to see
            for field in field_exclusions:
                if field in item:
                    if field not in fields_logged:
                        logger.info('[%(user)s] Excluding field "%(field)s" from response' % {
                            'user': self.user_identifier(user),
                            'field': field
                        })
                        fields_logged.add(field)
                    del item[field]

        # Return the filtered output
        return output

    def filter(self, user, filters=None):
        """
        Build an AND filter expression

        The filters should be structured as:

            {
                "search_key": "search_value",
                "search_key_2": "search_value_2"
            }

        For each item specified in the filters, a filter expression will be generated. In the above example, the
        following filter would be generated:

            search_key = search_value AND search_key_2 = search_value_2

        This also factors in the user's permissions to the filter. Anything that is defined in the user's group or
        the user itself will be ALWAYS applied to every filter call:

            search_key = search_value AND search_key_2 = search_value2 AND user_filter_1 = user_filter_value_1

        :param dict user: User object
        :param dict filters: Dictionary of filters to perform
        :return: Conditions to pass to a FilterExpression or ConditionExpression
        """
        conditions = None
        if filters is None:
            filters = {}

        # Build pre-set filters from the user's permissions
        for item in user.get('filter_fields', []):
            user_conds = None
            for sub_item in item:
                if 'value' not in sub_item:
                    continue

                attr = Attr(sub_item['field'])
                if isinstance(sub_item['value'], list):
                    condition = attr.is_in(sub_item['value'])
                    if not isinstance(user_conds, ConditionBase):
                        user_conds = condition
                    else:
                        user_conds &= condition
                else:
                    condition = attr.eq(sub_item['value'])
                    if not isinstance(user_conds, ConditionBase):
                        user_conds = condition
                    else:
                        user_conds &= condition

            if not isinstance(conditions, ConditionBase):
                conditions = user_conds
            else:
                conditions |= user_conds

        # Build filters that were passed in
        for key, value in filters.items():
            if isinstance(value, list):
                for item in value:
                    if not isinstance(item, str):
                        raise BadRequestException('Query filter value must be a string or list of strings')
                    conditions = self.perform_filter(conditions, key, item)
            elif isinstance(value, str):
                conditions = self.perform_filter(conditions, key, value)
            else:
                raise BadRequestException('Query filter value must be a string or list of strings')

        return conditions

    @staticmethod
    def perform_filter(conditions, key, value):
        condition = None
        value = unquote_plus(value)
        if value == '':
            raise BadRequestException('Filter key %s has no value' % key)

        # Check if this is a magic operator
        magic_operator_match = re.match(
            '^(.+)__(in|notin|contains|notcontains|startswith|ne|gt|lt|ge|le|between|exists)$',
            key
        )
        if magic_operator_match:
            key = magic_operator_match.group(1)
            operation = magic_operator_match.group(2)
            attr = Attr(key)

            # Convert to decimal if this is a numeric >, <. >=, <= operation
            if value.isnumeric() and operation in ('gt', 'lt', 'ge', 'le'):
                value = Decimal(value)

            if operation == 'in':
                try:
                    value = json.loads(value)
                except json.JSONDecodeError:
                    raise BadRequestException("Invalid syntax for 'in' magic operator")
                if not isinstance(value, list):
                    raise BadRequestException("Magic operator 'in' must be a JSON list of strings")
                elif not value:
                    raise BadRequestException("In operation for '%s' requires at least one value in the list" % key)
                condition = attr.is_in(value)
            elif operation == 'notin':
                try:
                    value = json.loads(value)
                except json.JSONDecodeError:
                    raise BadRequestException("Invalid syntax for 'notin' magic operator")
                if not isinstance(value, list):
                    raise BadRequestException("Magic operator 'notin' must be a JSON list of strings")
                elif not value:
                    raise BadRequestException("Not In operation for '%s' requires at least one value in the list" % key)
                condition = Not(attr.is_in(value))
            elif operation == 'contains':
                condition = attr.contains(value)
            elif operation == 'notcontains':
                condition = Not(attr.contains(value))
            elif operation == 'exists':
                if value == 'true':
                    condition = attr.exists()
                elif value == 'false':
                    condition = attr.not_exists()
            elif operation == 'startswith':
                condition = attr.begins_with(value)
            elif operation == 'ne':
                condition = attr.ne(value)
            elif operation == 'gt':
                condition = attr.gt(value)
            elif operation == 'lt':
                condition = attr.lt(value)
            elif operation == 'ge':
                condition = attr.gte(value)
            elif operation == 'le':
                condition = attr.lte(value)
            elif operation == 'between':
                try:
                    value = json.loads(value)
                except json.JSONDecodeError:
                    raise BadRequestException("Invalid syntax for 'between' magic operator")
                if not isinstance(value, list) or (isinstance(value, list) and len(value) != 2):
                    raise BadRequestException("Magic operator 'between' must be a JSON list of 2 values")
                condition = attr.between(*value)
            else:
                raise BadRequestException('Unsupported magic operator %s' % operation)
        else:
            condition = Attr(key).eq(value)

        if not isinstance(conditions, ConditionBase):
            conditions = condition
        else:
            conditions &= condition

        return conditions

    @staticmethod
    def multi_filter(user, filter_key, value):
        base_condition = None

        # Make sure a value was provided
        if not value:
            raise BadRequestException('No search values were provided')

        # Build pre-set filters
        for item in user.get('filter_fields', []):
            user_conds = None
            for sub_item in item:
                if 'value' not in sub_item:
                    continue

                attr = Attr(sub_item['field'])
                if isinstance(sub_item['value'], list):
                    condition = attr.is_in(sub_item['value'])
                    if not isinstance(user_conds, ConditionBase):
                        user_conds = condition
                    else:
                        user_conds &= condition
                else:
                    condition = attr.eq(sub_item['value'])
                    if not isinstance(user_conds, ConditionBase):
                        user_conds = condition
                    else:
                        user_conds &= condition

            if not isinstance(base_condition, ConditionBase):
                base_condition = user_conds
            else:
                base_condition |= user_conds

        # Build the multi-filters
        expressions = []

        if isinstance(value, list):
            if len(value) < 99:
                condition = Attr(filter_key).is_in(value)
                if isinstance(base_condition, ConditionBase):
                    condition &= base_condition
                expressions.append(condition)
            else:
                for i in range(0, len(value), 99):
                    condition = Attr(filter_key).is_in(value[i:i + 99])
                    if isinstance(base_condition, ConditionBase):
                        condition &= base_condition
                    expressions.append(condition)
        else:
            condition = Attr(filter_key).eq(value)
            if isinstance(base_condition, ConditionBase):
                condition &= base_condition
            expressions.append(condition)

        return expressions
