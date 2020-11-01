import json
import logging
from copy import deepcopy
from typing import List, Optional, Any, Callable, Union, Tuple

from bson import ObjectId
from pymongo import MongoClient
from pymongo.errors import DuplicateKeyError

from scoutr.exceptions import NotFoundException, BadRequestException, UnauthorizedException
from scoutr.models.config import MongoConfig
from scoutr.models.request import Request
from scoutr.models.user import User, Group
from scoutr.providers.base import BaseAPI
from scoutr.providers.mongo.filtering import MongoFiltering

try:
    import sentry_sdk
except ImportError:
    from scoutr.utils import mock_sentry
    sentry_sdk = mock_sentry

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)


class MongoAPI(BaseAPI):
    filtering = MongoFiltering()

    def __init__(self, config: MongoConfig):
        super(MongoAPI, self).__init__(config)
        self.config = config
        self.client = MongoClient(config.connection_string)
        self.db = self.client.get_database(self.config.database)
        self.data_table = self.db.get_collection(self.config.data_table)
        self.auth_table = self.db.get_collection(self.config.auth_table)
        self.group_table = self.db.get_collection(self.config.group_table)
        self.audit_table = self.db.get_collection(self.config.audit_table)

    #     # Configure indices
    #     self.setup_indices()
    #
    # def setup_indices(self):
    #     found = False
    #     for key, value in self.data_table.index_information().items():
    #         # Look for the primary key
    #         if value.get('key') == [(self.config.primary_key, 1)]:
    #             if value.get('unique', False) is True:
    #                 found = True
    #                 break
    #
    #     if not found:
    #         # Create index
    #         print(f'Creating unique index for {self.config.primary_key} on collection {self.config.data_table}')
    #         self.data_table.create_index(self.config.primary_key, unique=True)

    def get_auth(self, user_id: str) -> Optional[User]:
        # Try to find user in the auth table
        result = self.auth_table.find_one({'id': user_id})

        if not result:
            return None

        # Create user object
        return User.load(result)

    def get_group(self, group_id: str) -> Optional[Group]:
        # Try to find user in the auth table
        result = self.group_table.find_one({'id': group_id})

        if not result:
            return None

        # Create user object
        return Group.load(result)

    def store_item(self, table: str, item: dict) -> bool:
        try:
            self.db.get_collection(table).insert_one(item)
        except Exception as e:
            print('Failed to store record: %s', e)
            return False

        return True

    def create(self, request: Request, data: dict, validation: dict = None,
               required_fields: Union[List, Tuple] = ()) -> dict:
        """
        Create an item

        :param Request request: Request object
        :param dict data: Item to create
        :param dict validation: Optional dictionary containing mappings of field name to callable. See the docstring
        in the _validate_fields method for more information.
        :param list required_fields: List of required fields
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
            self.validate_fields(validation, required_fields, data)
            sentry_sdk.add_breadcrumb(category='validate', message='Validated input fields', level='info')

        # FIXME: Build creation filters
        # for filter_field in user.filter_fields:
        #     for sub_item in filter_field:
        #         key = sub_item.field
        #         filter_value = sub_item.value
        #         if key not in data:
        #             raise BadRequestException(f'Missing required field {key}')
        #
        #         # Perform the filter
        #         value = data[key]
        #         if isinstance(filter_value, list) and value not in filter_value or \
        #                 isinstance(filter_value, str) and value != filter_value:
        #             raise BadRequestException(f'Unauthorized value for field {key}')

        # Make sure primary key is included
        document_id = data.get(self.config.primary_key)
        if not document_id:
            raise BadRequestException('Primary key %s is required' % self.config.primary_key)

        # Set the resource identifier
        resource = {self.config.primary_key: document_id}

        # TODO: Build condition to ensure the unique key does not exist

        # Save the item
        try:
            # Set the document id
            data['_id'] = document_id

            # Insert the record
            result = self.data_table.insert_one(data)
            if not result.acknowledged:
                raise Exception('Failed to save item')

            logger.info('[%(user)s] Successfully created item:\n%(item)s' % {
                'user': self.user_identifier(user),
                'item': data
            })
        except DuplicateKeyError:
            raise BadRequestException(f"An item with id '{document_id}' already exists")

        except Exception as e:
            logger.error(
                '[%(user)s] Encountered error while attempting to create record %(error)s. Item:\n%(item)s' % {
                    'user': self.user_identifier(user),
                    'error': str(e),
                    'item': data
                }
            )
            raise

        sentry_sdk.add_breadcrumb(category='data', message='Created item in Firestore', level='info')

        # Create audit log
        self.audit_log(action='CREATE', resource=resource, request=request, user=user)

        return resource

    def update(self, request: Request, primary_key: dict, data: dict, validation: dict, audit_action='UPDATE') -> dict:
        """
        Update an item in Dynamo

        :param Request request: Request object
        :param dict primary_key: Dictionary formatted as {"primary_key": "value_of_row_to_update"}
        :param dict data: Fields to update, formatted as {"key": "value"}
        :param dict validation: Optional dictionary containing mappings of field name to callable. See the
        docstring in the _validate_fields method for more information.
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

        # Deny updates to primary key
        if self.config.primary_key in data:
            raise BadRequestException('Primary key %s cannot be updated' % self.config.primary_key)

        # Validate update
        self.validate_update(user, data)

        # Add in the user's permissions
        conditions = self.filtering.filter(user, {self.config.primary_key: primary_key[self.config.primary_key]})

        # Get the existing item
        existing_item = self.data_table.find_one(conditions)
        if len(existing_item) == 0:
            logger.info('[%(user)s] Primary key "%(primary_key)s" does not exist or user does '
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

        # Perform the update item call
        try:
            document_id = primary_key[self.config.primary_key]
            self.data_table.update_one(conditions, {'$set': data})
            response = self.data_table.find_one({primary_key: document_id})
            logger.info('[%(user)s] Successfully updated record "%(primary_key)s" with values:\n%(item)s' % {
                'user': self.user_identifier(user),
                'primary_key': primary_key,
                'item': data
            })
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

        sentry_sdk.add_breadcrumb(category='data', message='Updated item in Dynamo', level='info')

        # Create audit log
        self.audit_log(action=audit_action, resource=primary_key, changes=data, request=request, user=user)

        # Return updated record
        return self.post_process([response], user)[0]

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

        # Apply the search criteria for the requested item
        conditions = self.filtering.And(
            conditions,
            self.filtering.equals(key, value)
        )

        # Search for the item
        data = self.data_table.find_one(conditions)
        if not data:
            raise NotFoundException('Item not found')

        # Convert ObjectId to string if necessary
        if isinstance(data['_id'], ObjectId):
            data['_id'] = str(data['_id'])

        sentry_sdk.add_breadcrumb(
            category='query', message='%s = %s' % (key, value), level='info', table=self.config.data_table
        )

        # Filter the response
        output = self.post_process([data], user)

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
        user, params = self._prepare_list(request)

        # Build filters
        conditions = self.filtering.filter(user, params)
        if conditions is None:
            conditions = {}

        # Perform the query
        data = []
        for record in self.data_table.find(conditions):
            # Convert ObjectId to string if necessary
            if isinstance(record['_id'], ObjectId):
                record['_id'] = str(record['_id'])

            # Add the record
            data.append(record)

        # Perform post processing
        data = self.post_process(data, user)

        # Add audit log
        self.audit_log('LIST', request, user)

        return data

    def list_unique_values(self, request: Request, key: str,
                           unique_func: Callable[[List, str], List[str]] = lambda items, _: sorted(items)) -> List[str]:
        user, params = self._prepare_list(request, False)

        # Build filters
        conditions = self.filtering.And(
            self.filtering.filter(user, params),
            self.filtering.exists(key, 'true')
        )

        # Build a projection expression to exclude fields based on user permissions
        projection_expression = {}
        for excluded_field in user.exclude_fields:
            projection_expression[excluded_field] = False

        # If any fields are being excluded, set the projection expression
        args = {}
        if projection_expression:
            args['projection'] = projection_expression

        # Download the data
        try:
            raw_data = self.data_table.find(conditions, **args)
            distinct_values = raw_data.distinct(key)
        except Exception as e:
            logger.error(
                '[%(user)s] Encountered error while attempting to list records: %(error)s' % {
                    'user': self.user_identifier(user),
                    'error': str(e)
                }
            )
            raise

        # Make sure the requested key exists in the output - we only need to check the first record in the cursor.
        # It will be missing if user does not have permissions to view it
        for item in raw_data:
            if key not in item:
                raise UnauthorizedException(f"Not authorized to view contents of field '{key}'")
            break

        # Use the distinct values that were already saved
        data = distinct_values

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
        conditions = self.filtering.filter(None, request.query_params)

        # Download data
        try:
            data = self.audit_table.find(conditions)
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
            message='Scanned table',
            level='info',
            table=self.config.audit_table
        )

        # Sort the data
        data = sorted(data, key=lambda item: item['time'], reverse=True)

        return data

    def history(self, request: Request, key: str, value: str,
                actions: tuple = ('CREATE', 'UPDATE', 'DELETE')) -> List[dict]:
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
        self.initialize_request(request)

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
        multi_filters = self.filtering.multi_filter(user, key, values)
        sentry_sdk.add_breadcrumb(category='data', message='Built multi-value filter', level='info')

        # Perform each generated filter and then combine the results together
        output = []
        for filters in multi_filters:
            results = self.data_table.find(filters)
            if not results:
                continue

            if isinstance(results, dict):
                results = [results]

            for record in results:
                # Convert ObjectId to string if necessary
                if isinstance(record['_id'], ObjectId):
                    record['_id'] = str(record['_id'])
                output.append(record)

        # Create audit log
        self.audit_log(action='SEARCH', request=request, user=user)

        # Return the filtered response
        return self.post_process(output, user)

    def delete(self, request: Request, primary_key: dict) -> dict:
        """
        Delete an item

        :param Request request: Request object
        :param dict primary_key: Dictionary formatted as {"primary_key": "value_of_row_to_delete"}
        :return: Success
        :rtype: dict
        """
        # Get user
        user = self.initialize_request(request)

        # TODO: Default conditional expression to make sure the item actually exists

        # Add in the user's permissions
        conditions = self.filtering.filter(user)
        conditions = self.filtering.And(
            conditions,
            self.filtering.equals(self.config.primary_key, primary_key[self.config.primary_key])
        )

        # Perform the deletion
        try:
            self.data_table.delete_one(conditions)
            logger.info('[%(user)s] Successfully deleted record "%(primary_key)s"' % {
                'user': self.user_identifier(user),
                'primary_key': primary_key,
            })
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
