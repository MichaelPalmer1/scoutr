import logging
from typing import List, Dict, Optional, Any, Callable, Union, Tuple

from firebase_admin import firestore
from google.cloud.firestore_v1 import Client, DocumentSnapshot, CollectionReference

from scoutr.exceptions import NotFoundException, BadRequestException
from scoutr.models.config import Config
from scoutr.models.request import Request
from scoutr.models.user import User, Group
from scoutr.providers.base.api import BaseAPI
from scoutr.providers.gcp.filtering import GCPFiltering

try:
    import sentry_sdk
    has_sentry = True
except ImportError:
    has_sentry = False

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)


class FirestoreAPI(BaseAPI):
    def __init__(self, config: Config):
        super(FirestoreAPI, self).__init__(config)
        self.db: Client = firestore.client()
        self.data_table: CollectionReference = self.db.collection(self.config.data_table)
        self.audit_table: CollectionReference = self.db.collection(self.config.audit_table)
        self.auth_table: CollectionReference = self.db.collection(self.config.auth_table)
        self.group_table: CollectionReference = self.db.collection(self.config.group_table)

    def get_auth(self, user_id: str) -> Optional[User]:
        # Try to find user in the auth table
        result = self.auth_table.document(user_id).get()

        if not result.exists:
            return None

        # Create user object
        return User.load(result.to_dict())

    def get_group(self, group_id: str) -> Optional[Group]:
        # Try to find user in the auth table
        result = self.group_table.document(group_id).get()

        if not result.exists:
            return None

        # Create user object
        return Group.load(result.to_dict())

    def store_item(self, table: str, item: dict) -> bool:
        try:
            self.db.collection(table).document().set(item)
        except Exception as e:
            print('Failed to store record: %s', e)
            return False

        return True

    def create(self, request: Request, data: dict, validation: dict = None,
               required_fields: Union[List, Tuple] = ()) -> dict:
        """
        Create an item in Dynamo

        :param Request request: Request object
        :param dict data: Item to create
        :param dict validation: Optional dictionary containing mappings of field name to callable. See the docstring
        in the _validate_fields method for more information.
        :param list required_fields: List of required fields
        :return: Created item
        :rtype: dict
        """
        user = self._prepare_create(request, data, validation, required_fields)

        # Make sure primary key is included
        document_id = data.get(self.config.primary_key)
        if not document_id:
            raise BadRequestException('Primary key %s is required' % self.config.primary_key)

        # Set the resource identifier
        resource = {self.config.primary_key: document_id}

        # TODO: Build condition to ensure the unique key does not exist

        # Save the item
        try:
            self.data_table.document(document_id).set(data)
            logger.info('[%(user)s] Successfully created item:\n%(item)s' % {
                'user': self.user_identifier(user),
                'item': data
            })
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
            sentry_sdk.add_breadcrumb(category='data', message='Created item in Firestore', level='info')

        # Create audit log
        self.audit_log(action='CREATE', resource=resource, request=request, user=user)

        return resource

    def update(self, request: Request, primary_key: dict, data: dict, validation: dict, audit_action='UPDATE') -> dict:
        """
        Update an item in Dynamo

        :param Request request: Request object
        :param dict primary_key: Dictionary formatted as {"partition_key": "value_of_row_to_update"}
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
        filtering = GCPFiltering(self.data_table)
        filtering.filter(user)

        # Get the existing item
        existing_item = filtering.query.stream()
        if len(existing_item) == 0:
            logger.info('[%(user)s] Primary key "%(partition_key)s" does not exist or user does '
                        'not have permission to access it' % {
                            'user': self.user_identifier(user),
                            'partition_key': primary_key
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
            if has_sentry:
                sentry_sdk.add_breadcrumb(category='validate', message='Validated input fields', level='info')

        # Perform the update item call
        try:
            document_id = primary_key[self.config.primary_key]
            self.data_table.document(document_id).update(data)
            response = self.data_table.document(document_id).get()
            logger.info('[%(user)s] Successfully updated record "%(partition_key)s" with values:\n%(item)s' % {
                'user': self.user_identifier(user),
                'partition_key': primary_key,
                'item': data
            })
        except Exception as e:
            logger.error(
                '[%(user)s] Encountered error while attempting to update record '
                '"%(partition_key)s": %(error)s. Item:\n%(item)s' % {
                    'user': self.user_identifier(user),
                    'partition_key': primary_key,
                    'error': str(e),
                    'item': data
                }
            )
            raise

        if has_sentry:
            sentry_sdk.add_breadcrumb(category='data', message='Updated item in Dynamo', level='info')

        # Create audit log
        self.audit_log(action=audit_action, resource=primary_key, changes=data, request=request, user=user)

        # Return updated record
        return self.post_process([response.to_dict()], user)[0]

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
        filtering = GCPFiltering(self.data_table)
        conditions = filtering.filter(user)
        filtering.And(
            conditions,
            filtering.equals(key, value)
        )

        # Search for the item
        data = filtering.query.stream()
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
        user, params = self._prepare_list(request)

        args = {}
        filtering = GCPFiltering(self.data_table)
        conditions = filtering.filter(user, params)
        if conditions:
            args.update({'FilterExpression': conditions})

        data = []
        for record in filtering.query.stream():
            record_dict = record.to_dict()
            record_dict[self.config.primary_key] = record.id
            data.append(record_dict)
        data = self.post_process(data, user)

        self.audit_log('LIST', request, user)

        return data

    def list_unique_values(self, request: Request, key: str,
                           unique_func: Callable[[List[Dict], str], List[str]] = BaseAPI.unique_func) -> List[str]:
        user, params = self._prepare_list(request, False)

        # Build filters
        filtering = GCPFiltering(self.data_table)
        filtering.filter(user, params)

        # TODO: Add key existence filter

        # Download the data
        try:
            data = filtering.query.stream()
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
        filtering = GCPFiltering(self.audit_table)
        filtering.filter(None, request.query_params)

        # Download data
        try:
            data = filtering.query.stream()
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
                message='Scanned table',
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
        filtering = GCPFiltering(self.data_table)
        filters = filtering.multi_filter(user, key, values)
        if has_sentry:
            sentry_sdk.add_breadcrumb(category='data', message='Built multi-value filter', level='info')

        # Perform each generated filter expression and then combine the results together
        output = []
        for f in filters:
            for record in f.stream():
                # Add to output
                record_dict = record.to_dict()
                record_dict[self.config.primary_key] = record.id
                output.append(record_dict)

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
        filtering = GCPFiltering(self.data_table)
        filtering.filter(user)

        # Perform the deletion
        try:
            self.data_table.document(primary_key[self.config.primary_key]).delete()
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

        if has_sentry:
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
