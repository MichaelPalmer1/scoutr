import json
import re
from abc import abstractmethod
from concurrent import futures
from concurrent.futures.thread import ThreadPoolExecutor
from copy import deepcopy
from datetime import datetime, timedelta
from typing import List, Dict, Optional, Any, Callable, Union, Tuple, Set

from scoutr.exceptions import UnauthorizedException, BadRequestException, ForbiddenException, NotFoundException
from scoutr.models.audit import AuditLog, AuditUser
from scoutr.models.config import Config
from scoutr.models.request import Request, UserData
from scoutr.models.user import User, Group, Permissions
from scoutr.providers.base.filtering import Filtering
from scoutr.utils.utils import merge_lists

try:
    import sentry_sdk
except ImportError:
    from scoutr.utils import mock_sentry
    sentry_sdk = mock_sentry


class BaseAPI:
    filtering: Filtering
    unique_func: Callable[[List[Dict], str], List[str]] = \
        lambda data, key: sorted(set([item[key] for item in data if item]))

    def __init__(self, config: Config):
        self.config = config

    def can_access_endpoint(self, method: str, path: str, user: User, request: Request = None) -> bool:
        if request:
            # Fetch the user
            try:
                user = self.get_user(request.user.id, request.user.data)
            except Exception as e:
                print(f'Failed to fetch user: {e}')
                return False

            # Validate the user
            try:
                self.validate_user(user)
            except Exception as e:
                print(f'Encountered error while validating user: {e}')
                return False

        # Verify user was provided/looked up
        if user is None:
            print('Unable to validate if user has access to endpoint because user was None')
            return False

        # Check permitted endpoints
        for item in user.permitted_endpoints:
            if method == item.method and re.match(item.endpoint, path):
                return True

        return False

    def initialize_request(self, request: Request) -> User:
        # Get user
        user = self.get_user(request.user.id, request.user.data)

        # Validate user
        self.validate_user(user)

        # Validate request
        self.validate_request(request, user)

        return user

    @staticmethod
    def merge_permissions(user: User, group: Group):
        for attribute in Permissions.attributes():
            value = merge_lists(getattr(user, attribute), getattr(group, attribute))
            setattr(user, attribute, value)

    def get_user(self, user_id: str, user_data: Optional[UserData] = None) -> User:
        is_user = True
        user = User(id=user_id)

        # Try to find user in the auth table
        auth = self.get_auth(user_id)
        if not auth:
            # Failed to find user in the table
            is_user = False
        else:
            user = auth
            user.id = user_id

        # Try to find supplied entitlements in the auth table
        entitlement_ids: List[str] = []
        if user_data and user_data.groups:
            for group_id in user_data.groups:
                entitlement = self.get_auth(group_id)
                if not entitlement:
                    print('Failed to get entitlement')

                    # Entitlement not in the auth table
                    continue

                # Store this as a real entitlement
                entitlement_ids.append(group_id)

                # Add sub-groups
                user.groups.extend(entitlement.groups)

                # Merge permissions
                user.permitted_endpoints = merge_lists(user.permitted_endpoints, entitlement.permitted_endpoints)
                user.exclude_fields = merge_lists(user.exclude_fields, entitlement.exclude_fields)
                user.update_fields_restricted = merge_lists(
                    user.update_fields_restricted,
                    entitlement.update_fields_restricted
                )
                user.update_fields_permitted = merge_lists(
                    user.update_fields_permitted,
                    entitlement.update_fields_permitted
                )
                user.filter_fields = merge_lists(user.filter_fields, entitlement.filter_fields)

        # Check that a user was found
        if not is_user and not entitlement_ids:
            raise UnauthorizedException(f"Auth id '{user_id}' is not authorized")

        # If the user is a member of a group, merge in the group's permissions
        for group_id in user.groups:
            group = self.get_group(group_id)
            if not group:
                # Group is not in the table
                raise UnauthorizedException(f"Group '{group_id}' does not exist")

            # Merge user and group permissions together
            self.merge_permissions(user, group)

        # Save user groups before applying metadata
        user_groups = user.groups.copy()

        # Update user object with metadata
        if user_data:
            if user_data.username:
                user.username = user_data.username
            if user_data.name:
                user.name = user_data.name
            if user_data.email:
                user.email = user_data.email
            if user_data.groups:
                user.groups = user_data.groups

        # Update user object with all applied entitlements
        if entitlement_ids:
            groups: List[str] = []
            groups.extend(user_groups)
            groups.extend(entitlement_ids)
            user.groups = groups

        return user

    @staticmethod
    def validate_user(user: User):
        # Make sure the user contains the required keys
        if not user.id or not user.username or not user.name or not user.email:
            raise UnauthorizedException('User missing one of the following fields: id, username, name, email')

        # Validate exclude fields
        for item in user.exclude_fields:
            if not isinstance(item, str):
                raise UnauthorizedException(f"User '{user.id}' field 'exclude_fields' must be a list of strings")

        # Validate filter fields
        for filter_field in user.filter_fields:
            if not filter_field.field or not filter_field.value:
                raise UnauthorizedException(
                    f"User '{user.id}' field 'filter_fields' must be a list of dictionaries with each "
                    "item formatted as {'field': 'field_name', 'operation': 'eq', 'value': 'value'}"
                )

        # Make sure all the endpoints are valid regex
        for permitted_endpoint in user.permitted_endpoints:
            try:
                re.compile(permitted_endpoint.endpoint)
            except Exception as e:
                raise BadRequestException(f'Failed to compile endpoint regex: {e}')

    def validate_request(self, req: Request, user: User):
        # Make sure the user has permissions to access this endpoint
        if self.can_access_endpoint(req.method, req.path, user):
            # Log request
            user_id = self.user_identifier(user)
            if req.method == 'GET':
                print(f'[{user_id}] Performed {req.method} on {req.path}')
            else:
                print(f'[{user_id}] Performed {req.method} on {req.path}:\n{req.body}')

            # User is authorized to access this endpoint
            return
        
        # Make sure query params have keys and values
        if set(req.query_params.keys()).intersection(['']) or set(req.query_params.values()).intersection(['']):
            raise BadRequestException('Query strings must have keys and values')

        raise ForbiddenException(f'Not authorized to perform {req.method} on endpoint {req.path}')

    @staticmethod
    def validate_fields(validation: Optional[dict], required_fields: Union[List, Tuple], item: dict,
                        existing_item: Optional[dict] = None):
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

        :param dict validation: Dictionary that maps fields to their validation callables
        :param list required_fields: List of fields that should be required
        :param dict item: Data that should be validated
        :param dict existing_item: Existing item in Dynamo
        :raises: BadRequestException
        """
        if validation is None:
            validation = {}

        # Check for required fields
        if required_fields:
            missing_keys = set(required_fields).difference(set(item.keys()))
            if missing_keys:
                raise BadRequestException(f'Missing required fields {missing_keys}')

        sentry_sdk.add_breadcrumb(category='validate', message='Validated required fields were included', level='info')

        # Perform field validation
        errors: Dict[str, str] = {}
        with ThreadPoolExecutor() as executor:
            threads = {}
            for key, func in validation.items():
                if key in item:
                    future = executor.submit(func, item[key], item, existing_item)
                    threads.update({future: key})

            for future in futures.as_completed(threads):
                key = threads[future]
                try:
                    result = future.result()
                except Exception as e:
                    errors[key] = str(e)
                    continue

                if isinstance(result, dict):
                    if 'result' not in result:
                        errors[key] = 'Validator is not properly configured'
                    elif not result['result']:
                        if not isinstance(result.get('message'), str):
                            errors[key] = 'Validator is not properly configured'
                            continue
                        errors[key] = result['message']
                elif not result:
                    errors[key] = 'Invalid value'

        if errors:
            raise BadRequestException(errors)

        sentry_sdk.add_breadcrumb(category='validate', message='Validated input fields', level='info')

    def _prepare_create(self, request: Request, data: dict, validation: dict = None,
                        required_fields: Union[List, Tuple] = ()) -> User:
        # Get user
        user = self.initialize_request(request)

        # Make sure the user has permission to update all of the fields specified
        unauthorized_fields = set(data.keys()).intersection(set(user.exclude_fields))
        if unauthorized_fields:
            raise UnauthorizedException(f'Not authorized to create item with fields {unauthorized_fields}')

        # Run validation
        self.validate_fields(validation, required_fields, data)

        # FIXME: Creation filters
        # for filter_field in user.filter_fields:
        #     key = filter_field.field
        #     filter_value = filter_field.value
        #
        #     # Perform the filter
        #     value = data[key]
        #     if isinstance(filter_value, list) and value not in filter_value or \
        #             isinstance(filter_value, str) and value != filter_value:
        #         raise BadRequestException(f'Unauthorized value for field {key}')

        return user

    def _prepare_list(self, request: Request, process_path_params: bool = True,
                      process_search_keys: bool = True) -> (User, Dict[str, str]):
        # Get user
        user = self.initialize_request(request)

        # Build params
        params: Dict[str, str] = {}
        params.update(request.query_params)
        if process_path_params:
            params.update(request.path_params)

        # Generate dynamo search
        if process_search_keys:
            search_key = request.path_params.get('search_key')
            search_value = request.path_params.get('search_value')
            if search_key and search_value:
                # Map the search key and value into params
                params[search_key] = search_value
                del params['search_key']
                del params['search_value']

        return user, params

    @staticmethod
    def validate_update(user: User, data: dict):
        """
        Make sure the user has permission to update all of the fields specified

        :param User user: User object
        :param dict data: Data object
        :raises UnauthorizedException
        """
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

    def post_process(self, data: List[dict], user: User) -> List[dict]:
        # If no filtering is necessary, return output
        if not user.exclude_fields:
            return data

        fields_logged = set()
        for item in data:
            # Remove fields the user shouldn't be able to see
            for field in user.exclude_fields:
                if field in item:
                    if field not in fields_logged:
                        print(f'[{self.user_identifier(user)}] Excluding field "{field}" from response"')
                        fields_logged.add(field)
                    del item[field]

        # Return the filtered output
        return data

    def audit_log(self, action: str, request: Request, user: User,
                  resource: Dict[str, str] = None, changes: Dict[str, str] = None):
        # Only send audit logs if the table is configured
        if not self.config.audit_table:
            return

        # Create audit log
        now = datetime.utcnow()
        audit_log: AuditLog = AuditLog(
            time=now.isoformat(),
            user=AuditUser(
                id=user.id,
                name=user.name,
                email=user.email,
                username=user.username,
                source_ip=request.source_ip,
                user_agent=request.user_agent,
                filter_fields=user.filter_fields
            ),
            action=action,
            method=request.method,
            path=request.path
        )

        # Add expiry time for read events
        if action in ('GET', 'LIST', 'SEARCH'):
            expire_time = now + timedelta(days=self.config.log_retention_days)
            audit_log.expire_time = int(expire_time.timestamp())

        if request.query_params:
            audit_log.query_params = request.query_params

        # Add body
        if request.body:
            audit_log.body = request.body
        elif changes:
            audit_log.body = changes

        # Add resource
        if resource:
            audit_log.resource = resource

        # Marshal to dict
        item = audit_log.dict()

        # Add the record
        if not self.store_item(self.config.audit_table, item):
            print('Failed to store audit log')
            print('Failed audit log', item)

    @classmethod
    def value_in_set(cls, value: str, valid_options: Set[str], option_name: str = 'option',
                     custom_error_message: str = ''):
        """
        Check if a value is contained in a list of valid options. This is supplied as a convenience function
        and is intended to be used with the input field validation on creates/updates.

        :param str value: Value to check
        :param set of str valid_options: List of options that the value should be included in for this to be successful
        :param str option_name: Optional descriptive name of the option that can be used to enrich an error message.
        :param str custom_error_message: Optional custom error message to return instead of the default one.
        :return: Dictionary that can be used with the field_validation
        :rtype: dict
        """
        return {
            'result': value in valid_options,
            'message': custom_error_message or f'{value} is not a valid {option_name}. Valid options: {valid_options}'
        }

    @staticmethod
    def user_identifier(user: User):
        return f'{user.id}: {user.name} ({user.username} - {user.email})'

    @abstractmethod
    def store_item(self, table: str, item: dict) -> bool:
        raise NotImplementedError

    @abstractmethod
    def get_auth(self, user_id: str) -> Optional[User]:
        raise NotImplementedError

    @abstractmethod
    def get_group(self, group_id: str) -> Optional[Group]:
        raise NotImplementedError

    @abstractmethod
    def create(self, request: Request, data: dict, validation: dict,
               required_fields: Union[List, Tuple]) -> dict:
        raise NotImplementedError

    @abstractmethod
    def update(self, request: Request, partition_key: dict, data: dict, validation: dict) -> dict:
        raise NotImplementedError

    @abstractmethod
    def get(self, request: Request, key: Any, value: Any) -> dict:
        raise NotImplementedError

    @abstractmethod
    def list(self, request: Request) -> List[dict]:
        raise NotImplementedError

    @abstractmethod
    def list_unique_values(self, request: Request, key: str,
                           unique_func: Callable[[List, str], List[str]]) -> List[str]:
        raise NotImplementedError

    @abstractmethod
    def list_audit_logs(self, request: Request, param_overrides: dict) -> List[dict]:
        raise NotImplementedError

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

    @abstractmethod
    def search(self, request: Request, key: str, values: List[str]) -> List[dict]:
        raise NotImplementedError

    @abstractmethod
    def delete(self, request: Request, partition_key: dict) -> dict:
        raise NotImplementedError
