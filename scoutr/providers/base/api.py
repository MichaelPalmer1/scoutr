import re
from abc import abstractmethod
from datetime import datetime, timedelta
from typing import List, Dict, Optional, Any, Callable, Union

from scoutr.exceptions import UnauthorizedException, BadRequestException, ForbiddenException
from scoutr.models.audit import AuditLog, AuditUser
from scoutr.models.config import Config
from scoutr.models.request import Request, UserData
from scoutr.models.user import User, Group, Permissions
from scoutr.providers.base.filtering import Filtering
from scoutr.utils.utils import merge_lists


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
                print('Failed to fetch user: %s' % e)
                return False

            # Validate the user
            try:
                self.validate_user(user)
            except Exception as e:
                print('Encountered error while validating user: %s' % e)
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

    def get_user(self, user_id: str, user_data: UserData) -> User:
        is_user = True
        user = User(id=user_id)

        # Try to find user in the auth table
        auth = self.get_auth(user_id)
        if not auth:
            # Failed to find user in the table
            is_user = False
        else:
            user = auth

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
        for item in user.filter_fields:
            if not isinstance(item, list):
                raise UnauthorizedException(
                    f"User '{user.id}' field 'filter_fields' must be a list of lists of dictionaries with each item "
                    "formatted as {'field': 'field_name', 'value': 'value'}"
                )
            for sub_item in item:
                if not isinstance(sub_item, dict) or 'field' not in sub_item or 'value' not in sub_item:
                    raise UnauthorizedException(
                        f"User '{user.id}' field 'filter_fields' must be a list of lists of dictionaries with each "
                        "item formatted as {'field': 'field_name', 'value': 'value'}"
                    )

        # Make sure all the endpoints are valid regex
        for item in user.permitted_endpoints:
            try:
                re.compile(item.endpoint)
            except Exception as e:
                raise BadRequestException('Failed to compile endpoint regex: %s' % e)

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

        raise ForbiddenException(f'Not authorized to perform {req.method} on endpoint {req.path}')

    @staticmethod
    def validate_fields(validation: dict, item: dict, existing_item: Optional[dict] = None,
                        ignore_field_presence: bool = False):
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
        :param dict item: Data that should be validated
        :param dict existing_item: Existing item in Dynamo
        :param bool ignore_field_presence: If True and a field specified in `field_validation` does not exist in
        `data`, this will raise a BadRequestException. If False, missing fields will be ignored.
        :raises: BadRequestException
        """
        # Check for required fields
        if not ignore_field_presence:
            missing_keys = set(validation.keys()).difference(set(item.keys()))
            if missing_keys:
                raise BadRequestException('Missing required fields %s' % missing_keys)

        # Perform field validation
        for key, func in validation.items():
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
                        print('[%(user)s] Excluding field "%(field)s" from response' % {
                            'user': self.user_identifier(user),
                            'field': field
                        })
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
    def create(self, request: Request, data: dict, validation: dict) -> dict:
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
    def list_unique_values(self, request: Request, key: str, unique_func: Callable[[List[Dict], str], List[str]]) -> List[str]:
        raise NotImplementedError

    @abstractmethod
    def list_audit_logs(self, request: Request, param_overrides: dict) -> List[dict]:
        raise NotImplementedError

    @abstractmethod
    def history(self, request: Request, key: str, value: str, actions: tuple = ('CREATE', 'UPDATE', 'DELETE')) -> List[dict]:
        raise NotImplementedError

    @abstractmethod
    def search(self, request: Request, key: str, values: List[str]) -> List[dict]:
        raise NotImplementedError

    @abstractmethod
    def delete(self, request: Request, partition_key: dict):
        raise NotImplementedError
