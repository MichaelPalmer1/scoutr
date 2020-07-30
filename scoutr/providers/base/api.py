import re
from abc import abstractmethod
from typing import List

from scoutr.exceptions import UnauthorizedException, BadRequestException, ForbiddenException
from scoutr.models.request import Request, UserData
from scoutr.models.user import User
from scoutr.providers.base.filtering import Filtering


class BaseAPI:
    filter: Filtering
    config: dict

    def get_config(self):
        return self.config

    def can_access_endpoint(self, method: str, path: str, user: User, request: Request=None) -> bool:
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
        if user_data:
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

                # TODO: Merge permitted endpoints
                # TODO: Merge exclude fields
                # TODO: Merge update fields restricted
                # TODO: Merge update fields permitted
                # TODO: Merge filter fields

        # Check that a user was found
        if not is_user and not entitlement_ids:
            raise UnauthorizedException(f"Auth id '{user_id}' is not authorized")

        # If the user is a member of a group, merge in the group's permissions
        for group_id in user.groups:
            group = self.get_group(group_id)
            if not group:
                # Group is not in the table
                raise UnauthorizedException(f"Group '{group_id}' does not exist")

            # TODO: Merge permissions

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

        # TODO: Validate exclude fields

        # TODO: Validate filter fields

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
    def user_identifier(user: User):
        return f'{user.id}: {user.name} ({user.username} - {user.email})'

    @abstractmethod
    def get_auth(self, user_id: str) -> User:
        raise NotImplementedError

    @abstractmethod
    def get_group(self, group_id: str) -> User:
        raise NotImplementedError

    @abstractmethod
    def create(self, request: Request, data: dict, validation: dict) -> dict:
        raise NotImplementedError

    @abstractmethod
    def update(self, request: Request, partition_key: dict, data: dict, validation: dict) -> dict:
        raise NotImplementedError

    @abstractmethod
    def get(self, request: Request, record: str) -> dict:
        raise NotImplementedError

    @abstractmethod
    def list(self, request: Request) -> List[dict]:
        raise NotImplementedError

    @abstractmethod
    def list_unique_values(self, request: Request, key: str) -> List[str]:
        raise NotImplementedError

    @abstractmethod
    def list_audit_logs(self, request: Request, path_params: dict, query_params: dict) -> List[dict]:
        raise NotImplementedError

    @abstractmethod
    def history(self, request: Request, key: str, value: str, query_params: dict, actions: List[str]) -> List[dict]:
        raise NotImplementedError

    @abstractmethod
    def search(self, request: Request, key: str, values: List[str]) -> List[dict]:
        raise NotImplementedError

    @abstractmethod
    def delete(self, request: Request, partition_key: dict):
        raise NotImplementedError
