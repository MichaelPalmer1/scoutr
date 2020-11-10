from typing import List, Dict, Union, Any

from scoutr.exceptions import InvalidUserException
from scoutr.models import Model


class FilterField(Model):
    field: str
    operator: str = 'eq'
    value: Union[List, str]

    @classmethod
    def load(cls, data: Dict[str, Any]):
        filter_field = super(FilterField, cls).load(data)

        # Perform type check
        if not isinstance(data.get('field', None), str):
            raise InvalidUserException(f'Invalid type for field on user filter fields')
        if not isinstance(data.get('value', None), (str, list)):
            raise InvalidUserException(f'Invalid type for value on user filter fields')
        if isinstance(data.get('value', None), list):
            for item in data:
                if not isinstance(item, str):
                    raise InvalidUserException(f'User filter fields value must be a list of string values')
        if not isinstance(data.get('operator', ''), str):
            raise InvalidUserException(f'Invalid type for operator on user filter fields')

        return filter_field


class PermittedEndpoints(Model):
    endpoint: str
    method: str

    @classmethod
    def load(cls, data: Dict[str, str]):
        permitted_endpoint = super(PermittedEndpoints, cls).load(data)

        # Perform type check
        if not isinstance(data['endpoint'], str):
            raise InvalidUserException('Invalid type for endpoint on user permitted endpoints')
        if not isinstance(data['method'], str):
            raise InvalidUserException('Invalid type for method on user permitted endpoints')

        return permitted_endpoint


class Permissions(Model):
    permitted_endpoints: List[PermittedEndpoints] = []
    filter_fields: List[FilterField] = []
    exclude_fields: List[str] = []
    update_fields_permitted: List[str] = []
    update_fields_restricted: List[str] = []

    def __init__(self, permitted_endpoints: List[Dict[str, str]] = None, filter_fields: List[dict] = None,
                 exclude_fields: List[str] = None, update_fields_permitted: List[str] = None,
                 update_fields_restricted: List[str] = None, **kwargs):
        super(Permissions, self).__init__(**kwargs)

        if not filter_fields:
            filter_fields = []
        if not permitted_endpoints:
            permitted_endpoints = []
        if not exclude_fields:
            exclude_fields = []
        if not update_fields_permitted:
            update_fields_permitted = []
        if not update_fields_restricted:
            update_fields_restricted = []

        for item in filter_fields:
            self.filter_fields.append(FilterField.load(item))

        for item in permitted_endpoints:
            self.permitted_endpoints.append(PermittedEndpoints.load(item))

        self.exclude_fields = exclude_fields
        self.update_fields_permitted = update_fields_permitted
        self.update_fields_restricted = update_fields_restricted


class User(Permissions):
    id: str
    name: str
    username: str
    email: str
    groups: List[str]


class Group(Permissions):
    id: str
