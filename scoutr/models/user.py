from typing import List, Any

from scoutr.exceptions import InvalidUserException


class FilterField:
    field: str
    value: Any

    def __init__(self, field: str, value: Any):
        self.field = field
        self.value = value

    @classmethod
    def load(cls, data: dict):
        if 'field' not in data or 'value' not in data:
            raise InvalidUserException('Invalid entry on user filter fields')
        if not isinstance(data['field'], str):
            raise InvalidUserException('Invalid entry on user filter fields')
        if not isinstance(data['value'], (str, list)):
            raise InvalidUserException('Invalid entry on user filter fields')
        return cls(field=data['field'], value=data['value'])


class PermittedEndpoints:
    endpoint: str
    method: str

    def __init__(self, endpoint: str, method: Any):
        self.endpoint = endpoint
        self.method = method

    @classmethod
    def load(cls, data: dict):
        if 'endpoint' not in data or 'method' not in data:
            raise InvalidUserException('Invalid entry on user permitted endpoints')
        if not isinstance(data['endpoint'], str):
            raise InvalidUserException('Invalid entry on user permitted endpoints')
        if not isinstance(data['method'], str):
            raise InvalidUserException('Invalid entry on user permitted endpoints')
        return cls(endpoint=data['endpoint'], method=data['method'])


class Permissions:
    permitted_endpoints: List[PermittedEndpoints] = []
    filter_fields: List[FilterField] = []
    exclude_fields: List[str] = []
    update_fields_permitted: List[str] = []
    update_fields_restricted: List[str] = []

    def __init__(self, permitted_endpoints: List[dict]=None, filter_fields: List[dict]=None,
                 exclude_fields: List[str]=None, update_fields_permitted: List[str]=None,
                 update_fields_restricted: List[str]=None):

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

        for item in exclude_fields:
            if not isinstance(item, str):
                raise InvalidUserException('Invalid entry on user field exclusions')
            self.exclude_fields.append(item)

        for item in update_fields_permitted:
            if not isinstance(item, str):
                raise InvalidUserException('Invalid entry on user update fields permitted')
            self.update_fields_permitted.append(item)

        for item in update_fields_restricted:
            if not isinstance(item, str):
                raise InvalidUserException('Invalid entry on user update fields restricted')
            self.update_fields_permitted.append(item)


class User(Permissions):
    id: str
    name: str
    username: str
    email: str
    groups: List[str]

    def __init__(self, **kwargs):
        super(User, self).__init__(**kwargs)
        for key, value in kwargs.items():
            if hasattr(self, key):
                setattr(self, key, value)

    @classmethod
    def load(cls, data: dict):
        return cls(**data)


class Group(Permissions):
    id: str
