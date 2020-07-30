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


class UserData:
    pass


class User:
    permitted_endpoints: List[PermittedEndpoints] = []
    filter_fields: List[FilterField] = []
    exclude_fields: List[str] = []
    update_fields_permitted: List[str] = []
    update_fields_restricted: List[str] = []

    @classmethod
    def load(cls, data: dict):
        user = cls()
        for item in data.get('filter_fields', []):
            user.filter_fields.append(FilterField.load(item))

        for item in data.get('permitted_endpoints', []):
            user.permitted_endpoints.append(PermittedEndpoints.load(item))

        for item in data.get('exclude_fields', []):
            if not isinstance(item, str):
                raise InvalidUserException('Invalid entry on user field exclusions')
            user.exclude_fields.append(item)

        for item in data.get('update_fields_permitted', []):
            if not isinstance(item, str):
                raise InvalidUserException('Invalid entry on user update fields permitted')
            user.update_fields_permitted.append(item)

        for item in data.get('update_fields_restricted', []):
            if not isinstance(item, str):
                raise InvalidUserException('Invalid entry on user update fields restricted')
            user.update_fields_permitted.append(item)

        return user
