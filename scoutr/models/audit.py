from typing import Dict, Union


class AuditUser:
    id: str
    username: str
    name: str
    email: str
    source_ip: str
    user_agent: str

    def __init__(self, **kwargs):
        for key, value in kwargs.items():
            if hasattr(self, key):
                setattr(self, key, value)

    def __dict__(self):
        return {
            'id': self.id,
            'username': self.username,
            'name': self.name
        }


class AuditLog:
    time: str
    user: AuditUser
    action: str
    method: str
    path: str
    expire_time: int
    query_params: Dict[str, str]
    resource: Dict[str, str]
    body: Union[dict, list]

    def __init__(self, **kwargs):
        for key, value in kwargs.items():
            if hasattr(self, key):
                setattr(self, key, value)

    def __dict__(self):
        output = {
            'time': self.time,
            'user': dict(self.user),
            'action': self.action,
            'method': self.method,
            'path': self.path
        }

        return output

