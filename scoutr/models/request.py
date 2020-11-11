from typing import List, Any, Optional

from scoutr.models import Model


class UserData(Model):
    username: str
    name: str
    email: str
    groups: List[str]

    def __init__(self, username: str, name: str, email: str, groups: List[str]):
        super().__init__()
        self.username = username
        self.name = name
        self.email = email
        self.groups = groups


class RequestUser(Model):
    id: str
    data: Optional[UserData] = None

    def __init__(self, id: str, data: Optional[UserData] = None):
        super().__init__()
        self.id = id
        self.data = data


class Request(Model):
    user: RequestUser
    method: str
    path: str
    source_ip: str
    user_agent: str
    body: Any
    path_params: dict
    query_params: dict

    def __init__(self, user: RequestUser, method: str, path: str, source_ip: str, user_agent: str,
                 body: Any = None, path_params: dict = None, query_params: dict = None):
        super().__init__()
        self.user = user
        self.method = method
        self.path = path
        self.source_ip = source_ip
        self.user_agent = user_agent
        self.body = body
        self.path_params = path_params or {}
        self.query_params = query_params or {}
