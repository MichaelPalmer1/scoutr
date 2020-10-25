from typing import List, Any

from scoutr.models import Model


class UserData(Model):
    username: str
    name: str
    email: str
    groups: List[str]


class RequestUser(Model):
    id: str
    data: UserData


class Request(Model):
    user: RequestUser
    method: str
    path: str
    body: Any
    source_ip: str
    user_agent: str
    path_params: dict
    query_params: dict