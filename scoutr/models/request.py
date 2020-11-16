from typing import List, Any, Optional

from scoutr.models import Model


class UserData(Model):
    username: str
    name: str
    email: str
    groups: List[str]


class RequestUser(Model):
    id: str
    data: Optional[UserData] = None


class Request(Model):
    user: RequestUser
    method: str
    path: str
    source_ip: str
    user_agent: str
    body: Any
    path_params: dict
    query_params: dict
