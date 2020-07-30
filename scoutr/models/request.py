from typing import List, Any


class UserData:
    username: str
    name: str
    email: str
    groups: List[str]


class RequestUser:
    id: str
    data: UserData


class Request:
    user: RequestUser
    method: str
    path: str
    body: Any
    source_ip: str
    user_agent: str
    path_params: dict
    query_params: dict
