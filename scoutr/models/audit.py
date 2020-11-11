from typing import Dict, Union, List, Optional

from scoutr.models import Model
from scoutr.models.user import FilterField


class AuditUser(Model):
    id: str
    username: str
    name: str
    email: str
    source_ip: str
    user_agent: str
    read_filters: List[FilterField]
    create_filters: List[FilterField]
    update_filters: List[FilterField]
    delete_filters: List[FilterField]

    def __init__(self, id: str, username: str, name: str, email: str, source_ip: str, user_agent: str,
                 read_filters: List[FilterField], create_filters: List[FilterField],
                 update_filters: List[FilterField], delete_filters: List[FilterField]):
        super().__init__()
        self.id = id
        self.username = username
        self.name = name
        self.email = email
        self.source_ip = source_ip
        self.user_agent = user_agent
        self.read_filters = read_filters
        self.create_filters = create_filters
        self.update_filters = update_filters
        self.delete_filters = delete_filters


class AuditLog(Model):
    time: str
    user: AuditUser
    action: str
    method: str
    path: str
    expire_time: Optional[int]
    query_params: Optional[Dict[str, str]]
    resource: Optional[Dict[str, str]]
    body: Optional[Union[dict, list]]

    def __init__(self, time: str, user: AuditUser, action: str, method: str, path: str,
                 expire_time: Optional[int] = None, query_params: Optional[dict] = None,
                 resource: Optional[dict] = None, body: Optional[Union[dict, list]] = None):
        super().__init__()
        self.time = time
        self.user = user
        self.action = action
        self.method = method
        self.path = path
        self.expire_time = expire_time
        self.query_params = query_params
        self.resource = resource
        self.body = body
