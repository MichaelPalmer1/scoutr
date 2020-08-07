from typing import Dict, Union

from scoutr.models import Model


class AuditUser(Model):
    id: str
    username: str
    name: str
    email: str
    source_ip: str
    user_agent: str


class AuditLog(Model):
    time: str
    user: AuditUser
    action: str
    method: str
    path: str
    expire_time: int
    query_params: Dict[str, str]
    resource: Dict[str, str]
    body: Union[dict, list]
