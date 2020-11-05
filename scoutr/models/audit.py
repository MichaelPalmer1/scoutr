from typing import Dict, Union, List

from scoutr.models import Model
from scoutr.models.user import FilterField


class AuditUser(Model):
    id: str
    username: str
    name: str
    email: str
    source_ip: str
    user_agent: str
    filter_fields: List[FilterField]


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
