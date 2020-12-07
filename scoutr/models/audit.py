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
