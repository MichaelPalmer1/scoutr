class Config:
    data_table: str = None
    auth_table: str = None
    audit_table: str = None
    group_table: str = None
    primary_key: str = None
    log_retention_days: int = 30
    oidc_username_header: str = None
    oidc_name_header: str = None
    oidc_email_header: str = None
    oidc_group_header: str = None

    def __init__(self, **kwargs):
        for key, value in kwargs.items():
            if hasattr(self, key):
                setattr(self, key, value)
